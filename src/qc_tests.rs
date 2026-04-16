use futures_util::StreamExt;
use bytes::{Bytes, BytesMut};
use rand_core::SeedableRng;
use std::sync::Arc;
use crate::encrypt::Encrypt;
use crate::decrypt::Decrypt;

struct OwnedChunksIter<const S: usize, V: AsRef<[u8]>> {
	vec: Arc<V>,
	pos: usize
}

impl<const S: usize, V: AsRef<[u8]>> From<Arc<V>> for OwnedChunksIter<S, V> {
	fn from(vec: Arc<V>) -> Self {
		Self {
			vec,
			pos: 0
		}
	}
}

impl<const S: usize, V: AsRef<[u8]>> std::iter::Iterator for OwnedChunksIter<S, V> {
	// returning a slice here would require `Item` to have a generic lifetime
	type Item = Bytes;

	fn next(&mut self) -> Option<Self::Item> {
		let len = self.vec.as_ref().as_ref().len();
		if self.pos > len {
			return None
		}

		let end_idx = (self.pos + S).min(len);
		let slice = &self.vec.as_ref().as_ref()[self.pos..end_idx];
		self.pos += S;

		Some(Bytes::copy_from_slice(slice))
	}
}

#[tokio::test]
#[quickcheck_macros::quickcheck]
async fn end_to_end(rng_seed: u64, input: Vec<u8>, password: Vec<u8>) -> bool {
	let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

	let input = Arc::new(input);
	let password_enc = password.clone();
	let in_chunks: OwnedChunksIter<1024, Vec<u8>> = OwnedChunksIter::from(input.clone());
	let encryptor = tokio::task::spawn_blocking(move || {
		let s = futures_util::stream::iter(in_chunks)
			.map(Bytes::from_owner)
			.map(Result::<Bytes, std::io::Error>::Ok);

		Encrypt::new_uncompressed(s, &password_enc, &mut rng).unwrap()
	}).await.unwrap();

	let encrypted: Bytes = encryptor.map(|c| c.unwrap())
		.collect::<BytesMut>().await.freeze();

	let enc_chunks = encrypted.chunks(1024)
		.map(Bytes::copy_from_slice).collect::<Vec<Bytes>>();
	let s = futures_util::stream::iter(enc_chunks)
		.map(Result::<Bytes, std::io::Error>::Ok);

	let decryptor = Decrypt::new(s).await.unwrap();
	let decryptor = tokio::task::spawn_blocking(move || {
		let Ok(stream) = decryptor.try_password(&password) else { panic!("password should be correct") };
		stream
	}).await.unwrap();

	let decrypted = decryptor.map(|c| c.unwrap()).collect::<BytesMut>().await.freeze();

	input.as_ref().eq(&decrypted)
}
