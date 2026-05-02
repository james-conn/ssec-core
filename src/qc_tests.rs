use futures_util::StreamExt;
use bytes::{Bytes, BytesMut};
use rand_core::{Rng, SeedableRng};
use quickcheck::TestResult;
use core::num::NonZeroUsize;
use std::sync::Arc;
use crate::encrypt::{Encrypt, EncryptArgs};
use crate::decrypt::{Decrypt, DecryptArgs};
use crate::chaff::{ChaffStream, ChaffStreamArgs};

struct OwnedRandomChunksIter<const S: usize, V, R> {
	vec: Arc<V>,
	pos: usize,
	rng: R
}

impl<const S: usize, V: AsRef<[u8]>, R: Rng> OwnedRandomChunksIter<S, V, R> {
	fn new(vec: Arc<V>, rng: R) -> Self {
		Self {
			vec,
			pos: 0,
			rng
		}
	}

	fn next_chunk_size(&mut self) -> usize {
		let n = self.rng.next_u32() as usize;
		n % S
	}
}

impl<const S: usize, V: AsRef<[u8]>, R: Rng> std::iter::Iterator for OwnedRandomChunksIter<S, V, R> {
	type Item = Bytes;

	fn next(&mut self) -> Option<Self::Item> {
		let len = self.vec.as_ref().as_ref().len();
		if self.pos > len {
			return None
		}

		let chunk_size = self.next_chunk_size();
		let end_idx = (self.pos + chunk_size).min(len);
		let slice = &self.vec.as_ref().as_ref()[self.pos..end_idx];
		self.pos += chunk_size;

		Some(Bytes::copy_from_slice(slice))
	}
}

// buffers bigger than 64MB are probably not a meaningful test and may cause OOMs
const MAX_SIZE: usize = 64 * 1024 * 1024;

fn init_buffer<R: Rng>(mut rng: R, length: usize) -> Vec<u8> {
	let mut b = vec![0u8; length];
	rng.fill_bytes(&mut b);
	b
}

// TODO: fix double test, both these attribute macros add their own `#[test]`
#[tokio::test]
#[quickcheck_macros::quickcheck]
async fn end_to_end(
	rng_seed: u64,
	input_length: usize,
	password: Vec<u8>,
	bytes_per_poll_enc: NonZeroUsize,
	bytes_per_poll_dec: NonZeroUsize
) -> TestResult {
	if input_length > MAX_SIZE {
		return TestResult::discard();
	}

	let mut rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

	let input = Arc::new(init_buffer(&mut rng, input_length));
	let password_enc = password.clone();
	let in_chunks = OwnedRandomChunksIter::<99999, _, _>::new(input.clone(), rng);
	let encryptor = tokio::task::spawn_blocking(move || {
		let s = futures_util::stream::iter(in_chunks)
			.map(Result::<Bytes, std::io::Error>::Ok);

		let mut password_rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
		let mut args = EncryptArgs::default();
		args.set_bytes_per_poll(bytes_per_poll_enc);
		Encrypt::new(args, &mut password_rng, &password_enc, s).unwrap()
	}).await.unwrap();

	let encrypted: Bytes = encryptor.map(|c| c.unwrap())
		.collect::<BytesMut>().await.freeze();

	let dec_chunk_rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
	let s = futures_util::stream::iter(OwnedRandomChunksIter::<99999, _, _>::new(Arc::new(encrypted), dec_chunk_rng))
		.map(Result::<Bytes, std::io::Error>::Ok);

	let mut args = DecryptArgs::default();
	args.set_bytes_per_poll(bytes_per_poll_dec);
	let decryptor = Decrypt::new(args, s).await.unwrap();
	let decryptor = tokio::task::spawn_blocking(move || {
		let Ok(stream) = decryptor.try_password(&password) else { panic!("password should be correct") };
		stream
	}).await.unwrap();

	let decrypted = decryptor.map(|c| c.unwrap()).collect::<BytesMut>().await.freeze();

	TestResult::from_bool(input.as_ref().eq(&decrypted))
}

// TODO: fix double test, both these attribute macros add their own `#[test]`
#[tokio::test]
#[quickcheck_macros::quickcheck]
async fn chaff(
	rng_seed: u64,
	input_length: usize,
	chunk_size: usize,
	password: Vec<u8>,
	bytes_per_poll_dec: NonZeroUsize
) -> TestResult {
	if input_length > MAX_SIZE {
		return TestResult::discard();
	}

	let mut args = ChaffStreamArgs::with_length(input_length);
	let chunk_res = args.set_chunk_size(chunk_size);
	if chunk_res.is_err() {
		return TestResult::discard();
	}

	let rng = rand::rngs::StdRng::seed_from_u64(rng_seed);

	let chaff = ChaffStream::new(args, rng);
	let chaff_output: Bytes = chaff.map(|c| {
		let chunk = c.unwrap();
		assert!(chunk.len() <= chunk_size);
		chunk
	}).collect::<BytesMut>().await.freeze();

	let dec_chunk_rng = rand::rngs::StdRng::seed_from_u64(rng_seed);
	let s = futures_util::stream::iter(OwnedRandomChunksIter::<99999, _, _>::new(Arc::new(chaff_output), dec_chunk_rng))
		.map(Result::<Bytes, std::io::Error>::Ok);

	let mut args = DecryptArgs::default();
	args.set_bytes_per_poll(bytes_per_poll_dec);
	let decryptor = Decrypt::new(args, s).await.unwrap();
	let decryptor = tokio::task::spawn_blocking(move || {
		decryptor.try_password(&password)
	}).await.unwrap();

	// decryption should always fail, obviously
	TestResult::from_bool(decryptor.is_err())
}
