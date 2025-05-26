use futures_core::Stream;
use bytes::{Bytes, BytesMut, BufMut};
use rand_core::TryCryptoRng;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use core::pin::Pin;
use core::task::{Context, Poll, ready};
use crate::util::{HmacSha3_256, new_arr, kdf, compute_verification_hash};
use crate::{BYTES_PER_POLL, Aes256Ctr};

enum EncryptState {
	PreHeader,
	PostHeader,
	Finalizing,
	Finished
}

pin_project_lite::pin_project! {
	pub struct Encrypt<R> {
		#[pin]
		read: R,
		aes: Aes256Ctr,
		password_salt: Box<[u8; 32]>,
		password_verification_hash: Box<[u8; 64]>,
		integrity_code: Option<HmacSha3_256>,
		state: EncryptState,
		block_buffer: BytesMut,
		iv: [u8; 16]
	}
}

impl<R> Encrypt<R> {
	/// This method is *very* blocking.
	/// If you're using Tokio I advise that you wrap this call in a `spawn_blocking`.
	/// It's very important that you provide the correct length of the `read` stream otherwise you'll get a corrupted stream.
	///
	/// SECURITY: It is advisable to zero out the memory containing the password after this method returns.
	pub fn new_uncompressed<RNG: TryCryptoRng>(read: R, password: &[u8], rng: &mut RNG) -> Result<Self, RNG::Error> {
		let mut password_salt = new_arr::<32>();
		rng.try_fill_bytes(password_salt.as_mut())?;

		let aes_key = kdf(password, password_salt.as_ref());
		let password_verification_hash = compute_verification_hash(&aes_key);

		let mut iv = [0; 16];
		rng.try_fill_bytes(&mut iv)?;

		let aes = Aes256Ctr::new(aes_key.as_ref().get_ref().into(), iv.as_ref().into());

		Ok(Self {
			read,
			aes,
			password_salt,
			password_verification_hash,
			integrity_code: Some(HmacSha3_256::new_from_slice(aes_key.as_ref().get_ref()).unwrap()),
			state: EncryptState::PreHeader,
			block_buffer: BytesMut::new(),
			iv
		})
	}
}

impl<E, R: Stream<Item = Result<Bytes, E>>> Stream for Encrypt<R> {
	type Item = Result<Bytes, E>;

	fn poll_next(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>
	) -> Poll<Option<Self::Item>> {
		let mut this = self.project();

		loop {
			match this.state {
				EncryptState::PreHeader => {
					let mut buf = Vec::with_capacity(
						4 + // magic
						1 + // version number
						1 + // compression algo
						32 + // password salt
						64 + // password verification hash
						16 // IV
					);

					buf.extend_from_slice(b"SSEC");
					buf.push(0x01);
					buf.push(0x6e);
					buf.extend_from_slice(this.password_salt.as_ref());
					buf.extend_from_slice(this.password_verification_hash.as_ref());
					buf.extend_from_slice(this.iv.as_ref());

					// as per spec: first we add the version byte, compression algo, then iv before the data
					let integrity_code = this.integrity_code.as_mut().unwrap();
					integrity_code.update(&[0x01, 0x6e]);
					integrity_code.update(this.iv.as_ref());

					match this.read.poll_next(cx) {
						Poll::Pending => *this.state = EncryptState::PostHeader,
						Poll::Ready(None) => *this.state = EncryptState::Finalizing,
						Poll::Ready(Some(Err(e))) => {
							*this.state = EncryptState::Finished;
							return Poll::Ready(Some(Err(e)));
						},
						Poll::Ready(Some(Ok(bytes))) => {
							*this.state = EncryptState::PostHeader;
							this.block_buffer.put(bytes);
						}
					}

					return Poll::Ready(Some(Ok(Bytes::from_owner(buf))));
				},
				EncryptState::PostHeader => {
					if this.block_buffer.len() >= BYTES_PER_POLL {
						let mut data = this.block_buffer.split_to(BYTES_PER_POLL);
						this.aes.apply_keystream(&mut data);
						this.integrity_code.as_mut().unwrap().update(&data);

						return Poll::Ready(Some(Ok(data.freeze())));
					} else {
						match ready!(this.read.as_mut().poll_next(cx)) {
							Some(Ok(bytes)) => {
								this.block_buffer.put(bytes);
								continue;
							},
							Some(Err(e)) => {
								*this.state = EncryptState::Finished;
								return Poll::Ready(Some(Err(e)));
							},
							None => {
								*this.state = EncryptState::Finalizing;
								continue;
							}
						}
					}
				},
				EncryptState::Finalizing => {
					debug_assert!(this.block_buffer.len() < BYTES_PER_POLL);

					let mut final_data = this.block_buffer.split();

					let mut hmac = this.integrity_code.take()
						.expect("integrity_code only taken here");

					this.aes.apply_keystream(&mut final_data);

					hmac.update(&final_data);
					final_data.put(Bytes::from_owner(hmac.finalize().into_bytes()));

					*this.state = EncryptState::Finished;

					return Poll::Ready(Some(Ok(final_data.freeze())));
				},
				EncryptState::Finished => return Poll::Ready(None)
			}
		}
	}
}
