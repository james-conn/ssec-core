use futures_core::Stream;
use bytes::{Bytes, BytesMut, BufMut};
use rand_core::TryCryptoRng;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::{Mac, KeyInit};
use core::pin::Pin;
use core::task::{Context, Poll, ready};
use core::num::NonZeroUsize;
use crate::util::{HmacSha3_256, new_arr, kdf, compute_verification_hash};
use crate::{DEFAULT_BYTES_PER_POLL, Aes256Ctr};

/// builder for arguments to [Encrypt::new] with default values, can be constructed with [EncryptArgs::default]
#[derive(Debug, Clone, Copy)]
pub struct EncryptArgs {
	bytes_per_poll: NonZeroUsize
}

impl Default for EncryptArgs {
	/// default settings are not part of semver contract
	fn default() -> Self {
		Self {
			bytes_per_poll: DEFAULT_BYTES_PER_POLL
		}
	}
}

impl EncryptArgs {
	/// sets the maximum number of bytes to encrypt before yielding to the executor
	pub fn set_bytes_per_poll(&mut self, bytes_per_poll: NonZeroUsize) {
		self.bytes_per_poll = bytes_per_poll;
	}
}

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
		iv: [u8; 16],
		bytes_per_poll: NonZeroUsize
	}
}

impl<R> Encrypt<R> {
	/// This method is *very* blocking.
	/// If you're using Tokio I advise that you wrap this call in a `spawn_blocking`.
	///
	/// SECURITY: It is advisable to zero out the memory containing the password after this method returns.
	pub fn new<RNG: TryCryptoRng>(
		additional_args: EncryptArgs,
		rng: &mut RNG,
		password: &[u8],
		read: R
	) -> Result<Self, RNG::Error> {
		let mut password_salt = new_arr::<32>();
		rng.try_fill_bytes(password_salt.as_mut())?;

		let aes_key = kdf(password, password_salt.as_ref());
		let password_verification_hash = compute_verification_hash(&aes_key);

		let mut iv = [0; 16];
		rng.try_fill_bytes(&mut iv)?;

		let aes = Aes256Ctr::new(aes_key.as_ref().get_ref().into(), (&iv).into());

		Ok(Self {
			read,
			aes,
			password_salt,
			password_verification_hash,
			integrity_code: Some(HmacSha3_256::new_from_slice(aes_key.as_ref().get_ref()).unwrap()),
			state: EncryptState::PreHeader,
			block_buffer: BytesMut::new(),
			iv,
			bytes_per_poll: additional_args.bytes_per_poll
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
					if this.block_buffer.len() >= this.bytes_per_poll.get() {
						let mut data = this.block_buffer.split_to(this.bytes_per_poll.get());
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
					debug_assert!(this.block_buffer.len() < this.bytes_per_poll.get());

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
