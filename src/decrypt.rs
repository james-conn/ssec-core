use futures_core::Stream;
use bytes::{Bytes, BytesMut, BufMut};
use zeroize::Zeroizing;
use thiserror::Error;
use cbc::cipher::{KeyIvInit, BlockDecryptMut};
use hmac::Mac;
use block_padding::{Pkcs7, RawPadding};
use constant_time_eq::constant_time_eq_64;
use std::thread::{spawn, JoinHandle};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use crate::util::{HmacSha3_512, kdf, compute_verification_hash};
use crate::AES_BLOCKS_PER_POLL;

type Aes256Cbc = cbc::Decryptor<aes::Aes256>;

struct KdfState {
	waker: Option<Waker>,
	password: Zeroizing<Vec<u8>>,
	salt: [u8; 32],
	verification_hash: [u8; 64],
	block_count: u32,
	iv: [u8; 16],
	version_byte: u8,
	compression_algo: u8
}

struct DecryptionState {
	aes: Aes256Cbc,
	integrity_code: Option<HmacSha3_512>,
	block_count: u32
}

impl KdfState {
	fn compute(mut self) -> Option<Box<DecryptionState>> {
		let key = kdf(self.password.as_ref(), &self.salt);

		let result = if constant_time_eq_64(compute_verification_hash(&key).as_ref(), &self.verification_hash) {
			let mut integrity_code = HmacSha3_512::new_from_slice(key.as_ref().get_ref()).unwrap();
			integrity_code.update(&[self.version_byte, self.compression_algo]);

			Some(Box::new(DecryptionState {
				aes: Aes256Cbc::new(key.as_ref().get_ref().into(), self.iv.as_ref().into()),
				integrity_code: Some(integrity_code),
				block_count: self.block_count
			}))
		} else {
			None
		};

		self.waker.take().expect("waker only taken here").wake();

		result
	}
}

enum DecryptState {
	PreHeader(Option<Zeroizing<Vec<u8>>>),
	Kdf(Option<JoinHandle<Option<Box<DecryptionState>>>>),
	PostHeader(Box<DecryptionState>),
	Done
}

pin_project_lite::pin_project! {
	pub struct Decrypt<R> {
		#[pin]
		read: R,
		state: DecryptState,
		buffer: BytesMut
	}
}

impl<E, R: Stream<Item = Result<Bytes, E>>> Decrypt<R> {
	pub fn new(read: R, password: Zeroizing<Vec<u8>>) -> Self {
		Self {
			read,
			state: DecryptState::PreHeader(Some(password)),
			buffer: BytesMut::new()
		}
	}

	/// Returns the number of bytes that will be read from the wrapped stream.
	/// If this information is not available yet, `None` will be returned.
	pub fn remaining_read_len(&self) -> Option<u64> {
		match &self.state {
			DecryptState::PreHeader(_) | DecryptState::Kdf(_) => None,
			DecryptState::PostHeader(state) => {
				Some(
					(state.block_count as u64 * 16) // remaining blocks to be read
					+ 64 // add an extra 64 for the integrity code at the end
					- self.buffer.len() as u64 // subtract what we already have
				)
			},
			DecryptState::Done => Some(0)
		}
	}
}

#[derive(Error, Debug)]
pub enum DecryptionError<E: std::error::Error> {
	#[error("wrapped stream did not produce a SSEC file")]
	NotSsec,
	#[error("SSEC file version {0:?} is unsupported")]
	UnsupportedVersion(u8),
	#[error("SSEC compression algorithm {0:?} is valid but currently unsupported")]
	UnsupportedCompression(u8),
	#[error("wrapped stream does not have the correct length")]
	IncorrectLength,
	/// This variant indicates that the file has definitely been tampered with.
	/// If you receive variant, you **MUST** invalidate any previously decrypted data from this file.
	#[error("the file has been tampered with, previously decrypted data is inauthentic and should be discarded")]
	IntegrityFailed,
	#[error("padding error when decrypting, the SSEC file is authentic but malformed")]
	Padding,
	#[error("provided password was incorrect")]
	PasswordIncorrect,
	#[error(transparent)]
	Stream(#[from] E)
}

impl<E, R> Stream for Decrypt<R>
where
	E: std::error::Error,
	R: Stream<Item = Result<Bytes, E>>
{
	type Item = Result<Bytes, DecryptionError<E>>;

	fn poll_next(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>
	) -> Poll<Option<Self::Item>> {
		let this = self.project();

		match this.state {
			DecryptState::PreHeader(password) => {
				if this.buffer.len() >= 122 {
					let header = this.buffer.split_to(122);

					if &header[0..=3] != b"SSEC" {
						return Poll::Ready(Some(Err(DecryptionError::NotSsec)));
					}

					if header[4] != 0x00 {
						return Poll::Ready(Some(Err(DecryptionError::UnsupportedVersion(header[4]))));
					}

					if header[5] != 0x6e {
						return Poll::Ready(Some(Err(match header[5] {
							0x7a => DecryptionError::UnsupportedCompression(0x7a),
							_ => DecryptionError::NotSsec
						})));
					}

					let salt: [u8; 32] = header[6..=37].try_into().unwrap();
					let verification_hash: [u8; 64] = header[38..=101].try_into().unwrap();
					let block_count = u32::from_le_bytes(
						header[102..=105].try_into().unwrap()
					);
					let iv: [u8; 16] = header[106..122].try_into().unwrap();

					let password = password.take().unwrap();

					let kdf_state = Box::new(KdfState {
						waker: Some(cx.waker().clone()),
						password,
						salt,
						verification_hash,
						block_count,
						iv,
						version_byte: header[4],
						compression_algo: header[5]
					});

					*this.state = DecryptState::Kdf(Some(spawn(move || {
						kdf_state.compute()
					})));

					Poll::Pending
				} else {
					match this.read.poll_next(cx) {
						Poll::Ready(Some(Ok(bytes))) => {
							this.buffer.put(bytes);
							cx.waker().wake_by_ref();
							Poll::Pending
						},
						other => other.map_err(DecryptionError::Stream)
					}
				}
			},
			DecryptState::Kdf(listener) => {
				if listener.as_ref().unwrap().is_finished() {
					let listener = listener.take().unwrap();

					match listener.join() {
						Ok(Some(new_state)) => {
							*this.state = DecryptState::PostHeader(new_state);
							cx.waker().wake_by_ref();
							Poll::Pending
						},
						Ok(None) => Poll::Ready(Some(Err(DecryptionError::PasswordIncorrect))),
						Err(_) => unreachable!("upper if guard prevents this case")
					}
				} else {
					// this branch is *technically* possible to reach, but probably not likely in practice
					cx.waker().wake_by_ref();
					Poll::Pending
				}
			},
			DecryptState::PostHeader(state) => {
				if state.block_count < AES_BLOCKS_PER_POLL as u32 && this.buffer.len() == (state.block_count as usize * 16) + 64 {
					let mut output = Vec::with_capacity(state.block_count as usize * 16);
					let mut hmac = state.integrity_code.take().expect("integrity_code only taken here");

					for _ in 0..state.block_count.saturating_sub(1) {
						let mut block = this.buffer.split_to(16);
						let block: &mut [u8; 16] = block.as_mut().try_into()
							.expect("if guard ensures we will always fill blocks");

						hmac.update(block);
						state.aes.decrypt_block_mut(block.into());
						output.extend_from_slice(block);
					}

					// final (padded) block
					let final_block = if state.block_count >= 1 {
						let mut final_block = this.buffer.split_to(16);
						let final_block_ref: &mut [u8; 16] = final_block.as_mut().try_into()
							.expect("if guard ensures we will always fill final block");

						hmac.update(final_block_ref);

						Some(final_block)
					} else {
						None
					};

					let stored_integrity_code = this.buffer.split_to(64);
					let stored_integrity_code: &[u8; 64] = stored_integrity_code.as_ref().try_into().unwrap();
					if !constant_time_eq_64(stored_integrity_code, hmac.finalize().into_bytes().as_ref()) {
						return Poll::Ready(Some(Err(DecryptionError::IntegrityFailed)));
					}

					if let Some(mut final_block) = final_block {
						let final_block_ref: &mut [u8; 16] = final_block.as_mut().try_into()
							.expect("this worked before, so it should work again");

						state.aes.decrypt_block_mut(final_block_ref.into());
						output.extend_from_slice(match Pkcs7::raw_unpad(final_block_ref) {
							Ok(unpadded) => unpadded,
							Err(_) => return Poll::Ready(Some(Err(DecryptionError::Padding)))
						});
					}

					*this.state = DecryptState::Done;

					Poll::Ready(Some(Ok(Bytes::from_owner(output))))
				} else if state.block_count >= AES_BLOCKS_PER_POLL as u32 && this.buffer.len() >= 16 * AES_BLOCKS_PER_POLL {
					let mut output = Vec::with_capacity(16 * AES_BLOCKS_PER_POLL);

					for _ in 0..AES_BLOCKS_PER_POLL {
						let mut block = this.buffer.split_to(16);
						let block: &mut [u8; 16] = block.as_mut().try_into()
							.expect("if guard ensures we will always fill blocks");

						state.integrity_code.as_mut().unwrap().update(block);
						state.aes.decrypt_block_mut(block.into());
						output.extend_from_slice(block);
					}

					state.block_count -= AES_BLOCKS_PER_POLL as u32;

					Poll::Ready(Some(Ok(Bytes::from_owner(output))))
				} else {
					match this.read.poll_next(cx) {
						Poll::Ready(Some(Ok(bytes))) => {
							this.buffer.put(bytes);
							cx.waker().wake_by_ref();
							Poll::Pending
						},
						Poll::Ready(None) => Poll::Ready(Some(Err(DecryptionError::IncorrectLength))),
						other => other.map_err(DecryptionError::Stream)
					}
				}
			},
			DecryptState::Done => Poll::Ready(None)
		}
	}
}
