use futures_core::Stream;
use bytes::{Bytes, BytesMut, BufMut};
use thiserror::Error;
use cbc::cipher::{KeyIvInit, BlockDecryptMut};
use hmac::Mac;
use block_padding::{Pkcs7, RawPadding};
use constant_time_eq::constant_time_eq_64;
use core::pin::Pin;
use core::task::{Context, Poll};
use crate::util::{HmacSha3_512, kdf, compute_verification_hash};
use crate::AES_BLOCKS_PER_POLL;

type Aes256Cbc = cbc::Decryptor<aes::Aes256>;

pin_project_lite::pin_project! {
	pub struct Decrypt<R> {
		#[pin]
		read: Option<R>,
		buffer: Option<BytesMut>
	}
}

impl<R> Decrypt<R> {
	pub fn new(read: R) -> Self {
		Self {
			read: Some(read),
			buffer: Some(BytesMut::new())
		}
	}
}
#[derive(Error, Debug)]
pub enum SsecHeaderError<E> {
	#[error("wrapped stream did not produce a SSEC file")]
	NotSsec,
	#[error("SSEC file version {0:?} is unsupported")]
	UnsupportedVersion(u8),
	#[error("SSEC compression algorithm {0:?} is valid but currently unsupported")]
	UnsupportedCompression(u8),
	#[error(transparent)]
	Stream(#[from] E)
}

impl<E, R: Stream<Item = Result<Bytes, E>> + Unpin> Future for Decrypt<R> {
	type Output = Result<Box<DecryptAwaitingPassword<R>>, SsecHeaderError<E>>;

	fn poll(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>
	) -> Poll<Self::Output> {
		let this = self.project();

		if this.buffer.as_ref().unwrap().len() >= 122 {
			let read = this.read.get_mut().take().unwrap();
			let mut buffer = this.buffer.take().unwrap();

			let header = buffer.split_to(122);

			if &header[0..=3] != b"SSEC" {
				return Poll::Ready(Err(SsecHeaderError::NotSsec));
			}

			if header[4] != 0x00 {
				return Poll::Ready(Err(SsecHeaderError::UnsupportedVersion(header[4])));
			}

			if header[5] != 0x6e {
				return Poll::Ready(Err(match header[5] {
					0x7a => SsecHeaderError::UnsupportedCompression(0x7a),
					_ => SsecHeaderError::NotSsec
				}));
			}

			let salt: [u8; 32] = header[6..=37].try_into().unwrap();
			let verification_hash: [u8; 64] = header[38..=101].try_into().unwrap();
			let block_count = u32::from_le_bytes(
				header[102..=105].try_into().unwrap()
			);
			let iv: [u8; 16] = header[106..122].try_into().unwrap();

			Poll::Ready(Ok(Box::new(DecryptAwaitingPassword {
				read,
				buffer,
				salt,
				verification_hash,
				block_count,
				iv,
				version_byte: header[4],
				compression_algo: header[5]
			})))
		} else {
			let read = this.read.as_pin_mut().unwrap();

			match read.poll_next(cx) {
				Poll::Ready(Some(Ok(bytes))) => {
					this.buffer.as_mut().unwrap().put(bytes);
					cx.waker().wake_by_ref();
					Poll::Pending
				},
				Poll::Ready(Some(Err(e))) => Poll::Ready(Err(SsecHeaderError::Stream(e))),
				Poll::Ready(None) => Poll::Ready(Err(SsecHeaderError::NotSsec)),
				Poll::Pending => Poll::Pending
			}
		}
	}
}

pub struct DecryptAwaitingPassword<R> {
	read: R,
	buffer: BytesMut,
	salt: [u8; 32],
	verification_hash: [u8; 64],
	block_count: u32,
	iv: [u8; 16],
	version_byte: u8,
	compression_algo: u8
}

impl<R> DecryptAwaitingPassword<R> {
	/// This method is *very* blocking.
	/// If you're using Tokio I advise that you wrap this call in a `spawn_blocking`.
	///
	/// If a `Result::Err` is returned it indicates the password was incorrect.
	pub fn try_password(self: Box<Self>, password: &[u8]) -> Result<DecryptStream<R>, Box<Self>> {
		let key = kdf(password, &self.salt);

		if constant_time_eq_64(compute_verification_hash(&key).as_ref(), &self.verification_hash) {
			let mut integrity_code = HmacSha3_512::new_from_slice(key.as_ref().get_ref()).unwrap();
			integrity_code.update(&[self.version_byte, self.compression_algo]);

			let state = DecryptState::PostHeader(Box::new(DecryptionState {
				aes: Aes256Cbc::new(key.as_ref().get_ref().into(), self.iv.as_ref().into()),
				integrity_code: Some(integrity_code),
				block_count: self.block_count
			}));

			Ok(DecryptStream {
				read: self.read,
				state,
				buffer: self.buffer
			})
		} else {
			Err(self)
		}
	}
}

struct DecryptionState {
	aes: Aes256Cbc,
	integrity_code: Option<HmacSha3_512>,
	block_count: u32
}

enum DecryptState {
	PostHeader(Box<DecryptionState>),
	Done
}

pin_project_lite::pin_project! {
	pub struct DecryptStream<R> {
		#[pin]
		read: R,
		state: DecryptState,
		buffer: BytesMut
	}
}

impl<R> DecryptStream<R> {
	/// Returns the number of bytes that will be read from the wrapped stream.
	pub fn remaining_read_len(&self) -> u64 {
		match &self.state {
			DecryptState::PostHeader(state) => {
				(state.block_count as u64 * 16) // remaining blocks to be read
				+ 64 // add an extra 64 for the integrity code at the end
				- self.buffer.len() as u64 // subtract what we already have
			},
			DecryptState::Done => 0
		}
	}
}

#[derive(Error, Debug)]
pub enum DecryptStreamError<E: std::error::Error> {
	#[error("wrapped stream does not have the correct length")]
	IncorrectLength,
	/// This variant indicates that the file has definitely been tampered with.
	/// If you receive variant, you **MUST** invalidate any previously decrypted data from this file.
	#[error("the file has been tampered with, previously decrypted data is inauthentic and should be discarded")]
	IntegrityFailed,
	#[error("padding error when decrypting, the SSEC file is authentic but malformed")]
	Padding,
	#[error(transparent)]
	Stream(#[from] E)
}

impl<E, R> Stream for DecryptStream<R>
where
	E: std::error::Error,
	R: Stream<Item = Result<Bytes, E>>
{
	type Item = Result<Bytes, DecryptStreamError<E>>;

	fn poll_next(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>
	) -> Poll<Option<Self::Item>> {
		let this = self.project();

		match this.state {
			DecryptState::PostHeader(state) => {
				if state.block_count <= AES_BLOCKS_PER_POLL as u32 && this.buffer.len() == (state.block_count as usize * 16) + 64 {
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

					debug_assert!(state.block_count >= 1);
					let mut final_block = this.buffer.split_to(16);
					let final_block: &mut [u8; 16] = final_block.as_mut().try_into()
						.expect("should be at least one block left");

					hmac.update(final_block);

					let stored_integrity_code = this.buffer.split_to(64);
					let stored_integrity_code: &[u8; 64] = stored_integrity_code.as_ref().try_into().unwrap();
					if !constant_time_eq_64(stored_integrity_code, hmac.finalize().into_bytes().as_ref()) {
						return Poll::Ready(Some(Err(DecryptStreamError::IntegrityFailed)));
					}

					state.aes.decrypt_block_mut(final_block.into());
					output.extend_from_slice(match Pkcs7::raw_unpad(final_block) {
						Ok(unpadded) => unpadded,
						Err(_) => return Poll::Ready(Some(Err(DecryptStreamError::Padding)))
					});

					*this.state = DecryptState::Done;

					Poll::Ready(Some(Ok(Bytes::from_owner(output))))
				} else if state.block_count > AES_BLOCKS_PER_POLL as u32 && this.buffer.len() >= 16 * AES_BLOCKS_PER_POLL {
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
						Poll::Ready(None) => Poll::Ready(Some(Err(DecryptStreamError::IncorrectLength))),
						other => other.map_err(DecryptStreamError::Stream)
					}
				}
			},
			DecryptState::Done => Poll::Ready(None)
		}
	}
}
