use futures_core::Stream;
use bytes::{Bytes, BytesMut, BufMut};
use thiserror::Error;
use ctr::cipher::{KeyIvInit, StreamCipher};
use hmac::Mac;
use constant_time_eq::constant_time_eq_64;
use core::pin::Pin;
use core::task::{Context, Poll, ready};
use crate::util::{HmacSha3_512, kdf, compute_verification_hash};
use crate::{BYTES_PER_POLL, Aes256Ctr};

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

const HEADER_LEN: usize = 118;

impl<E, R: Stream<Item = Result<Bytes, E>> + Unpin> Future for Decrypt<R> {
	type Output = Result<Box<DecryptAwaitingPassword<R>>, SsecHeaderError<E>>;

	fn poll(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>
	) -> Poll<Self::Output> {
		let this = self.project();

		if this.buffer.as_ref().unwrap().len() >= HEADER_LEN {
			let read = this.read.get_mut().take().unwrap();
			let mut buffer = this.buffer.take().unwrap();

			let header = buffer.split_to(HEADER_LEN);

			if &header[0..=3] != b"SSEC" {
				return Poll::Ready(Err(SsecHeaderError::NotSsec));
			}

			if header[4] != 0x01 {
				return Poll::Ready(Err(SsecHeaderError::UnsupportedVersion(header[4])));
			}

			if header[5] != 0x6e {
				return Poll::Ready(Err(match header[5] {
					0x62 => SsecHeaderError::UnsupportedCompression(0x62),
					_ => SsecHeaderError::NotSsec
				}));
			}

			let salt: [u8; 32] = header[6..=37].try_into().unwrap();
			let verification_hash: [u8; 64] = header[38..=101].try_into().unwrap();
			let iv: [u8; 16] = header[102..HEADER_LEN].try_into().unwrap();

			Poll::Ready(Ok(Box::new(DecryptAwaitingPassword {
				read,
				buffer,
				salt,
				verification_hash,
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
	iv: [u8; 16],
	version_byte: u8,
	compression_algo: u8
}

impl<R> DecryptAwaitingPassword<R> {
	/// This method is *very* blocking.
	/// If you're using Tokio I advise that you wrap this call in a `spawn_blocking`.
	///
	/// If a `Result::Err` is returned it indicates the password was incorrect.
	///
	/// SECURITY: It is advisable to zero out the memory containing the password after this method returns.
	pub fn try_password(mut self: Box<Self>, password: &[u8]) -> Result<DecryptStream<R>, Box<Self>> {
		let key = kdf(password, &self.salt);

		if constant_time_eq_64(compute_verification_hash(&key).as_ref(), &self.verification_hash) {
			let mut integrity_code = HmacSha3_512::new_from_slice(key.as_ref().get_ref()).unwrap();
			integrity_code.update(&[self.version_byte, self.compression_algo]);
			integrity_code.update(&self.iv);

			let buf_len = self.buffer.len();
			let eof_buf = if buf_len >= 64 {
				self.buffer.split_off(buf_len - 64)
			} else {
				self.buffer.split()
			};
			debug_assert!(eof_buf.len() <= 64);

			let state = DecryptState::PostHeader(Box::new(DecryptionState {
				aes: Aes256Ctr::new(key.as_ref().get_ref().into(), self.iv.as_ref().into()),
				integrity_code: Some(integrity_code),
				eof: false,
				eof_buf
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
	aes: Aes256Ctr,
	integrity_code: Option<HmacSha3_512>,
	eof: bool,
	eof_buf: BytesMut
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
		buffer: BytesMut,
	}
}

#[derive(Error, Debug)]
pub enum DecryptStreamError<E> {
	#[error("wrapped stream was too short to have been a valid SSEC file (no integrity code)")]
	TooShort,
	#[error("the file has been tampered with, previously decrypted data is inauthentic and should be discarded")]
	IntegrityFailed,
	#[error(transparent)]
	Stream(#[from] E)
}

impl<E, R> Stream for DecryptStream<R>
where
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
				if state.eof {
					if state.eof_buf.len() < 64 {
						*this.state = DecryptState::Done;
						return Poll::Ready(Some(Err(DecryptStreamError::TooShort)));
					}
					debug_assert_eq!(state.eof_buf.len(), 64);

					let mut hmac = state.integrity_code.take().expect("integrity_code only taken here");
					let mut data = this.buffer.split();

					hmac.update(&data);
					state.aes.apply_keystream(&mut data);

					let stored_integrity_code: &[u8; 64] = state.eof_buf.as_ref().try_into().unwrap();
					if !constant_time_eq_64(stored_integrity_code, hmac.finalize().into_bytes().as_ref()) {
						*this.state = DecryptState::Done;
						return Poll::Ready(Some(Err(DecryptStreamError::IntegrityFailed)));
					}

					*this.state = DecryptState::Done;

					Poll::Ready(Some(Ok(data.freeze())))
				} else if this.buffer.len() >= BYTES_PER_POLL {
					let mut data = this.buffer.split_to(BYTES_PER_POLL);

					state.integrity_code.as_mut().unwrap().update(&data);
					state.aes.apply_keystream(&mut data);

					Poll::Ready(Some(Ok(data.freeze())))
				} else {
					match ready!(this.read.poll_next(cx)) {
						Some(Ok(bytes)) => {
							state.eof_buf.put(bytes);
							let eof_len = state.eof_buf.len();
							if eof_len > 64 {
								this.buffer.put(state.eof_buf.split_off(eof_len - 64));
								debug_assert_eq!(state.eof_buf.len(), 64);
							}
							cx.waker().wake_by_ref();
							Poll::Pending
						},
						Some(Err(e)) => {
							*this.state = DecryptState::Done;
							Poll::Ready(Some(Err(DecryptStreamError::Stream(e))))
						},
						None => {
							debug_assert!(state.eof_buf.len() <= 64);
							state.eof = true;
							cx.waker().wake_by_ref();
							Poll::Pending
						}
					}
				}
			},
			DecryptState::Done => Poll::Ready(None)
		}
	}
}
