use futures_core::Stream;
use bytes::{Bytes, BytesMut, BufMut};
use rand_core::TryCryptoRng;
use hmac::Mac;
use cbc::cipher::KeyIvInit;
use cbc::cipher::BlockEncryptMut;
use block_padding::{Pkcs7, RawPadding};
use thiserror::Error;
use core::pin::Pin;
use core::task::{Context, Poll};
use crate::util::{HmacSha3_512, new_arr, length_to_blocks, kdf, compute_verification_hash};

type Aes256Cbc = cbc::Encryptor<aes::Aes256>;

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
		aes: Aes256Cbc,
		password_salt: Box<[u8; 32]>,
		password_verification_hash: Box<[u8; 64]>,
		block_count: u32,
		integrity_code: Option<HmacSha3_512>,
		state: EncryptState,
		block_buffer: BytesMut,
		iv: [u8; 16]
	}
}

#[derive(Error, Debug)]
pub enum NewEncryptError<R: TryCryptoRng> {
	#[error(transparent)]
	Rng(R::Error),
	#[error("length not supported by SSEC specification")]
	TooLong(#[from] std::num::TryFromIntError)
}

impl<R> Encrypt<R> {
	/// This method is *very* blocking.
	/// If you're using Tokio I advise that you wrap this call in a `spawn_blocking`.
	/// It's very important that you provide the correct length of the `read` stream otherwise you'll get a corrupted stream.
	///
	/// SECURITY: It is advisable to zero out the memory containing the password after this method returns.
	pub fn new_uncompressed<RNG: TryCryptoRng>(read: R, password: &[u8], rng: &mut RNG, length: u64) -> Result<Self, NewEncryptError<RNG>> {
		let mut password_salt = new_arr::<32>();
		rng.try_fill_bytes(password_salt.as_mut())
			.map_err(NewEncryptError::Rng)?;

		let aes_key = kdf(password, password_salt.as_ref());
		let password_verification_hash = compute_verification_hash(&aes_key);
		let block_count = length_to_blocks(length)?;

		let mut iv = [0; 16];
		rng.try_fill_bytes(&mut iv)
			.map_err(NewEncryptError::Rng)?;

		let aes = Aes256Cbc::new(aes_key.as_ref().get_ref().into(), iv.as_ref().into());

		Ok(Self {
			read,
			aes,
			password_salt,
			password_verification_hash,
			block_count,
			integrity_code: Some(HmacSha3_512::new_from_slice(aes_key.as_ref().get_ref()).unwrap()),
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
		let this = self.project();

		match this.state {
			EncryptState::PostHeader => {
				if this.block_buffer.len() >= 8 * 16 {
					let mut output = Vec::with_capacity(8 * 16);

					for _ in 0..8 {
						let mut block = this.block_buffer.split_to(16);
						let block: &mut [u8; 16] = block.as_mut().try_into()
							.expect("if guard ensures we will always fill blocks");

						this.aes.encrypt_block_mut(block.into());
						output.extend_from_slice(block);
					}

					this.integrity_code.as_mut().unwrap().update(&output);

					Poll::Ready(Some(Ok(Bytes::from_owner(output))))
				} else {
					match this.read.poll_next(cx) {
						Poll::Ready(Some(Ok(bytes))) => {
							this.block_buffer.put(bytes);
							cx.waker().wake_by_ref();
							Poll::Pending
						},
						Poll::Ready(None) => {
							*this.state = EncryptState::Finalizing;
							cx.waker().wake_by_ref();
							Poll::Pending
						},
						other => other
					}
				}
			},
			EncryptState::Finalizing => {
				if this.block_buffer.len() >= 8 * 16 {
					let mut output = Vec::with_capacity(8 * 16);

					for _ in 0..8 {
						let mut block = this.block_buffer.split_to(16);
						let block: &mut [u8; 16] = block.as_mut().try_into()
							.expect("if guard ensures we will always fill blocks");

						this.aes.encrypt_block_mut(block.into());
						output.extend_from_slice(block);
					}

					this.integrity_code.as_mut().unwrap().update(&output);

					Poll::Ready(Some(Ok(Bytes::from_owner(output))))
				} else {
					let remaining_blocks = length_to_blocks(this.block_buffer.len() as u64)
						.expect("if guard prevents overflow") as usize;

					let mut output = Vec::with_capacity((remaining_blocks * 16) + 64);

					let mut hmac = this.integrity_code.take()
						.expect("integrity_code only taken here");

					for _ in 0..remaining_blocks.saturating_sub(1) {
						let mut block = this.block_buffer.split_to(16);
						let block: &mut [u8; 16] = block.as_mut().try_into()
							.expect("if guard ensures we will always fill blocks");

						this.aes.encrypt_block_mut(block.into());
						output.extend_from_slice(block);
					}

					if remaining_blocks >= 1 {
						let mut final_block = [0; 16];
						let final_len = this.block_buffer.len();
						final_block[..final_len].copy_from_slice(this.block_buffer.as_ref());
						Pkcs7::raw_pad(&mut final_block, final_len);
						this.aes.encrypt_block_mut(final_block.as_mut().into());
						output.extend_from_slice(&final_block);

						hmac.update(&output);
					}

					output.extend_from_slice(&hmac.finalize().into_bytes());

					*this.state = EncryptState::Finished;

					Poll::Ready(Some(Ok(Bytes::from_owner(output))))
				}
			},
			EncryptState::PreHeader => {
				match this.read.poll_next(cx) {
					Poll::Pending => (),
					Poll::Ready(None) => return Poll::Ready(None),
					Poll::Ready(Some(Err(e))) => return Poll::Ready(Some(Err(e))),
					Poll::Ready(Some(Ok(bytes))) => {
						this.block_buffer.put(bytes);
					}
				}

				let mut buf = Vec::with_capacity(
					4 + // magic
					1 + // version number
					1 + // compression algo
					32 + // password salt
					64 + // password verification hash
					4 + // file block count
					16 // IV
				);

				buf.extend_from_slice(b"SSEC");
				buf.push(0x00);
				buf.push(0x6e);
				buf.extend_from_slice(this.password_salt.as_ref());
				buf.extend_from_slice(this.password_verification_hash.as_ref());
				buf.extend_from_slice(&this.block_count.to_le_bytes());
				buf.extend_from_slice(this.iv.as_ref());

				// as per spec: first we add the version byte and compression algo before the data
				this.integrity_code.as_mut().unwrap().update(&[0x00, 0x6e]);

				*this.state = EncryptState::PostHeader;

				Poll::Ready(Some(Ok(Bytes::from_owner(buf))))
			},
			EncryptState::Finished => Poll::Ready(None)
		}
	}
}
