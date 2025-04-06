use zeroize::Zeroizing;
use sha3::{Sha3_512, Digest};
use hmac::Hmac;
use core::pin::Pin;
use core::ops::DerefMut;

pub(crate) type HmacSha3_512 = Hmac<Sha3_512>;

/// allocates a new boxed array with unspecified contents (like `malloc` in C)
#[inline]
pub(crate) fn new_arr<const N: usize>() -> Box<[u8; N]> {
	let arr = Box::<[u8; N]>::new_uninit();
	// SAFETY: any possible state of [u8; N] is valid
	unsafe { arr.assume_init() }
}

#[inline]
pub(crate) fn length_to_blocks(length: u64) -> Result<u32, std::num::TryFromIntError> {
	let blocks = (length / 16) + match length % 16 {
		0 => 0,
		_ => 1
	};

	u32::try_from(blocks)
}

// returns a pin to absolutely ensure the compiler won't troll our memory erasure
pub(crate) fn kdf(password: &[u8], salt: &[u8]) -> Pin<Zeroizing<[u8; 32]>> {
	let mut hash = Pin::new(Zeroizing::new([0; 32]));

	let argon = argon2::Argon2::new(
		argon2::Algorithm::Argon2d,
		argon2::Version::V0x13, // version 19
		argon2::Params::new(
			512 * 1024, // memory
			10, // iterations
			1, // parallelism
			Some(32) // KDF output length
		).unwrap()
	);

	argon.hash_password_into(password, salt, hash.deref_mut()).unwrap();

	hash
}

#[inline]
pub(crate) fn compute_verification_hash(aes_key: &[u8; 32]) -> Box<[u8; 64]> {
	Box::new(Sha3_512::digest(aes_key).into())
}
