mod util;

const DEFAULT_BYTES_PER_POLL: core::num::NonZeroUsize = core::num::NonZeroUsize::new(128).unwrap();

const HEADER_LENGTH: usize = 150;

type Aes256Ctr = ctr::Ctr64LE<aes::Aes256>;

pub mod encrypt;
pub use encrypt::{Encrypt, EncryptArgs};

pub mod decrypt;
pub use decrypt::{Decrypt, DecryptArgs};

pub mod chaff;
pub use chaff::ChaffStream;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod qc_tests;
