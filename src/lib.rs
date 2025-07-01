mod util;

const BYTES_PER_POLL: usize = 128;

type Aes256Ctr = ctr::Ctr64LE<aes::Aes256>;

pub mod encrypt;
pub use encrypt::Encrypt;

pub mod decrypt;
pub use decrypt::Decrypt;

#[cfg(feature = "brotli")]
mod brotli_stream;

#[cfg(test)]
mod tests;
