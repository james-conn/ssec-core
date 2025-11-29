mod util;

const HEADER_LENGTH: usize = 150;
const BYTES_PER_POLL: usize = 128;

type Aes256Ctr = ctr::Ctr64LE<aes::Aes256>;

pub mod encrypt;
pub use encrypt::Encrypt;

pub mod decrypt;
pub use decrypt::Decrypt;

pub mod chaff;
pub use chaff::ChaffStream;

#[cfg(test)]
mod tests;
