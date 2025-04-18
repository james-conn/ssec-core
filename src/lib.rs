mod util;

const AES_BLOCKS_PER_POLL: usize = 8;

pub mod encrypt;
pub use encrypt::Encrypt;

pub mod decrypt;
pub use decrypt::Decrypt;

#[cfg(test)]
mod tests;
