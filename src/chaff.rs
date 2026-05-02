use rand_core::TryRng;
use bytes::Bytes;
use futures_core::Stream;
use core::pin::Pin;
use core::task::{Context, Poll};
use crate::HEADER_LENGTH;

enum ChaffState {
	PreHeader,
	Data,
	Finished
}

pin_project_lite::pin_project! {
	pub struct ChaffStream<RNG> {
		rng: RNG,
		state: ChaffState,
		remaining_bytes: usize,
		chunk_size: usize
	}
}

const MIN_CHUNK_SIZE: usize = HEADER_LENGTH;

#[derive(Debug)]
pub struct ChunkSizeTooSmallError;

impl std::fmt::Display for ChunkSizeTooSmallError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		write!(f, "chunk size too small, must be at least {MIN_CHUNK_SIZE} bytes")
	}
}

impl std::error::Error for ChunkSizeTooSmallError {}

#[derive(Debug, Clone, Copy)]
pub struct ChaffArgs {
	output_length: usize,
	chunk_size: usize
}

impl ChaffArgs {
	/// The `output_length` parameter controls the size of the hypothetical chaff input file.
	/// In other words, the length of the stream is the length of the headers plus `output_length`.
	pub fn with_length(output_length: usize) -> Self {
		Self {
			output_length,
			chunk_size: 2048
		}
	}

	pub fn set_chunk_size(&mut self, chunk_size: usize) -> Result<(), ChunkSizeTooSmallError> {
		if chunk_size < MIN_CHUNK_SIZE {
			return Err(ChunkSizeTooSmallError);
		}

		self.chunk_size = chunk_size;
		Ok(())
	}
}

impl<RNG:TryRng> ChaffStream<RNG> {
	pub fn new(args: ChaffArgs, rng: RNG) -> Self {
		debug_assert!(args.chunk_size >= MIN_CHUNK_SIZE);

		Self {
			rng,
			state: ChaffState::PreHeader,
			remaining_bytes: args.output_length,
			chunk_size: args.chunk_size
		}
	}
}

impl<RNG: TryRng> Stream for ChaffStream<RNG> {
	type Item = Result<Bytes, RNG::Error>;

	fn poll_next(
		self: Pin<&mut Self>,
		_cx: &mut Context<'_>
	) -> Poll<Option<Self::Item>> {
		let this = self.project();

		match this.state {
			ChaffState::PreHeader => {
				let output_len: usize = (HEADER_LENGTH + *this.remaining_bytes).min(*this.chunk_size);
				debug_assert!(output_len >= HEADER_LENGTH);

				let mut output = Vec::with_capacity(output_len);

				output.extend_from_slice(b"SSEC");
				output.push(0x01);
				output.push(0x6e);
				output.extend_from_slice(&vec![0u8; output_len - 6]);

				if let Err(err) = this.rng.try_fill_bytes(&mut output[6..]) {
					*this.state = ChaffState::Finished;
					return Poll::Ready(Some(Err(err)));
				};

				let bytes_left = *this.remaining_bytes - (output.len() - HEADER_LENGTH);
				if bytes_left == 0 {
					*this.state = ChaffState::Finished
				} else {
					*this.state = ChaffState::Data;
					*this.remaining_bytes = bytes_left;
				}

				Poll::Ready(Some(Ok(Bytes::from_owner(output))))
			},
			ChaffState::Data => {
				let chaff_len: usize = (*this.chunk_size).min(*this.remaining_bytes);
				let mut chaff_data = vec![0u8; chaff_len];

				if let Err(err) = this.rng.try_fill_bytes(&mut chaff_data) {
					*this.state = ChaffState::Finished;
					return Poll::Ready(Some(Err(err)));
				};

				let bytes_left = *this.remaining_bytes - chaff_len;
				if bytes_left == 0 {
					*this.state = ChaffState::Finished
				} else {
					*this.remaining_bytes = bytes_left;
				}

				Poll::Ready(Some(Ok(Bytes::from_owner(chaff_data))))
			},
			ChaffState::Finished => Poll::Ready(None)
		}
	}
}
