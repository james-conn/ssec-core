use bytes::{Bytes, BytesMut, BufMut};
use futures_core::Stream;
use brotli::enc::StandardAlloc;
use brotli::enc::encode::{BrotliEncoderStateStruct, BrotliEncoderOperation};
use brotli::{BrotliDecompressStream, BrotliState, BrotliResult};
use core::pin::Pin;
use core::task::{Context, Poll, ready};

#[derive(Default)]
pub struct BrotliParams;

enum BrotliEncState {
	Compressing,
	Flushing,
	Finishing,
	Finished
}

pin_project_lite::pin_project! {
	pub struct BrotliEncStream<S> {
		#[pin]
		stream: S,
		brotli: BrotliEncoderStateStruct<StandardAlloc>,
		buf: BytesMut,
		state: BrotliEncState
	}
}

impl<S> BrotliEncStream<S> {
	pub fn new(stream: S, _brotli_params: BrotliParams) -> Self {
		Self {
			stream,
			brotli: BrotliEncoderStateStruct::new(StandardAlloc::default()),
			buf: BytesMut::new(),
			state: BrotliEncState::Compressing
		}
	}
}

// TODO: is this a reasonable number?
const BROTLI_BUF_LEN: usize = 1024;

impl<E, S: Stream<Item = Result<Bytes, E>>> Stream for BrotliEncStream<S> {
	type Item = Result<Bytes, E>;

	fn poll_next(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>
	) -> Poll<Option<Self::Item>> {
		let mut this = self.project();

		loop {
			match this.state {
				BrotliEncState::Compressing => {
					if this.buf.is_empty() {
						match ready!(this.stream.as_mut().poll_next(cx)) {
							None => {
								*this.state = BrotliEncState::Flushing;
								continue;
							},
							Some(Ok(bytes)) => {
								this.buf.put(bytes);
								continue;
							},
							Some(Err(e)) => {
								*this.state = BrotliEncState::Finished;
								return Poll::Ready(Some(Err(e)));
							}
						}
					}

					let mut in_offset = 0;
					let mut out_offset = 0;
					let mut out_buf = vec![0; BROTLI_BUF_LEN];

					let brotli_ok = this.brotli.compress_stream(
						BrotliEncoderOperation::BROTLI_OPERATION_PROCESS,
						&mut this.buf.len(),
						this.buf.as_ref(),
						&mut in_offset,
						&mut out_buf.len(),
						&mut out_buf,
						&mut out_offset,
						&mut None,
						&mut |_, _, _, _| ()
					);

					if !brotli_ok {
						todo!("handle brotli error");
					}

					let _ = this.buf.split_to(in_offset);
					out_buf.truncate(out_offset);

					return Poll::Ready(Some(Ok(Bytes::from_owner(out_buf))));
				},
				BrotliEncState::Flushing => {
					let mut out_offset = 0;
					let mut out_buf = vec![0; BROTLI_BUF_LEN];

					let brotli_ok = this.brotli.compress_stream(
						BrotliEncoderOperation::BROTLI_OPERATION_FLUSH,
						&mut 0,
						&[],
						&mut 0,
						&mut out_buf.len(),
						&mut out_buf,
						&mut out_offset,
						&mut None,
						&mut |_, _, _, _| ()
					);

					if !brotli_ok {
						todo!("handle brotli error");
					}

					if !this.brotli.has_more_output() {
						*this.state = BrotliEncState::Finishing;
					}

					out_buf.truncate(out_offset);
					return Poll::Ready(Some(Ok(Bytes::from_owner(out_buf))));
				},
				BrotliEncState::Finishing => {
					let mut out_offset = 0;
					let mut out_buf = vec![0; BROTLI_BUF_LEN];

					let brotli_ok = this.brotli.compress_stream(
						BrotliEncoderOperation::BROTLI_OPERATION_FINISH,
						&mut 0,
						&[],
						&mut 0,
						&mut out_buf.len(),
						&mut out_buf,
						&mut out_offset,
						&mut None,
						&mut |_, _, _, _| ()
					);

					if !brotli_ok {
						todo!("handle brotli error");
					}

					if this.brotli.is_finished() {
						*this.state = BrotliEncState::Finished;
					}

					out_buf.truncate(out_offset);
					return Poll::Ready(Some(Ok(Bytes::from_owner(out_buf))));
				},
				BrotliEncState::Finished => {
					return Poll::Ready(None);
				}
			}
		}
	}
}

enum BrotliDecState {
	Reading,
	Decompress,
	Finished
}

pin_project_lite::pin_project! {
	pub struct BrotliDecStream<S> {
		#[pin]
		stream: S,
		brotli: BrotliState<StandardAlloc, StandardAlloc, StandardAlloc>,
		buf: BytesMut,
		state: BrotliDecState,
		stream_finished: bool
	}
}

impl<S> BrotliDecStream<S> {
	pub fn new(stream: S) -> Self {
		Self {
			stream,
			brotli: BrotliState::new(
				StandardAlloc::default(),
				StandardAlloc::default(),
				StandardAlloc::default()
			),
			buf: BytesMut::new(),
			state: BrotliDecState::Reading,
			stream_finished: false
		}
	}
}

impl<E, S: Stream<Item = Result<Bytes, E>>> Stream for BrotliDecStream<S> {
	type Item = Result<Bytes, E>;

	fn poll_next(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>
	) -> Poll<Option<Self::Item>> {
		let mut this = self.project();

		loop {
			match this.state {
				BrotliDecState::Reading => {
					match ready!(this.stream.as_mut().poll_next(cx)) {
						None => {
							*this.stream_finished = true;
							*this.state = BrotliDecState::Decompress;
							continue;
						},
						Some(Ok(bytes)) => {
							this.buf.put(bytes);
							*this.state = BrotliDecState::Decompress;
							continue;
						},
						Some(Err(e)) => {
							*this.state = BrotliDecState::Finished;
							return Poll::Ready(Some(Err(e)));
						}
					}
				},
				BrotliDecState::Decompress => {
					let mut out_offset = 0;
					let mut out_buf = vec![0; BROTLI_BUF_LEN];

					let result = BrotliDecompressStream(
						&mut this.buf.len(),
						&mut 0,
						this.buf.as_ref(),
						&mut out_buf.len(),
						&mut out_offset,
						&mut out_buf,
						&mut 0,
						this.brotli
					);

					match result {
						BrotliResult::ResultSuccess => {
							if *this.stream_finished {
								*this.state = BrotliDecState::Finished;
							}

							out_buf.truncate(out_offset);
							return Poll::Ready(Some(Ok(Bytes::from_owner(out_buf))));
						},
						BrotliResult::NeedsMoreInput => {
							if *this.stream_finished {
								unreachable!("brotli wants more data but EOF reached");
							}

							*this.state = BrotliDecState::Reading;
							out_buf.truncate(out_offset);
							return Poll::Ready(Some(Ok(Bytes::from_owner(out_buf))));
						},
						BrotliResult::NeedsMoreOutput => {
							out_buf.truncate(out_offset);
							return Poll::Ready(Some(Ok(Bytes::from_owner(out_buf))));
						},
						BrotliResult::ResultFailure => {
							todo!("handle brotli error")
						}
					}
				},
				BrotliDecState::Finished => {
					return Poll::Ready(None);
				}
			}
		}
	}
}
