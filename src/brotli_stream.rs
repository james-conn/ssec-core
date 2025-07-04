use bytes::{Bytes, BytesMut, BufMut};
use futures_core::Stream;
use brotli::enc::StandardAlloc;
use brotli::enc::encode::{BrotliEncoderStateStruct, BrotliEncoderOperation};
use core::pin::Pin;
use core::task::{Context, Poll, ready};

#[derive(Default)]
pub struct BrotliParams;

enum BrotliState {
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
		state: BrotliState
	}
}

impl<S> BrotliEncStream<S> {
	pub fn new(stream: S, _brotli_params: BrotliParams) -> Self {
		Self {
			stream,
			brotli: BrotliEncoderStateStruct::new(StandardAlloc::default()),
			buf: BytesMut::new(),
			state: BrotliState::Compressing
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
				BrotliState::Compressing => {
					if this.buf.is_empty() {
						match ready!(this.stream.as_mut().poll_next(cx)) {
							None => {
								*this.state = BrotliState::Flushing;
								continue;
							},
							Some(Ok(bytes)) => {
								this.buf.put(bytes);
								continue;
							},
							Some(Err(e)) => {
								*this.state = BrotliState::Finished;
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
				BrotliState::Flushing => {
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
						*this.state = BrotliState::Finishing;
					}

					out_buf.truncate(out_offset);
					return Poll::Ready(Some(Ok(Bytes::from_owner(out_buf))));
				},
				BrotliState::Finishing => {
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
						*this.state = BrotliState::Finished;
					}

					out_buf.truncate(out_offset);
					return Poll::Ready(Some(Ok(Bytes::from_owner(out_buf))));
				},
				BrotliState::Finished => {
					return Poll::Ready(None);
				}
			}
		}
	}
}
