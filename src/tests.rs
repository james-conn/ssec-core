use futures_util::StreamExt;
use bytes::{Bytes, BytesMut};
use rand_core::SeedableRng;
use crate::encrypt::Encrypt;
use crate::decrypt::{Decrypt, DecryptStreamError};

const RNG_SEED: u64 = 12345678;

const PASSWORD: &[u8] = b"hunter2";
const WRONG_PASSWORD: &[u8] = b"not_hunter2";

const TEST_BUF_EMPTY: &[u8] = &[];
const TEST_BUF_SHORT: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
const TEST_BUF_LONG: &[u8] = &[42; 12345];
// `Encrypt` and `Decrypt` both work on 8 AES blocks at a time so
// it is possible for things to break when working with data that is
// an exact multiple of 8 AES blocks
const TEST_BUF_PERFECTLY_ALIGNED: &[u8] = &[42; 8 * 16 * 50];
// what if we have a multiple of the block size that's *not* divisible by 8?
const TEST_BUF_IMPERFECTLY_ALIGNED: &[u8] = &[42; 9 * 16];
// the data is one block less than 8 AES blocks, but padding adds an
// extra block which makes it a perfect multiple of 8 again
const TEST_BUF_PERFECT_PAD: &[u8] = &[42; 7 * 16];

macro_rules! test_encrypt {
	($n:ident, $b:ident) => {
		#[tokio::test]
		async fn $n() {
			let mut rng = rand::rngs::StdRng::seed_from_u64(RNG_SEED);

			let buf = Bytes::from_owner($b);

			let s = futures_util::stream::once(
				std::future::ready(Result::<Bytes, ()>::Ok(buf))
			);

			let mut encryptor = tokio::task::spawn_blocking(move || {
				Encrypt::new_uncompressed(s, PASSWORD, &mut rng).unwrap()
			}).await.unwrap();

			while let Some(chunk) = encryptor.next().await {
				let _ = chunk.unwrap();
			}
		}
	}
}

test_encrypt!(encrypt_buf_empty, TEST_BUF_EMPTY);
test_encrypt!(encrypt_buf_short, TEST_BUF_SHORT);
test_encrypt!(encrypt_buf_long, TEST_BUF_LONG);
test_encrypt!(encrypt_buf_perfectly_aligned, TEST_BUF_PERFECTLY_ALIGNED);
test_encrypt!(encrypt_buf_imperfectly_aligned, TEST_BUF_IMPERFECTLY_ALIGNED);
test_encrypt!(encrypt_buf_perfect_pad, TEST_BUF_PERFECT_PAD);

macro_rules! test_end_to_end {
	($n:ident, $b:ident) => {
		#[tokio::test]
		async fn $n() {
			let mut rng = rand::rngs::StdRng::seed_from_u64(RNG_SEED);

			let buf = Bytes::from_owner($b);

			let s = futures_util::stream::once(
				std::future::ready(Result::<Bytes, ()>::Ok(buf))
			);

			let encryptor = tokio::task::spawn_blocking(move || {
				Encrypt::new_uncompressed(s, PASSWORD, &mut rng).unwrap()
			}).await.unwrap();

			let encrypted = encryptor.map(|c| c.unwrap()).collect::<BytesMut>().await.freeze();
			let s = futures_util::stream::once(
				std::future::ready(Result::<Bytes, std::io::Error>::Ok(encrypted))
			);

			let decryptor = Decrypt::new(s).await.unwrap();
			let decryptor = tokio::task::spawn_blocking(move || {
				let Ok(stream) = decryptor.try_password(PASSWORD) else { panic!("password should be correct") };
				stream
			}).await.unwrap();

			let decrypted = decryptor.map(|c| c.unwrap()).collect::<BytesMut>().await.freeze();

			assert_eq!($b, decrypted);
		}
	}
}

test_end_to_end!(end_to_end_empty, TEST_BUF_EMPTY);
test_end_to_end!(end_to_end_short, TEST_BUF_SHORT);
test_end_to_end!(end_to_end_long, TEST_BUF_LONG);
test_end_to_end!(end_to_end_perfectly_aligned, TEST_BUF_PERFECTLY_ALIGNED);
test_end_to_end!(end_to_end_imperfectly_aligned, TEST_BUF_IMPERFECTLY_ALIGNED);
test_end_to_end!(end_to_end_perfect_pad, TEST_BUF_PERFECT_PAD);

macro_rules! test_tamper_detection {
	($n:ident, $b:ident, $n_bit:literal, $v:literal, $e:ident) => {
		#[tokio::test]
		async fn $n() {
			let mut rng = rand::rngs::StdRng::seed_from_u64(RNG_SEED);

			let buf = Bytes::from_owner($b);

			let s = futures_util::stream::once(
				std::future::ready(Result::<Bytes, ()>::Ok(buf))
			);

			let encryptor = tokio::task::spawn_blocking(move || {
				Encrypt::new_uncompressed(s, PASSWORD, &mut rng).unwrap()
			}).await.unwrap();

			let mut encrypted: BytesMut = encryptor.map(|c| c.unwrap()).collect().await;
			encrypted[$n_bit] ^= $v;
			let s = futures_util::stream::once(
				std::future::ready(Result::<Bytes, std::io::Error>::Ok(encrypted.freeze()))
			);

			let decryptor = Decrypt::new(s).await.unwrap();
			let mut decryptor = tokio::task::spawn_blocking(move || {
				let Ok(stream) = decryptor.try_password(PASSWORD) else { panic!("password should be correct") };
				stream
			}).await.unwrap();

			let mut errored = false;

			while let Some(chunk) = decryptor.next().await {
				match chunk {
					Ok(_) => (),
					Err(DecryptStreamError::$e) => {
						errored = true;
						break;
					},
					Err(e) => panic!("incorrect error raised {e:?}")
				}
			}

			assert!(errored);
		}
	}
}

test_tamper_detection!(tamper_short, TEST_BUF_SHORT, 150, 0x42, IntegrityFailed);
test_tamper_detection!(tamper_long, TEST_BUF_LONG, 1234, 0x42, IntegrityFailed);
test_tamper_detection!(tamper_perfectly_aligned, TEST_BUF_PERFECTLY_ALIGNED, 1234, 0x42, IntegrityFailed);
test_tamper_detection!(tamper_imperfectly_aligned, TEST_BUF_IMPERFECTLY_ALIGNED, 150, 0x42, IntegrityFailed);
test_tamper_detection!(tamper_perfect_pad, TEST_BUF_PERFECT_PAD, 150, 0x42, IntegrityFailed);

macro_rules! test_password {
	($n:ident, $b:ident) => {
		#[tokio::test]
		async fn $n() {
			let mut rng = rand::rngs::StdRng::seed_from_u64(RNG_SEED);

			let buf = Bytes::from_owner($b);

			let s = futures_util::stream::once(
				std::future::ready(Result::<Bytes, ()>::Ok(buf))
			);

			let encryptor = tokio::task::spawn_blocking(move || {
				Encrypt::new_uncompressed(s, PASSWORD, &mut rng).unwrap()
			}).await.unwrap();

			let encrypted = encryptor.map(|c| c.unwrap()).collect::<BytesMut>().await.freeze();
			let s = futures_util::stream::once(
				std::future::ready(Result::<Bytes, std::io::Error>::Ok(encrypted))
			);

			let decryptor = Decrypt::new(s).await.unwrap();
			let decryptor = tokio::task::spawn_blocking(move || {
				decryptor.try_password(WRONG_PASSWORD)
			}).await.unwrap();

			let decryptor = match decryptor {
				Ok(_) => panic!("password should be incorrect"),
				Err(d) => d
			};

			let decryptor = tokio::task::spawn_blocking(move || {
				let Ok(stream) = decryptor.try_password(PASSWORD) else { panic!("password should be correct") };
				stream
			}).await.unwrap();

			let decrypted = decryptor.map(|c| c.unwrap()).collect::<BytesMut>().await.freeze();

			assert_eq!($b, decrypted);
		}
	}
}

test_password!(wrong_password_empty, TEST_BUF_EMPTY);
test_password!(wrong_password_short, TEST_BUF_SHORT);
test_password!(wrong_password_long, TEST_BUF_LONG);
test_password!(wrong_password_perfectly_aligned, TEST_BUF_PERFECTLY_ALIGNED);
test_password!(wrong_password_imperfectly_aligned, TEST_BUF_IMPERFECTLY_ALIGNED);
test_password!(wrong_password_perfect_pad, TEST_BUF_PERFECT_PAD);
