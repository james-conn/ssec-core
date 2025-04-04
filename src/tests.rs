use futures_util::StreamExt;
use bytes::{Bytes, BytesMut};
use rand_core::SeedableRng;
use zeroize::Zeroizing;
use crate::encrypt::Encrypt;
use crate::decrypt::{Decrypt, DecryptionError};

const RNG_SEED: u64 = 12345678;
const PASSWORD: &[u8] = b"hunter2";
const TEST_BUF_SHORT: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8];
const TEST_BUF_LONG: &[u8] = &[42; 12345];
// `Encrypt` and `Decrypt` both work on 8 AES blocks at a time so
// it is possible for things to break when working with data that is
// an exact multiple of 8 AES blocks
const TEST_BUF_PERFECTLY_ALIGNED: &[u8] = &[42; 8 * 16 * 50];

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
				Encrypt::new_uncompressed(s, PASSWORD, &mut rng, $b.len() as u64).unwrap()
			}).await.unwrap();

			while let Some(chunk) = encryptor.next().await {
				std::hint::black_box(chunk.unwrap());
			}
		}
	}
}

test_encrypt!(encrypt_buf_short, TEST_BUF_SHORT);
test_encrypt!(encrypt_buf_long, TEST_BUF_LONG);
test_encrypt!(encrypt_buf_perfectly_aligned, TEST_BUF_PERFECTLY_ALIGNED);

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
				Encrypt::new_uncompressed(s, PASSWORD, &mut rng, $b.len() as u64).unwrap()
			}).await.unwrap();

			let encrypted = encryptor.map(|c| c.unwrap()).collect::<BytesMut>().await.freeze();
			let s = futures_util::stream::once(
				std::future::ready(Result::<Bytes, std::io::Error>::Ok(encrypted))
			);

			let decryptor = Decrypt::new(s, Zeroizing::new(PASSWORD.to_vec()));

			let decrypted = decryptor.map(|c| c.unwrap()).collect::<BytesMut>().await.freeze();

			assert_eq!($b, decrypted);
		}
	}
}

test_end_to_end!(end_to_end_short, TEST_BUF_SHORT);
test_end_to_end!(end_to_end_long, TEST_BUF_LONG);
test_end_to_end!(end_to_end_perfectly_aligned, TEST_BUF_PERFECTLY_ALIGNED);

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
				Encrypt::new_uncompressed(s, PASSWORD, &mut rng, $b.len() as u64).unwrap()
			}).await.unwrap();

			let mut encrypted: BytesMut = encryptor.map(|c| c.unwrap()).collect().await;
			encrypted[$n_bit] ^= $v;
			let s = futures_util::stream::once(
				std::future::ready(Result::<Bytes, std::io::Error>::Ok(encrypted.freeze()))
			);

			let mut decryptor = Decrypt::new(s, Zeroizing::new(PASSWORD.to_vec()));

			let mut errored = false;

			while let Some(chunk) = decryptor.next().await {
				match chunk {
					Ok(_) => (),
					Err(DecryptionError::$e) => {
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
				Encrypt::new_uncompressed(s, PASSWORD, &mut rng, $b.len() as u64).unwrap()
			}).await.unwrap();

			let encrypted = encryptor.map(|c| c.unwrap()).collect::<BytesMut>().await.freeze();
			let s = futures_util::stream::once(
				std::future::ready(Result::<Bytes, std::io::Error>::Ok(encrypted))
			);

			let mut decryptor = Decrypt::new(s, Zeroizing::new(b"not_hunter2".to_vec()));

			let mut errored = false;

			while let Some(chunk) = decryptor.next().await {
				match chunk {
					Ok(_) => (),
					Err(DecryptionError::PasswordIncorrect) => {
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

test_password!(wrong_password_short, TEST_BUF_SHORT);
test_password!(wrong_password_long, TEST_BUF_LONG);
test_password!(wrong_password_perfectly_aligned, TEST_BUF_PERFECTLY_ALIGNED);
