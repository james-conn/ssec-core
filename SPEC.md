# Copyright Notice
Copyright © 2025 James Connolly. \<me@j-conn.com\>

This specification document is licensed under the [Creative Commons Attribution-ShareAlike 4.0 International](https://creativecommons.org/licenses/by-sa/4.0/) license.

# Simple Symmetric Encryption & Compression (SSEC) format
A file is encrypted with a password and optionally compressed.

# Motivation
SSEC was developed as an alternative to the zip file format for [yeet-it.com](https://yeet-it.com).
The zip file format is way too complicated for our purposes.
The cryptography of zip encryption is either weak, unsuited for the future (due to use of PBKDF2, which is not memory-hard), or patent encumbered.
Zip files leak metadata like filenames and size of the uncompressed file by design, SSEC does not store filenames and future versions may optionally include additional chaff data to obfuscate file length.
I did not use GCM is because Rust currently has no widely trusted/used implementation of AES-GCM that is capable of streaming encryption/decryption and I would very much like to avoid writing my own AES-GCM implementation.
I avoided the STREAM construction (from `aead::stream`) because the storage required for authentication tags scales with the length of the message, potentially wasting space in large files (unlike an HMAC which uses a constant amount of storage).
SSEC version 0 uses CBC which provides the very minor theoretical advantage that if--for whatever reason--the integrity check could be bypassed or subverted, then modifications to the ciphertext will cascade instead of being confined to a single block, hopefully increasing the probability the user will detect the file has been tampered with.
Obviously the disadvantage of using CBC over something like CTR is reduced performance due to pipeline stalling.
If performance proves to be a problem in real world testing I will switch to CTR mode, but I suspect the bottleneck in this system is more likely to be IO than CPU.
The threat model SSEC is an adversary capable of spending a nearly unbounded amount of money on offline cracking and is capable of live arbitrary reads & writes.
SSEC guarantees confidentiality and integrity against such an adversary.

# Format
- Bytes 0-3: magic, the constant "`SSEC`" (`0x53534543`)
- Byte 4: version number
	- `0x00`: version 0 (this version)
	- other values are reserved for future use and are to be considered invalid
- Byte 5: compression algorithm
	- `0x6e`: no compression (identity function)
	- `0x7a`: zstd (of unspecified compression level)
	- other values are reserved for future use and are to be considered invalid
- Bytes 6-37: password salt (randomly generated, used for password verification hash)
- Bytes 38-101: password verification hash (see below)
- Bytes 102-105: encrypted file block count (little endian)
- Bytes 106-121: initialization vector (randomly generated)
- Bytes 122-(EOF-64): encrypted file (see below)
- Bytes (EOF-63)-EOF: integrity code (see below)

# Note on Argon2dKDF
The parameters used for Argon2dKDF are as follows:

- version: 19 (`0x13`)
- memory cost (m cost): 512 * 1024 = 524288 (512 MB)
- iterations (t cost): 10
- parallelism (p cost): 1
- output length: 32 bytes

I don't think that side channel attacks are a realistic threat for SSEC users, so I elected to use Argon2d instead of Argon2i or Argon2id.
Files can only be encrypted or decrypted on devices that hold the password in memory, so any attacker capable of side-channel attacks could just use an evil maid or rubberhose cryptanalysis.

# Password Verification Hash {#password-verification-hash}
The password is first passed into Argon2dKDF using the stored salt.
The output of the Argon2d key derivation is then hashed with SHA3-512.
When attempting to decrypt, the computed value (from user inputted password) must match the stored value otherwise decryption MUST fail.

# Integrity Code {#integrity-code}
After the user inputs the password and the program checks the password verification hash, the program computes the following:

```
HMAC-SHA3-512(
	Argon2dKDF(input_password, stored_salt),
	concat(
		ssec_version_byte,
		ssec_compression_algorithm_byte,
		stored_encrypted_file
	)
)
```

If the computed value does not match the stored value then decryption MUST fail.
In the case of streaming decryption, there MUST be some mechanism to retroactively invalidate decrypted data because an inauthentic message will not be discovered until it has already been decrypted.

## Integrity Code Implementation Guidance (non-normative) {#integrity-code-guidance}
In the `ssec` command line tool, retroactive invalidation is implemented by decrypting files in a temporary directory--only moving the decrypted file to its final location *after* the integrity code confirms the authenticity of the file.

# Encrypted File
To encrypt, the input file is passed through the function specified by the compression algorithm (byte 5).
The output of the compression is then encrypted using AES-256-CBC with PKCS7 padding, with the key being the output of `Argon2dKDF(password, salt)`.
The decryption process is the inverse of the encryption process.

# Preventing Padding Oracles {#anti-padding-oracle}
Padding oracles shouldn't be a serious threat for most SSEC users, but it's fairly trivial to mitigate them.
When decrypting, implementations MUST validate the integrity code before unpadding the final block in order to avoid creating a padding oracle.

# Security Checklist
- Did you [check the password verification hash](#password-verification-hash)?
- Did you [check the integrity code](#integrity-code)?  Also see the provided [implementation guidance](#integrity-code-guidance).
- Did you [validate the integrity code before unpadding the final block](#anti-padding-oracle)?
- Did you use a cryptographically secure RNG for random generation?
