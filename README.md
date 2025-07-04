# ssec-core

This repository is **not** for the CLI, if you're a prospective user you probably want to be [here](https://github.com/james-conn/ssec-cli).

## Introduction
SSEC was developed as a simple alternative to ZIP for single files (analogous to gzip, but for encryption).
This repository contains both the specification of the file format, and a streaming implementation (the `ssec-core` crate) in Rust.
The implementation is based around the Futures-rs' `Stream` abstraction, so it is sans-IO and async runtime agnostic.
The decryption implementation is structured like a state machine so that consumers can avoid blocking the executor by moving the computation of KDF onto a seperate threadpool (such as a Tokio blocking task).

## Security Guarentees
The headers of a SSEC file reveal no information about its contents.
The only information about the contents that is revealed is the size (duh).
Attempting decryption of a SSEC file requires a lot (512 MB) of memory, so even state-sponsored brute force attacks are unfeasible.
When decrypting a SSEC file, the authenticity of the contents can be verified after the entire file has been read.
SSEC makes no guarentees about side-channel resistance.
This specific implementation uses the `zeroize` crate to erase sensitive material from memory (see [the docs](https://docs.rs/zeroize/latest/zeroize/) for more information about what this actually entails).

## Feature Roadmap
- [x] uncompressed mode
- [x] Brotli compression (in `brotli` branch)
- [ ] Brotli decompression
- [ ] more robust testing
- [ ] fuzzing harness

## Acknowledgements
This entire project was massively inspired by (https://fasterthanli.me/articles/the-case-for-sans-io).
