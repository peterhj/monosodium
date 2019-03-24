# monosodium

[![docs.rs](https://docs.rs/monosodium/badge.svg)](https://docs.rs/monosodium/)

These are bindings to [libsodium](https://github.com/jedisct1/libsodium).
Unlike its namesake, `monosodium` is rather plain and boring.

Other than the direct bindings to libsodium, the only other abstractions in
this crate are in the `util` module and are centered around a `CryptoBuf`
type for wrapping sensitive bytes; this is described below.

## CryptoBuf

`util::CryptoBuf` is a simple wrapper struct around an inner `Vec<u8>` buffer.
`util::CryptoBuf` implements `PartialEq` and `Eq` (using libsodium's
constant-time comparison function `sodium_memcmp`), implements `Drop` by
zeroing its inner `Vec<u8>` buffer (using `sodium_memzero`), and has
constructors that initialize its inner buffer with zero-valued bytes or random
bytes (using `randombytes_buf`).

### HashCryptoBuf

There is a related struct, `util::HashCryptoBuf`, that additionally implements
`Hash`.

### KeyPair

A public/secret pair of key buffers is encapsulated in a `util::KeyPair`.
This is also the return type of `gen_sign_keypair`, which is the wrapper around
libsodium's `crypto_sign_keypair`.
