# monosodium

[![docs.rs](https://docs.rs/monosodium/badge.svg)](https://docs.rs/monosodium/)

These are bindings to [libsodium](https://github.com/jedisct1/libsodium).
Unlike its namesake, `monosodium` is rather plain and boring.

## CryptoBuf

Other than the direct bindings to libsodium, the only other abstraction in
this crate is `util::CryptoBuf`, which is a simple wrapper struct around an
inner `Vec<u8>`. `util::CryptoBuf` implements `PartialEq` and `Eq` (using
libsodium's constant-time comparison function `sodium_memcmp`), implements
`Drop` by zeroing its inner `Vec<u8>` buffer (using `sodium_memzero`), and
has constructors that initialize its inner buffer with zero-valued bytes or
random bytes (using `randombytes_buf`).

There is a related struct, `util::HashCryptoBuf`, that additionally implements
`Hash`.
