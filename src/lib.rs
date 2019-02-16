use crate::ffi::sodium::*;
use crate::util::{CryptoBuf, KeyPair};

use std::ffi::{CStr};
use std::os::raw::{c_char};
use std::ptr::{null, null_mut};

pub mod ffi;
pub mod util;

pub fn init_sodium() {
  assert_eq!(0, unsafe { sodium_init() });
}

pub fn random_buf(buf: &mut [u8]) {
  unsafe { randombytes_buf(buf.as_mut_ptr() as *mut _, buf.len()) };
}

pub fn zero_buf(buf: &mut [u8]) {
  unsafe { sodium_memzero(buf.as_mut_ptr() as *mut _, buf.len()) };
}

pub fn eq_bufs(buf: &[u8], other_buf: &[u8]) -> bool {
  if buf.len() != other_buf.len() {
    return false;
  }
  assert_eq!(buf.len(), other_buf.len());
  let ret = unsafe { sodium_memcmp(
      buf.as_ptr() as *const _,
      other_buf.as_ptr() as *const _,
      buf.len(),
  ) };
  match ret {
    0 => true,
    -1 => false,
    _ => panic!(),
  }
}

pub fn aead_key_buflen() -> usize {
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize
}

pub fn aead_nonce_buflen() -> usize {
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES as usize
}

pub fn aead_cipher_buflen(msg_len: usize) -> usize {
  let cipher_len = msg_len + crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;
  assert!(cipher_len > msg_len);
  cipher_len
}

pub fn aead_decrypt_buflen(cipher_len: usize) -> usize {
  let decrypt_len = cipher_len - crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;
  assert!(decrypt_len < cipher_len);
  decrypt_len
}

pub fn gen_aead_key(key_buf: &mut [u8]) {
  assert_eq!(key_buf.len(), crypto_aead_xchacha20poly1305_ietf_KEYBYTES as usize);
  unsafe { crypto_aead_xchacha20poly1305_ietf_keygen(key_buf.as_mut_ptr()) };
}

pub fn aead_encrypt(cipher_buf: &mut [u8], msg_buf: &[u8], moremsg_buf: &[u8], nonce_buf: &[u8], key_buf: &[u8]) -> Result<(), ()> {
  assert_eq!(cipher_buf.len(), aead_cipher_buflen(msg_buf.len()));
  assert_eq!(nonce_buf.len(), aead_nonce_buflen());
  assert_eq!(key_buf.len(), aead_key_buflen());
  let mut cipher_buflen_ret: u64 = 0;
  let ret = unsafe { crypto_aead_xchacha20poly1305_ietf_encrypt(
      cipher_buf.as_mut_ptr(), &mut cipher_buflen_ret as *mut _,
      msg_buf.as_ptr(), msg_buf.len() as u64,
      moremsg_buf.as_ptr(), moremsg_buf.len() as u64,
      null(),
      nonce_buf.as_ptr(), key_buf.as_ptr(),
  ) };
  assert_eq!(cipher_buflen_ret, cipher_buf.len() as u64);
  match ret {
    0 => {}
    -1 => return Err(()),
    _ => panic!(),
  }
  Ok(())
}

pub fn aead_decrypt(decrypt_buf: &mut [u8], cipher_buf: &[u8], moremsg_buf: &[u8], nonce_buf: &[u8], key_buf: &[u8]) -> Result<(), ()> {
  assert_eq!(decrypt_buf.len(), aead_decrypt_buflen(cipher_buf.len()));
  assert_eq!(nonce_buf.len(), aead_nonce_buflen());
  assert_eq!(key_buf.len(), aead_key_buflen());
  let mut decrypt_buflen_ret: u64 = 0;
  let ret = unsafe { crypto_aead_xchacha20poly1305_ietf_decrypt(
      decrypt_buf.as_mut_ptr(), &mut decrypt_buflen_ret as *mut _,
      null_mut(),
      cipher_buf.as_ptr(), cipher_buf.len() as u64,
      moremsg_buf.as_ptr(), moremsg_buf.len() as u64,
      nonce_buf.as_ptr(), key_buf.as_ptr(),
  ) };
  assert_eq!(decrypt_buflen_ret, decrypt_buf.len() as u64);
  match ret {
    0 => {}
    -1 => return Err(()),
    _ => panic!(),
  }
  Ok(())
}

pub fn auth_sig_buflen() -> usize {
  crypto_auth_hmacsha512256_BYTES as usize
}

pub fn auth_key_buflen() -> usize {
  crypto_auth_hmacsha512256_KEYBYTES as usize
}

pub fn auth_sign(sig_buf: &mut [u8], msg_buf: &[u8], key_buf: &[u8]) -> Result<(), ()> {
  assert_eq!(sig_buf.len(), auth_sig_buflen());
  assert_eq!(key_buf.len(), auth_key_buflen());
  let ret = unsafe { crypto_auth_hmacsha512256(
      sig_buf.as_mut_ptr(),
      msg_buf.as_ptr(), msg_buf.len() as u64,
      key_buf.as_ptr(),
  ) };
  match ret {
    0 => {}
    -1 => return Err(()),
    _ => panic!(),
  }
  Ok(())
}

pub fn auth_verify(sig_buf: &[u8], msg_buf: &[u8], key_buf: &[u8]) -> Result<(), ()> {
  assert_eq!(sig_buf.len(), auth_sig_buflen());
  assert_eq!(key_buf.len(), auth_key_buflen());
  let ret = unsafe { crypto_auth_hmacsha512256_verify(
      sig_buf.as_ptr(),
      msg_buf.as_ptr(), msg_buf.len() as u64,
      key_buf.as_ptr(),
  ) };
  match ret {
    0 => {}
    -1 => return Err(()),
    _ => panic!(),
  }
  Ok(())
}

pub fn sign_buflen() -> usize {
  crypto_sign_BYTES as usize
}

pub fn sign_public_key_buflen() -> usize {
  crypto_sign_PUBLICKEYBYTES as usize
}

pub fn sign_secret_key_buflen() -> usize {
  crypto_sign_SECRETKEYBYTES as usize
}

pub fn gen_sign_keypair() -> Result<KeyPair, ()> {
  let mut public_key_buf = CryptoBuf::zero_bytes(sign_public_key_buflen());
  let mut secret_key_buf = CryptoBuf::zero_bytes(sign_secret_key_buflen());
  let ret = {
    let p = public_key_buf.as_mut();
    let s = secret_key_buf.as_mut();
    unsafe { crypto_sign_keypair(
      p.as_mut_ptr(),
      s.as_mut_ptr(),
    ) }
  };
  match ret {
    0 => {}
    -1 => return Err(()),
    _ => panic!(),
  }
  Ok(KeyPair{
    public: public_key_buf,
    secret: secret_key_buf,
  })
}

pub fn sign(sig_buf: &mut [u8], msg_buf: &[u8], secret_key_buf: &[u8]) -> Result<(), ()> {
  assert_eq!(sig_buf.len(), sign_buflen());
  assert_eq!(secret_key_buf.len(), sign_secret_key_buflen());
  let mut sig_buflen_ret: u64 = 0;
  let ret = unsafe { crypto_sign_detached(
      sig_buf.as_mut_ptr(), &mut sig_buflen_ret as *mut u64,
      msg_buf.as_ptr(), msg_buf.len() as u64,
      secret_key_buf.as_ptr(),
  ) };
  assert_eq!(sig_buflen_ret, sig_buf.len() as u64);
  match ret {
    0 => {}
    -1 => return Err(()),
    _ => panic!(),
  }
  Ok(())
}

pub fn sign_verify(sig_buf: &[u8], msg_buf: &[u8], public_key_buf: &[u8]) -> Result<(), ()> {
  assert_eq!(sig_buf.len(), sign_buflen());
  assert_eq!(public_key_buf.len(), sign_public_key_buflen());
  let ret = unsafe { crypto_sign_verify_detached(
      sig_buf.as_ptr(),
      msg_buf.as_ptr(), msg_buf.len() as u64,
      public_key_buf.as_ptr(),
  ) };
  match ret {
    0 => {}
    -1 => return Err(()),
    _ => panic!(),
  }
  Ok(())
}

pub fn generic_hash_buflen() -> usize {
  crypto_generichash_BYTES as usize
}

pub fn generic_hash_key_buflen() -> usize {
  crypto_generichash_KEYBYTES as usize
}

pub fn generic_hash(hash_buf: &mut [u8], msg_buf: &[u8], key_buf: &[u8]) -> Result<(), ()> {
  assert_eq!(hash_buf.len(), generic_hash_buflen());
  assert_eq!(key_buf.len(), generic_hash_key_buflen());
  let ret = unsafe { crypto_generichash(
      hash_buf.as_mut_ptr(), hash_buf.len(),
      msg_buf.as_ptr(), msg_buf.len() as u64,
      key_buf.as_ptr(), key_buf.len(),
  ) };
  match ret {
    0 => {}
    -1 => return Err(()),
    _ => panic!(),
  }
  Ok(())
}

pub fn pwhash_buflen() -> usize {
  crypto_pwhash_BYTES_MIN as usize
}

pub fn pwhash_salt_buflen() -> usize {
  crypto_pwhash_SALTBYTES as usize
}

pub fn pwhash_str_buflen() -> usize {
  crypto_pwhash_STRBYTES as usize
}

pub fn pwhash_str_prefix() -> &'static [u8] {
  crypto_pwhash_STRPREFIX
}

pub fn pwhash_str(str_buf: &mut [u8], passwd: &CStr, ops_limit: u64, mem_limit: usize) -> Result<(), ()> {
  assert_eq!(str_buf.len(), pwhash_str_buflen());
  let ret = unsafe { crypto_pwhash_str(
      str_buf.as_mut_ptr() as *mut c_char,
      passwd.as_ptr(), passwd.to_bytes().len() as u64,
      ops_limit,
      mem_limit,
  ) };
  match ret {
    0 => {}
    -1 => return Err(()),
    _ => panic!(),
  }
  Ok(())
}

pub fn pwhash_str_verify(str_buf: &[u8], passwd: &CStr) -> Result<(), ()> {
  assert_eq!(str_buf.len(), pwhash_str_buflen());
  let ret = unsafe { crypto_pwhash_str_verify(
      str_buf.as_ptr() as *const c_char,
      passwd.as_ptr(), passwd.to_bytes().len() as u64,
  ) };
  match ret {
    0 => {}
    -1 => return Err(()),
    _ => panic!(),
  }
  Ok(())
}
