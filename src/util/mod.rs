use crate::{
  random_buf, zero_buf,
  eq_bufs, partial_cmp_bufs, is_zero_buf,
  hex_decode_slice,
  hex_encode_slice_c,
  base64_decode_config_slice,
  base64_encode_config_slice_c,
};
use crate::ffi::sodium::{sodium_base64_encoded_len};
use crate::util::base64::{Base64Config};

use std::cmp::{Ordering};
use std::ops::{Deref, DerefMut};
use std::ffi::{CStr};

pub mod base64;

#[derive(Clone)]
pub struct KeyPair {
  pub public: CryptoBuf,
  pub secret: CryptoBuf,
}

pub struct CryptoSlice<'a> {
  buf: &'a [u8],
}

impl<'a> CryptoSlice<'a> {
  pub fn from_bytes(buf: &'a [u8]) -> CryptoSlice<'a> {
    CryptoSlice{buf}
  }

  pub fn is_zero(&self) -> bool {
    is_zero_buf(&self.buf)
  }

  pub fn encode_hex(&self) -> String {
    let max_enc_len = self.buf.len() * 2 + 1;
    let mut enc_buf = vec![0; max_enc_len];
    hex_encode_slice_c(&self.buf, &mut enc_buf);
    let c_str = unsafe { CStr::from_ptr(enc_buf.as_ptr() as *const i8) };
    match c_str.to_str() {
      Err(_) => unreachable!(),
      Ok(s) => {
        assert!(s.len() < max_enc_len);
        s.to_owned()
      }
    }
  }

  pub fn base64_encode_config(&self, config: Base64Config) -> String {
    self.encode_base64_config(config)
  }

  pub fn encode_base64_config(&self, config: Base64Config) -> String {
    let max_enc_len = unsafe { sodium_base64_encoded_len(self.buf.len(), config.to_raw_variant()) };
    let mut enc_buf = vec![0; max_enc_len];
    base64_encode_config_slice_c(&self.buf, config, &mut enc_buf);
    let c_str = unsafe { CStr::from_ptr(enc_buf.as_ptr() as *const i8) };
    match c_str.to_str() {
      Err(_) => unreachable!(),
      Ok(s) => {
        assert!(s.len() < max_enc_len);
        s.to_owned()
      }
    }
  }
}

impl<'a> Deref for CryptoSlice<'a> {
  type Target = [u8];

  fn deref(&self) -> &[u8] {
    &self.buf
  }
}

impl<'a> PartialEq for CryptoSlice<'a> {
  fn eq(&self, other: &CryptoSlice<'a>) -> bool {
    eq_bufs(&*self, &*other)
  }
}

impl<'a> Eq for CryptoSlice<'a> {
}

impl<'a> PartialOrd for CryptoSlice<'a> {
  fn partial_cmp(&self, other: &CryptoSlice<'a>) -> Option<Ordering> {
    partial_cmp_bufs(&*self, &*other)
  }
}

pub struct CryptoSliceMut<'a> {
  buf: &'a mut [u8],
}

impl<'a> Deref for CryptoSliceMut<'a> {
  type Target = [u8];

  fn deref(&self) -> &[u8] {
    &self.buf
  }
}

impl<'a> DerefMut for CryptoSliceMut<'a> {
  fn deref_mut(&mut self) -> &mut [u8] {
    &mut self.buf
  }
}

#[derive(Clone)]
pub struct CryptoBuf {
  buf: Vec<u8>,
}

impl Drop for CryptoBuf {
  fn drop(&mut self) {
    zero_buf(&mut self.buf);
  }
}

impl CryptoBuf {
  pub fn from_vec(expected_len: usize, buf: Vec<u8>) -> CryptoBuf {
    assert_eq!(expected_len, buf.len());
    CryptoBuf{buf}
  }

  pub fn decode_hex<T: ?Sized + AsRef<[u8]>>(input: &T) -> Result<CryptoBuf, ()> {
    let hex_len = input.as_ref().len();
    let max_bin_len = (hex_len + 1) / 2;
    let mut buf = vec![0; max_bin_len];
    hex_decode_slice(input, &mut buf)
      .map(|bin_len| {
        assert!(bin_len <= max_bin_len);
        buf.resize(bin_len, 0);
        CryptoBuf{buf}
      })
  }

  pub fn base64_decode_config<T: ?Sized + AsRef<[u8]>>(input: &T, config: Base64Config) -> Result<CryptoBuf, ()> {
    CryptoBuf::decode_base64_config(input, config)
  }

  pub fn decode_base64_config<T: ?Sized + AsRef<[u8]>>(input: &T, config: Base64Config) -> Result<CryptoBuf, ()> {
    let b64_len = input.as_ref().len();
    let max_bin_len = (b64_len + 3) / 4 * 3;
    let mut buf = vec![0; max_bin_len];
    base64_decode_config_slice(input, config, &mut buf)
      .map(|bin_len| {
        assert!(bin_len <= max_bin_len);
        buf.resize(bin_len, 0);
        CryptoBuf{buf}
      })
  }

  pub fn zero_bytes(len: usize) -> CryptoBuf {
    let mut buf: Vec<u8> = vec![0; len];
    zero_buf(&mut buf);
    CryptoBuf{buf}
  }

  pub fn random_bytes(len: usize) -> CryptoBuf {
    let mut buf: Vec<u8> = vec![0; len];
    random_buf(&mut buf);
    CryptoBuf{buf}
  }

  pub fn borrow(&self) -> CryptoSlice {
    CryptoSlice{buf: &self.buf}
  }

  pub fn borrow_mut(&mut self) -> CryptoSliceMut {
    CryptoSliceMut{buf: &mut self.buf}
  }

  pub fn as_vec(&self) -> &Vec<u8> {
    &self.buf
  }

  pub fn to_vec(&self) -> Vec<u8> {
    self.buf.clone()
  }

  pub fn to_hashbuf(&self) -> HashCryptoBuf {
    HashCryptoBuf{buf: self.buf.clone()}
  }
}

/*impl AsRef<[u8]> for CryptoBuf {
  fn as_ref(&self) -> &[u8] {
    &self.buf
  }
}

impl AsMut<[u8]> for CryptoBuf {
  fn as_mut(&mut self) -> &mut [u8] {
    &mut self.buf
  }
}*/

impl PartialEq for CryptoBuf {
  fn eq(&self, other: &CryptoBuf) -> bool {
    eq_bufs(&*self.borrow(), &*other.borrow())
  }
}

impl Eq for CryptoBuf {
}

impl PartialOrd for CryptoBuf {
  fn partial_cmp(&self, other: &CryptoBuf) -> Option<Ordering> {
    partial_cmp_bufs(&*self.borrow(), &*other.borrow())
  }
}

#[derive(Clone, Hash)]
pub struct HashCryptoBuf {
  buf: Vec<u8>,
}

impl Drop for HashCryptoBuf {
  fn drop(&mut self) {
    zero_buf(&mut self.buf);
  }
}

impl HashCryptoBuf {
  pub fn from_vec(expected_len: usize, buf: Vec<u8>) -> HashCryptoBuf {
    assert_eq!(expected_len, buf.len());
    HashCryptoBuf{buf}
  }

  pub fn borrow(&self) -> CryptoSlice {
    CryptoSlice{buf: &self.buf}
  }

  pub fn borrow_mut(&mut self) -> CryptoSliceMut {
    CryptoSliceMut{buf: &mut self.buf}
  }

  pub fn as_vec(&self) -> &Vec<u8> {
    &self.buf
  }

  pub fn to_vec(&self) -> Vec<u8> {
    self.buf.clone()
  }

  pub fn to_buf(&self) -> CryptoBuf {
    CryptoBuf{buf: self.buf.clone()}
  }
}

/*impl AsRef<[u8]> for HashCryptoBuf {
  fn as_ref(&self) -> &[u8] {
    &self.buf
  }
}

impl AsMut<[u8]> for HashCryptoBuf {
  fn as_mut(&mut self) -> &mut [u8] {
    &mut self.buf
  }
}*/

impl PartialEq for HashCryptoBuf {
  fn eq(&self, other: &HashCryptoBuf) -> bool {
    eq_bufs(&*self.borrow(), &*other.borrow())
  }
}

impl Eq for HashCryptoBuf {
}

impl PartialOrd for HashCryptoBuf {
  fn partial_cmp(&self, other: &HashCryptoBuf) -> Option<Ordering> {
    partial_cmp_bufs(&*self.borrow(), &*other.borrow())
  }
}
