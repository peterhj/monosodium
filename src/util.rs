use crate::{eq_bufs, random_buf, zero_buf};

pub struct KeyPair {
  pub public: CryptoBuf,
  pub secret: CryptoBuf,
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

  pub fn into_vec_copy(self) -> Vec<u8> {
    self.buf.clone()
  }

  pub fn into_hashbuf_copy(self) -> HashCryptoBuf {
    HashCryptoBuf{buf: self.buf.clone()}
  }
}

impl AsRef<[u8]> for CryptoBuf {
  fn as_ref(&self) -> &[u8] {
    &self.buf
  }
}

impl AsMut<[u8]> for CryptoBuf {
  fn as_mut(&mut self) -> &mut [u8] {
    &mut self.buf
  }
}

impl PartialEq for CryptoBuf {
  fn eq(&self, other: &CryptoBuf) -> bool {
    eq_bufs(self.as_ref(), other.as_ref())
  }
}

impl Eq for CryptoBuf {
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
  pub fn into_vec_copy(self) -> Vec<u8> {
    self.buf.clone()
  }
}

impl AsRef<[u8]> for HashCryptoBuf {
  fn as_ref(&self) -> &[u8] {
    &self.buf
  }
}

impl AsMut<[u8]> for HashCryptoBuf {
  fn as_mut(&mut self) -> &mut [u8] {
    &mut self.buf
  }
}

impl PartialEq for HashCryptoBuf {
  fn eq(&self, other: &HashCryptoBuf) -> bool {
    eq_bufs(self.as_ref(), other.as_ref())
  }
}

impl Eq for HashCryptoBuf {
}
