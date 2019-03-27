use crate::ffi::sodium::{
  sodium_base64_VARIANT_ORIGINAL,
  sodium_base64_VARIANT_ORIGINAL_NO_PADDING,
  sodium_base64_VARIANT_URLSAFE,
  sodium_base64_VARIANT_URLSAFE_NO_PADDING,
};

use std::os::raw::{c_int};

pub const STANDARD: Base64Config = Base64Config::Standard;
pub const STANDARD_NO_PAD: Base64Config = Base64Config::StandardNoPad;
pub const URL_SAFE: Base64Config = Base64Config::UrlSafe;
pub const URL_SAFE_NO_PAD: Base64Config = Base64Config::UrlSafeNoPad;

#[derive(Clone, Copy, Debug)]
pub enum Base64Config {
  Standard,
  StandardNoPad,
  UrlSafe,
  UrlSafeNoPad,
}

impl Base64Config {
  pub fn to_raw_variant(&self) -> c_int {
    let v: u32 = match self {
      &Base64Config::Standard => sodium_base64_VARIANT_ORIGINAL,
      &Base64Config::StandardNoPad => sodium_base64_VARIANT_ORIGINAL_NO_PADDING,
      &Base64Config::UrlSafe => sodium_base64_VARIANT_URLSAFE,
      &Base64Config::UrlSafeNoPad => sodium_base64_VARIANT_URLSAFE_NO_PADDING,
    };
    v as c_int
  }
}
