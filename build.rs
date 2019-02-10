use std::env;
use std::fs;
use std::path::{PathBuf};
use std::process::{Command, Stdio};

#[cfg(feature = "fresh")]
fn gen_bindings(manifest_dir: &PathBuf, build_dir: &PathBuf) {
  let gensrc_dir = manifest_dir.join("gensrc");
  fs::create_dir_all(&gensrc_dir).ok();
  fs::remove_file(gensrc_dir.join("_sodium.rs")).ok();
  bindgen::Builder::default()
    .clang_arg(format!("-I{}", build_dir.join("src/libsodium/include").display()))
    .header("wrapped_sodium.h")
    .whitelist_recursively(false)
    .whitelist_function("sodium_init")
    .whitelist_function("sodium_memcmp")
    .whitelist_function("sodium_pad")
    .whitelist_function("sodium_unpad")
    .whitelist_function("sodium_memzero")
    .whitelist_function("randombytes_buf")
    .whitelist_var("crypto_aead_xchacha20poly1305_ietf_NPUBBYTES")
    .whitelist_var("crypto_aead_xchacha20poly1305_ietf_KEYBYTES")
    .whitelist_var("crypto_aead_xchacha20poly1305_ietf_ABYTES")
    .whitelist_function("crypto_aead_xchacha20poly1305_ietf_encrypt")
    .whitelist_function("crypto_aead_xchacha20poly1305_ietf_decrypt")
    .whitelist_function("crypto_aead_xchacha20poly1305_ietf_keygen")
    .whitelist_var("crypto_auth_hmacsha512256_KEYBYTES")
    .whitelist_var("crypto_auth_hmacsha512256_BYTES")
    .whitelist_type("crypto_hash_sha512_state")
    .whitelist_type("crypto_auth_hmacsha512_state")
    .whitelist_type("crypto_auth_hmacsha512256_state")
    .whitelist_function("crypto_auth_hmacsha512256")
    .whitelist_function("crypto_auth_hmacsha512256_verify")
    .whitelist_function("crypto_auth_hmacsha512256_init")
    .whitelist_function("crypto_auth_hmacsha512256_update")
    .whitelist_function("crypto_auth_hmacsha512256_final")
    .whitelist_function("crypto_auth_hmacsha512256_keygen")
    .whitelist_var("crypto_sign_PUBLICKEYBYTES")
    .whitelist_var("crypto_sign_SECRETKEYBYTES")
    .whitelist_var("crypto_sign_BYTES")
    .whitelist_function("crypto_sign_keypair")
    .whitelist_function("crypto_sign_detached")
    .whitelist_function("crypto_sign_verify_detached")
    .whitelist_var("crypto_generichash_KEYBYTES")
    .whitelist_var("crypto_generichash_BYTES")
    .whitelist_type("crypto_generichash_blake2b_state")
    .whitelist_type("crypto_generichash_state")
    .whitelist_function("crypto_generichash")
    .whitelist_function("crypto_generichash_init")
    .whitelist_function("crypto_generichash_update")
    .whitelist_function("crypto_generichash_final")
    .whitelist_function("crypto_generichash_keygen")
    .whitelist_function("crypto_generichash_statebytes")
    .generate_comments(false)
    .rustfmt_bindings(true)
    .generate()
    .expect("bindgen failed to generate sodium bindings")
    .write_to_file(gensrc_dir.join("_sodium.rs"))
    .expect("bindgen failed to write sodium bindings");
}

fn main() {
  let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
  let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

  let build_dir = out_dir.join("libsodium-1.0.17");

  println!("cargo:rerun-if-changed=build.rs");
  println!("cargo:rerun-if-changed=libsodium-1.0.17.tar.gz");

  eprintln!("TRACE: clean dirs");
  fs::remove_dir_all(&build_dir).ok();

  eprintln!("TRACE: extract tar");
  let mut proc = Command::new("tar")
    .current_dir(&out_dir)
    .arg("-xzkf")
    .arg(format!("{}", manifest_dir.join("libsodium-1.0.17.tar.gz").display()))
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn().unwrap();
  assert!(proc.wait().is_ok());

  eprintln!("TRACE: run configure script");
  let mut proc = Command::new(build_dir.join("configure"))
    .current_dir(&build_dir)
    .arg("--disable-silent-rules")
    .arg("--enable-minimal")
    .arg("--enable-retpoline")
    .arg("--with-pic")
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn().unwrap();
  assert!(proc.wait().is_ok());

  eprintln!("TRACE: run make");
  let mut proc = Command::new("make")
    .current_dir(&build_dir)
    .arg("-j8")
    .stdout(Stdio::null())
    .stderr(Stdio::null())
    .spawn().unwrap();
  assert!(proc.wait().is_ok());

  eprintln!("TRACE: copy lib");
  let build_lib_path = build_dir.join("src/libsodium/.libs/libsodium.a");
  let target_lib_path = out_dir.join("libminisodium-native.a");
  assert!(fs::copy(&build_lib_path, &target_lib_path).is_ok());
  println!("cargo:rustc-link-search=native={}", out_dir.display());
  println!("cargo:rustc-link-lib=static=minisodium-native");

  eprintln!("TRACE: run bindgen, maybe");
  #[cfg(feature = "fresh")]
  gen_bindings(&manifest_dir, &build_dir);
}
