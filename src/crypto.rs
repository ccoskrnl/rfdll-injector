//! AES-256-CBC encrypt / decrypt with stack-constructed key/IV.
//!
//! The key and IV are stored as two XOR halves so they never appear
//! contiguously in the binary.  They are reconstructed on the stack
//! at runtime using the `reconstruct_*` helpers.
//!
//! Only two public functions:
//!   - `decrypt(ciphertext) → plaintext`   (server → local)
//!   - `encrypt(plaintext)  → ciphertext`  (local  → server)
//!
//! The plaintext is bit-for-bit identical to what was originally encrypted
//! — no trailing padding or extra bytes leak through.

use aes::Aes256;
use cbc::{Decryptor, Encryptor};
use cipher::{
    KeyIvInit,
    BlockModeDecrypt,
    BlockModeEncrypt,
    block_padding::Pkcs7,
    Array,
};
use anyhow::Result;
const KEY_HALF_1: [u8; 32] = [
    0x5D, 0x84, 0xDB, 0xAC, 0xBA, 0x28, 0xD7, 0x74, 0xF4, 0x55, 0x14, 0x43,
    0x24, 0x63, 0x2D, 0x67, 0xB5, 0x4D, 0x1F, 0x5A, 0xCB, 0x52, 0x01, 0xBD,
    0xD7, 0xC2, 0x08, 0xCB, 0x23, 0xC4, 0xEE, 0xE7,
];

const KEY_HALF_2: [u8; 32] = [
    0x7C, 0x9C, 0x05, 0x28, 0x6F, 0x89, 0x33, 0x09, 0xE2, 0xC2, 0x9B, 0x0A,
    0x9E, 0x95, 0x0C, 0xAA, 0xE2, 0x3C, 0xE1, 0x5F, 0x86, 0xC2, 0xBE, 0x4E,
    0x3D, 0x45, 0xC1, 0x9A, 0xF3, 0xB4, 0x46, 0x98,
];

const IV_HALF_1: [u8; 16] = [
    0xC6, 0x79, 0x28, 0x21, 0xAF, 0x05, 0x52, 0xF1, 0x2E, 0x03, 0x04, 0x7F,
    0xB1, 0xD5, 0x0F, 0x5F,
];

const IV_HALF_2: [u8; 16] = [
    0x6F, 0xEF, 0x6D, 0x59, 0xFB, 0xFF, 0x11, 0x59, 0xE4, 0xE1, 0x37, 0xE3,
    0xAE, 0xED, 0x03, 0x9E,
];
// ────────────────────────────────────────────────────────────────────────────

/// Convenience type aliases.
type Aes256CbcDec = Decryptor<Aes256>;
type Aes256CbcEnc = Encryptor<Aes256>;

// ── helpers (re-usable) ────────────────────────────────────────────────────

fn load_key_iv() -> ([u8; 32], [u8; 16]) {
    let mut key = [0u8; 32];
    let mut iv  = [0u8; 16];
    reconstruct_key(&mut key, &KEY_HALF_1, &KEY_HALF_2);
    reconstruct_iv (&mut iv,  &IV_HALF_1,  &IV_HALF_2);
    (key, iv)
}

// ── public API ─────────────────────────────────────────────────────────────

/// Decrypt a server-supplied ciphertext and return the **exact** original
/// plaintext (PKCS7 padding is stripped).  No extra bytes are appended.
pub fn decrypt(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let (key, iv) = load_key_iv();

    let mut buf = ciphertext.to_vec();

    #[allow(deprecated)]
    let key_arr = Array::from_slice(&key);
    #[allow(deprecated)]
    let iv_arr  = Array::from_slice(&iv);

    let plain = Aes256CbcDec::new(key_arr, iv_arr)
        .decrypt_padded::<Pkcs7>(&mut buf)
        .map_err(|e| anyhow::anyhow!("decrypt failed: {:?}", e))?;

    Ok(plain.to_vec())
}

/// Encrypt a plaintext so it can be sent to the server.
/// Returns AES-256-CBC ciphertext (PKCS7 padded).
pub fn encrypt(plaintext: &[u8]) -> Result<Vec<u8>> {
    let (key, iv) = load_key_iv();

    // Allocate buffer: plaintext + one extra block for PKCS7 padding
    let block_size = 16usize;
    let padded_len = plaintext.len() + (block_size - (plaintext.len() % block_size));
    let mut buf = Vec::with_capacity(padded_len);
    buf.resize(padded_len, 0);

    #[allow(deprecated)]
    let key_arr = Array::from_slice(&key);
    #[allow(deprecated)]
    let iv_arr  = Array::from_slice(&iv);

    let ciphertext = Aes256CbcEnc::new(key_arr, iv_arr)
        .encrypt_padded::<Pkcs7>(&mut buf, plaintext.len())
        .map_err(|e| anyhow::anyhow!("encrypt failed: {:?}", e))?;

    Ok(ciphertext.to_vec())
}

// ── stack-key reconstruction (inlinable) ───────────────────────────────────

#[inline(always)]
pub fn reconstruct_key(out: &mut [u8; 32], half_1: &[u8; 32], half_2: &[u8; 32]) {
    for i in 0..32 { out[i] = half_1[i] ^ half_2[i]; }
}

#[inline(always)]
pub fn reconstruct_iv(out: &mut [u8; 16], half_1: &[u8; 16], half_2: &[u8; 16]) {
    for i in 0..16 { out[i] = half_1[i] ^ half_2[i]; }
}
