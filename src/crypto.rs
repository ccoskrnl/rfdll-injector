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
    0xD6, 0x30, 0xAE, 0x93, 0x33, 0xD8, 0xEA, 0xCA, 0xD9, 0x0A, 0xE2, 0xA0,
    0xDC, 0xD5, 0x8C, 0xFD, 0x89, 0x0A, 0xC1, 0x34, 0x06, 0x98, 0x1F, 0xB1,
    0xF0, 0x66, 0x06, 0xB0, 0xDD, 0x9B, 0x2F, 0x0B,
];

const KEY_HALF_2: [u8; 32] = [
    0x93, 0x47, 0x65, 0x3C, 0x68, 0x64, 0xF8, 0x2B, 0xEF, 0xF1, 0x30, 0xDC,
    0xA4, 0x95, 0x86, 0x0F, 0xDE, 0xE8, 0xB0, 0xE3, 0x11, 0xE1, 0x5A, 0xCB,
    0x5A, 0xB1, 0x06, 0xAC, 0x21, 0xC1, 0x95, 0x93,
];

const IV_HALF_1: [u8; 16] = [
    0x2B, 0xCD, 0x27, 0x49, 0x74, 0xC9, 0xDA, 0x6B, 0x87, 0x19, 0x21, 0x34,
    0x1B, 0xA1, 0xB0, 0x1E,
];

const IV_HALF_2: [u8; 16] = [
    0x06, 0x74, 0xC8, 0xC0, 0x75, 0x4B, 0xF8, 0x92, 0x00, 0x3B, 0x69, 0x4D,
    0x6E, 0x1D, 0xE6, 0x93,
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

    // The in-place decryptor needs room for the padding check.
    // We allocate a buffer one block larger than the ciphertext.
    let mut buf = Vec::with_capacity(ciphertext.len() + 16);
    buf.extend_from_slice(ciphertext);
    buf.resize(ciphertext.len() + 16, 0);

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
