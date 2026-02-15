//! Share encryption at rest using Argon2id + ChaCha20-Poly1305.
//!
//! Encrypted format (binary):
//!   [4 bytes]  magic: b"SAW1"
//!   [1 byte]   version: 0x01
//!   [32 bytes] salt (random, for Argon2id)
//!   [12 bytes] nonce (random, for ChaCha20-Poly1305)
//!   [N bytes]  ciphertext + 16-byte Poly1305 tag
//!
//! Total overhead: 4 + 1 + 32 + 12 + 16 = 65 bytes
//!
//! Plaintext detection: if the first 4 bytes are NOT b"SAW1", assume
//! the file is unencrypted JSON (backward compatibility).

use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand_core::{OsRng, RngCore};

use crate::error::MpcError;

const MAGIC: &[u8; 4] = b"SAW1";
const VERSION: u8 = 0x01;
const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN; // 49

/// Returns true if the data appears to be encrypted (starts with SAW1 magic).
pub fn is_encrypted(data: &[u8]) -> bool {
    data.len() >= 4 && &data[..4] == MAGIC
}

/// Encrypt plaintext key share bytes with a passphrase.
pub fn encrypt(plaintext: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, MpcError> {
    if passphrase.is_empty() {
        return Err(MpcError::Encryption("empty passphrase".into()));
    }

    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| MpcError::Encryption(format!("cipher init: {e}")))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| MpcError::Encryption(format!("encrypt: {e}")))?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);

    Ok(out)
}

/// Decrypt an encrypted key share. Returns the plaintext bytes.
///
/// If the data is not encrypted (no SAW1 magic), returns it as-is
/// for backward compatibility with unencrypted key shares.
pub fn decrypt(data: &[u8], passphrase: &[u8]) -> Result<Vec<u8>, MpcError> {
    if !is_encrypted(data) {
        // Unencrypted — pass through
        return Ok(data.to_vec());
    }

    if data.len() < HEADER_LEN + 16 {
        // minimum: header + 16-byte auth tag (empty plaintext)
        return Err(MpcError::Encryption("encrypted data too short".into()));
    }

    let version = data[4];
    if version != VERSION {
        return Err(MpcError::Encryption(format!(
            "unsupported encryption version: {version}"
        )));
    }

    let salt = &data[5..5 + SALT_LEN];
    let nonce_bytes = &data[5 + SALT_LEN..HEADER_LEN];
    let ciphertext = &data[HEADER_LEN..];

    let key = derive_key(passphrase, salt)?;
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| MpcError::Encryption(format!("cipher init: {e}")))?;
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| MpcError::Encryption("decryption failed — wrong passphrase or corrupted data".into()))
}

/// Derive a 256-bit key from passphrase + salt using Argon2id.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; 32], MpcError> {
    let mut key = [0u8; 32];
    // Argon2id with default params (19 MiB memory, 2 iterations, 1 parallelism)
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut key)
        .map_err(|e| MpcError::Encryption(format!("argon2: {e}")))?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let plaintext = b"{\"key\": \"share data here\"}";
        let passphrase = b"test-passphrase-123";

        let encrypted = encrypt(plaintext, passphrase).unwrap();
        assert!(is_encrypted(&encrypted));
        assert!(&encrypted[..4] == MAGIC);

        let decrypted = decrypt(&encrypted, passphrase).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let plaintext = b"secret key share";
        let encrypted = encrypt(plaintext, b"correct").unwrap();
        let result = decrypt(&encrypted, b"wrong");
        assert!(result.is_err());
    }

    #[test]
    fn unencrypted_passthrough() {
        let plaintext = b"{\"some\": \"json\"}";
        let result = decrypt(plaintext, b"anything").unwrap();
        assert_eq!(result, plaintext);
    }

    #[test]
    fn empty_passphrase_rejected() {
        let result = encrypt(b"data", b"");
        assert!(result.is_err());
    }

    #[test]
    fn different_encryptions_differ() {
        let plaintext = b"same data";
        let e1 = encrypt(plaintext, b"pass").unwrap();
        let e2 = encrypt(plaintext, b"pass").unwrap();
        // Different salt + nonce → different ciphertext
        assert_ne!(e1, e2);
        // But both decrypt to the same thing
        assert_eq!(decrypt(&e1, b"pass").unwrap(), plaintext);
        assert_eq!(decrypt(&e2, b"pass").unwrap(), plaintext);
    }
}
