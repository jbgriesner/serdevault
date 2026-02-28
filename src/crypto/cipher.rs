use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::kdf::KEY_SIZE;
use crate::error::SerdeVaultError;

/// Nonce size in bytes. 12 bytes is the standard for AES-GCM (96-bit nonce).
pub const NONCE_SIZE: usize = 12;

/// Encrypt `plaintext` with AES-256-GCM using the provided key.
pub fn encrypt(
    plaintext: &[u8],
    key: &Zeroizing<[u8; KEY_SIZE]>,
) -> Result<(Vec<u8>, [u8; NONCE_SIZE]), SerdeVaultError> {
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher_key = Key::<Aes256Gcm>::from_slice(key.as_ref());
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| SerdeVaultError::EncryptionError(e.to_string()))?;

    Ok((ciphertext, nonce_bytes))
}

/// Decrypt `ciphertext` with AES-256-GCM.
pub fn decrypt(
    ciphertext: &[u8],
    key: &Zeroizing<[u8; KEY_SIZE]>,
    nonce_bytes: &[u8; NONCE_SIZE],
) -> Result<Zeroizing<Vec<u8>>, SerdeVaultError> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(key.as_ref());
    let cipher = Aes256Gcm::new(cipher_key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| SerdeVaultError::DecryptionFailed)?;

    Ok(Zeroizing::new(plaintext))
}
