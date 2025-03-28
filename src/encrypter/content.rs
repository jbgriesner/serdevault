use crate::consts::{NONCE_SIZE, SALT_SIZE};
use crate::encrypter::encrypted_content::EncryptedContent;
use crate::SerdeVaultError;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha2::{Digest, Sha256};

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct Content(Vec<u8>);

impl Content {
    pub fn new(msg: Vec<u8>) -> Self
    where
        Self: Sized,
    {
        Self(msg)
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn from_encrypted(data: EncryptedContent, pwd: &str) -> Result<Self, SerdeVaultError> {
        let key = derive_key(pwd, &data.salt[..])?;

        let nonce = Nonce::from_slice(&data.nonce[..]);
        let cipher = Aes256Gcm::new(&key);

        let decrypted = cipher.decrypt(nonce, &data.encrypted[..]).map_err(|_| {
            SerdeVaultError::DecryptionError("Decryption failed - incorrect password?".to_string())
        })?;
        Ok(Content::new(decrypted))
    }

    pub fn encrypt(&self, password: &str) -> Result<EncryptedContent, SerdeVaultError> {
        let mut salt = [0u8; SALT_SIZE];
        OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|e| SerdeVaultError::EncryptionError(e.to_string()))?;
        let key = derive_key(&password, &salt)?;

        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng
            .try_fill_bytes(&mut nonce_bytes)
            .map_err(|e| SerdeVaultError::EncryptionError(e.to_string()))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let cipher = Aes256Gcm::new(&key);
        let encrypted_data = cipher
            .encrypt(nonce, self.0.as_ref())
            .map_err(|e| SerdeVaultError::EncryptionError(e.to_string()))?;
        Ok(EncryptedContent::new(encrypted_data, salt, nonce_bytes))
    }
}

fn derive_key(password: &str, salt: &[u8]) -> Result<Key<Aes256Gcm>, SerdeVaultError> {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(salt);

    let result = hasher.finalize();
    let key = Key::<Aes256Gcm>::from_slice(result.as_slice());

    Ok(*key)
}
