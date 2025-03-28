use crate::consts::{NONCE_SIZE, SALT_SIZE};
use crate::errors::SerdeVaultError;
use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct EncryptedContent {
    pub encrypted: Vec<u8>,
    pub salt: [u8; SALT_SIZE],
    pub nonce: [u8; NONCE_SIZE],
}

impl EncryptedContent {
    pub fn new(encrypted: Vec<u8>, salt: [u8; SALT_SIZE], nonce: [u8; NONCE_SIZE]) -> Self {
        Self {
            encrypted,
            salt,
            nonce,
        }
    }

    pub fn to_vault(&self, path: impl AsRef<Path>) -> Result<(), SerdeVaultError> {
        let mut file = File::create(path).map_err(|e| SerdeVaultError::IoError(e))?;

        file.write_all(&self.salt)
            .map_err(|e| SerdeVaultError::IoError(e))?;
        file.write_all(&self.nonce)
            .map_err(|e| SerdeVaultError::IoError(e))?;
        file.write_all(&self.encrypted)
            .map_err(|e| SerdeVaultError::IoError(e))?;
        Ok(())
    }

    pub fn from_vault(path: impl AsRef<Path>) -> Result<Self, SerdeVaultError> {
        let mut file = File::open(path).map_err(|e| SerdeVaultError::IoError(e))?;

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .map_err(|e| SerdeVaultError::IoError(e))?;

        if buffer.len() < SALT_SIZE + NONCE_SIZE {
            return Err(SerdeVaultError::DecryptionError(
                "Vault too small".to_string(),
            ));
        }

        let salt_slice = &buffer[0..SALT_SIZE];
        let nonce_slice = &buffer[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
        let encrypted = (&buffer[SALT_SIZE + NONCE_SIZE..]).to_vec();

        if salt_slice.len() != SALT_SIZE {
            return Err(SerdeVaultError::DecryptionError(
                "salt slice length doesn't match array length".to_string(),
            ));
        }

        if nonce_slice.len() != NONCE_SIZE {
            return Err(SerdeVaultError::DecryptionError(
                "nonce slice length doesn't match array length".to_string(),
            ));
        }

        let mut salt = [0u8; SALT_SIZE];
        salt.copy_from_slice(salt_slice);

        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(nonce_slice);

        Ok(Self {
            encrypted,
            salt,
            nonce,
        })
    }
}
