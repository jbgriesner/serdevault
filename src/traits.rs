use crate::encrypter::{content::Content, encrypted_content::EncryptedContent};
use crate::serialize::SerializerType;
use crate::SerdeVaultError;
use serde::{Deserialize, Serialize};
use std::env;
use std::path::PathBuf;

/// Main trait that provides safe serialization/deserialization methods
pub trait SafeSerde: Serialize + for<'de> Deserialize<'de> + Sized {
    type S: SerializerType<S = Self>;
    const VAULT_PATH: &'static str;

    /// Save the struct to the encrypted file
    fn save(&self, pwd: &str) -> Result<(), SerdeVaultError> {
        let serialized = Self::S::serialize(&self)?;
        let content = Content::new(serialized.into_vec());
        let encrypted_content = content.encrypt(pwd)?;
        encrypted_content.to_vault(expand_tilde(Self::VAULT_PATH))?;
        Ok(())
    }

    /// Load the struct from the encrypted file
    fn load(pwd: &str) -> Result<Self, SerdeVaultError> {
        let encrypted_content = EncryptedContent::from_vault(expand_tilde(Self::VAULT_PATH))?;
        let content = Content::from_encrypted(encrypted_content, pwd)?;

        let serializer = Self::S::new(content.into_vec());
        serializer.deserialize()

        // serde_json::from_slice()
        //     .map_err(|e| SerdeVaultError::DeserializationError(e.to_string()))
    }
}

pub fn expand_tilde(path: &str) -> PathBuf {
    if path.starts_with("~/") {
        let home = env::var("HOME").map(PathBuf::from).unwrap_or_default();
        home.join(&path[2..])
    } else {
        PathBuf::from(path)
    }
}
