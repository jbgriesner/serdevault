use thiserror::Error;

#[derive(Debug, Error)]
pub enum SerdeVaultError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Deserialization error: {0}")]
    DeserializationError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    /// Triggered when AES-GCM authentication fails — wrong password or corrupted file.
    /// Intentionally vague to avoid leaking information.
    #[error("Decryption failed — wrong password or corrupted vault")]
    DecryptionFailed,

    #[error("Key derivation error: {0}")]
    KdfError(String),

    #[error("Invalid vault format: {0}")]
    InvalidFormat(String),

    #[error("Unsupported vault version: {0}")]
    UnsupportedVersion(u8),
}
