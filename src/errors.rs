use std::error::Error as StdError;
use std::fmt;
use std::fmt::Debug;
use std::io;

/// Custom error type for safe_serde operations
#[derive(Debug)]
pub enum SerdeVaultError {
    IoError(io::Error),
    SerializationError(String),
    DeserializationError(String),
    EncryptionError(String),
    DecryptionError(String),
    PasswordError(String),
    RandomError(String), // Added for OsRng errors
}

// From implementations for error conversions
impl From<io::Error> for SerdeVaultError {
    fn from(error: io::Error) -> Self {
        SerdeVaultError::IoError(error)
    }
}

// Implement Display trait for SerdeVaultError
impl fmt::Display for SerdeVaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SerdeVaultError::IoError(e) => write!(f, "I/O error: {}", e),
            SerdeVaultError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            SerdeVaultError::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
            SerdeVaultError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            SerdeVaultError::DecryptionError(e) => write!(f, "Decryption error: {}", e),
            SerdeVaultError::PasswordError(e) => write!(f, "Password error: {}", e),
            SerdeVaultError::RandomError(_) => todo!(),
        }
    }
}

// Implement Error trait for SerdeVaultError
impl StdError for SerdeVaultError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            SerdeVaultError::IoError(e) => Some(e),
            _ => None,
        }
    }
}
