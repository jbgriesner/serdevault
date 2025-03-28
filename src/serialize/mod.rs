pub mod impls;

use crate::SerdeVaultError;
use serde::{Deserialize, Serialize};

/// Serialization abstract with type to serialize.
///
/// Serializer implementations must implement this trait.
pub trait SerializerType {
    /// Type to serialize
    type S;

    fn new(serialized: Vec<u8>) -> Self
    where
        Self: Sized;

    /// Ref to serialized.
    fn as_slice(&self) -> &[u8];

    /// Into serialized.
    fn into_vec(self) -> Vec<u8>;

    /// # Failures
    ///
    /// - SerdeVaultError when failed to serialize message.
    fn serialize(v: &Self::S) -> Result<Self, SerdeVaultError>
    where
        Self: Sized,
        Self::S: Serialize;

    /// # Failures
    ///
    /// - SerdeVaultError when failed to deserialize decrypted message.
    fn deserialize<'de>(&'de self) -> Result<Self::S, SerdeVaultError>
    where
        Self::S: Deserialize<'de>;
}
