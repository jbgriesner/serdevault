use crate::errors::SerdeVaultError;
use crate::serialize::SerializerType;
use core::marker::PhantomData;
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct JsonSerialized<T> {
    serialized: Vec<u8>,
    _type: PhantomData<T>,
}

impl<T> SerializerType for JsonSerialized<T> {
    type S = T;

    fn new(serialized: Vec<u8>) -> Self
    where
        Self: Sized,
    {
        Self {
            serialized,
            _type: PhantomData::default(),
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.serialized
    }

    fn into_vec(self) -> Vec<u8> {
        self.serialized
    }

    fn serialize(data: &Self::S) -> Result<Self, SerdeVaultError>
    where
        Self: Sized,
        Self::S: Serialize,
    {
        let serialized = serde_json::to_vec(data)
            .map_err(|e| SerdeVaultError::SerializationError(e.to_string()))?;
        Ok(Self::new(serialized))
    }

    fn deserialize<'de>(&'de self) -> Result<Self::S, SerdeVaultError>
    where
        Self::S: Deserialize<'de>,
    {
        serde_json::from_slice(self.as_slice())
            .map_err(|e| SerdeVaultError::DeserializationError(e.to_string()))
    }
}
