use serde::{Deserialize, Serialize};

use crate::cryptography::encryption::{EncryptionError, encrypt::encrypt_using_symmetric_key};
use crate::cryptography::serializers::base64_serializer::base64_serializer;
use crate::cryptography::vault::vault::UserVaultError;

/// Encrypted field with its corresponding nonce.
#[derive(uniffi::Object, Serialize, Deserialize, Clone)]
pub struct EncryptedField {
    #[serde(with = "base64_serializer")]
    pub field: Vec<u8>,
    #[serde(with = "base64_serializer")]
    pub nonce: Vec<u8>,
}

#[uniffi::export]
impl EncryptedField {
    #[uniffi::constructor]
    pub fn new(encryption_key: &Vec<u8>, field: &Vec<u8>) -> Result<Self, EncryptionError> {
        let encrypted_field = encrypt_using_symmetric_key(encryption_key, field)?;

        Ok(EncryptedField {
            field: encrypted_field.cipher_text,
            nonce: encrypted_field.nonce,
        })
    }

    pub fn to_json(&self) -> Result<String, UserVaultError> {
        serde_json::to_string(&self).map_err(|_| UserVaultError::SerializationFailed)
    }
}
