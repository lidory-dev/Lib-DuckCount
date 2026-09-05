use serde::{Deserialize, Serialize};

use crate::cryptography::encryption::{EncryptionError, encrypt::encrypt_using_symmetric_key};
use crate::cryptography::serializers::base64_serializer::base64_serializer;

/// Encrypted field with its corresponding nonce.
#[derive(uniffi::Object, Serialize, Deserialize, Clone)]
pub struct EncryptedField {
    #[serde(with = "base64_serializer")]
    pub ciphertext: Vec<u8>,
    #[serde(with = "base64_serializer")]
    pub nonce: Vec<u8>,
}

/// EncryptedField getters.
#[uniffi::export]
impl EncryptedField {
    fn ciphertext(&self) -> Vec<u8> {
        self.ciphertext.clone()
    }

    fn nonce(&self) -> Vec<u8> {
        self.nonce.clone()
    }
}

#[uniffi::export]
impl EncryptedField {
    #[uniffi::constructor]
    pub fn new(encryption_key: &Vec<u8>, field: &Vec<u8>) -> Result<Self, EncryptionError> {
        encrypt_using_symmetric_key(encryption_key, field)
    }

    /// Rebuilds an `EncryptedField` from ciphertext and nonce sealed elsewhere,
    /// typically a vault entry read back from the server.
    ///
    /// Unlike [`new`](Self::new), which encrypts what it is given, this only
    /// carries already-sealed bytes across the FFI boundary. Without it a
    /// binding has no way to hand an `EncryptedField` back to the library,
    /// since the fields of a `uniffi::Object` are not exposed.
    ///
    /// # Arguments
    ///
    /// * `ciphertext` - The ciphertext.
    /// * `nonce` - The nonce it was sealed with.
    #[uniffi::constructor]
    pub fn from_parts(ciphertext: &Vec<u8>, nonce: &Vec<u8>) -> Self {
        EncryptedField {
            ciphertext: ciphertext.to_owned(),
            nonce: nonce.to_owned(),
        }
    }
}
