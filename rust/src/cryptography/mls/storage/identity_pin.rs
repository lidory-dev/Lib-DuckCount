//! Trust-on-first-use pinning of member signature keys.
//!
//! MLS says nothing about *which* signature key legitimately belongs to a given
//! user; a basic credential is a bare assertion. Left at that, the server (the
//! party that hands out key packages) would decide who "Bob" is, and could
//! quietly seat itself in every group. Pinning removes that power: the
//! signature key a user is first invited or trusted with is remembered, and
//! any later one is rejected until a human resolves the discrepancy.
//!
//! Records are sealed like every other, not because a public key is secret but
//! because the AEAD tag is what stops an attacker with write access to the
//! host's database from swapping a pin.

use std::sync::Arc;

use crate::cryptography::mls::{
    MlsError,
    storage::{MlsNamespace, MlsStore, sealed_record::SealingKey},
};

/// The signature keys pinned to user UUIDs on first contact.
///
/// All clones share the same underlying host store.
#[derive(Clone)]
pub struct IdentityPinStore {
    store: Arc<dyn MlsStore>,
    sealing_key: SealingKey,
}

impl IdentityPinStore {
    /// Creates a pin store over `store`.
    pub fn new(store: Arc<dyn MlsStore>, sealing_key: SealingKey) -> Self {
        Self { store, sealing_key }
    }

    /// Returns the signature key pinned for `user_uuid`, if there is one.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If the stored pin fails authentication.
    pub fn pinned_key(&self, user_uuid: &str) -> Result<Option<Vec<u8>>, MlsError> {
        let key = user_uuid.as_bytes();

        let Some(sealed) = self
            .store
            .get(MlsNamespace::IdentityPin, key.to_vec())
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?
        else {
            return Ok(None);
        };

        self.sealing_key
            .unseal(MlsNamespace::IdentityPin, key, &sealed)
            .map(|signature_key| Some(signature_key.to_vec()))
    }

    /// Pins `signature_key` to `user_uuid`, replacing any existing pin.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If sealing fails.
    pub fn pin(&self, user_uuid: &str, signature_key: &[u8]) -> Result<(), MlsError> {
        let key = user_uuid.as_bytes();

        let sealed = self
            .sealing_key
            .seal(MlsNamespace::IdentityPin, key, signature_key)?;

        self.store
            .put(MlsNamespace::IdentityPin, key.to_vec(), sealed)
            .map_err(|error| MlsError::StorageFailed(error.to_string()))
    }

    /// Forgets the pin held for `user_uuid`.
    ///
    /// The next signature key that user is invited or trusted with is pinned
    /// afresh, so this is only safe once the user has verified the new key out
    /// of band.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    pub fn clear(&self, user_uuid: &str) -> Result<(), MlsError> {
        self.store
            .delete(MlsNamespace::IdentityPin, user_uuid.as_bytes().to_vec())
            .map_err(|error| MlsError::StorageFailed(error.to_string()))
    }

    /// Checks `signature_key` against the pin for `user_uuid`, without pinning
    /// anything when there is none.
    ///
    /// # Errors
    ///
    /// * `MlsError::IdentityKeyMismatch` - If a different key is already pinned.
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If a stored pin fails authentication.
    pub fn verify(&self, user_uuid: &str, signature_key: &[u8]) -> Result<(), MlsError> {
        match self.pinned_key(user_uuid)? {
            Some(pinned) if pinned != signature_key => {
                Err(MlsError::IdentityKeyMismatch(user_uuid.to_string()))
            }
            _ => Ok(()),
        }
    }

    /// Checks `signature_key` against the pin for `user_uuid`, pinning it when
    /// none is pinned yet.
    ///
    /// # Errors
    ///
    /// * `MlsError::IdentityKeyMismatch` - If a different key is already pinned.
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If a stored pin fails authentication.
    pub fn verify_or_pin(&self, user_uuid: &str, signature_key: &[u8]) -> Result<(), MlsError> {
        match self.pinned_key(user_uuid)? {
            Some(pinned) if pinned == signature_key => Ok(()),
            Some(_) => Err(MlsError::IdentityKeyMismatch(user_uuid.to_string())),
            None => self.pin(user_uuid, signature_key),
        }
    }
}
