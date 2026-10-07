//! [`KeyPackageStorage`] backed by the host's [`MlsStore`].

use std::sync::Arc;

use mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use zeroize::Zeroizing;

use crate::cryptography::mls::{
    MlsError,
    storage::{MlsNamespace, MlsStore, sealed_record::SealingKey},
};

/// Key package storage that seals every record before the host sees it.
///
/// Each record holds the init and leaf secret keys of one published key
/// package. mls-rs deletes the record of a one-time key package as soon as it
/// is used to join a group, which is what makes it one-time, and keeps that of
/// a last-resort one, which can be used again. Every record it keeps stays
/// until [`prune_expired`](Self::prune_expired) deletes it.
///
/// All clones share the same underlying host store.
#[derive(Clone)]
pub struct SealedKeyPackageStorage {
    store: Arc<dyn MlsStore>,
    sealing_key: SealingKey,
}

impl SealedKeyPackageStorage {
    /// Creates a storage adapter over `store`.
    pub fn new(store: Arc<dyn MlsStore>, sealing_key: SealingKey) -> Self {
        Self { store, sealing_key }
    }

    /// When the last of the key packages this device holds expires, in seconds
    /// since the Unix epoch, or `None` when it holds none it can open.
    ///
    /// What bounds the Welcomes it can still open: each was sealed to one of
    /// them, and [`prune_expired`](Self::prune_expired) deletes them by this
    /// same expiration.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    pub fn latest_expiration(&self) -> Result<Option<u64>, MlsError> {
        let ids = self
            .store
            .keys(MlsNamespace::KeyPackage)
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?;

        let mut latest = None;

        for id in ids {
            let expiration = match self.get(&id) {
                Ok(Some(data)) => data.expiration,
                // Gone since it was listed, or unreadable under this sealing key,
                // and so of no use to a join made with it either, see
                // `prune_expired`.
                Ok(None) | Err(MlsError::StorageIntegrityFailed) => continue,
                Err(error) => return Err(error),
            };

            latest = latest.max(Some(expiration));
        }

        Ok(latest)
    }

    /// Deletes every record whose key package expired before `expired_before`,
    /// in seconds since the Unix epoch, and returns how many went.
    ///
    /// A record that cannot be opened is left where it is. It is of no use to
    /// a join either, and deleting it would erase what may be the only sign
    /// that someone tampered with the store.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails. The records
    ///   deleted before it did stay deleted.
    pub fn prune_expired(&self, expired_before: u64) -> Result<u32, MlsError> {
        let ids = self
            .store
            .keys(MlsNamespace::KeyPackage)
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?;

        let mut pruned = 0;

        for id in ids {
            let data = match self.get(&id) {
                Ok(Some(data)) => data,
                // Gone since it was listed, which only the host emptying its
                // store does: a join waits for the client lock the caller holds.
                Ok(None) => continue,
                Err(MlsError::StorageIntegrityFailed) => continue,
                Err(error) => return Err(error),
            };

            if data.expiration >= expired_before {
                continue;
            }

            self.store
                .delete(MlsNamespace::KeyPackage, id)
                .map_err(|error| MlsError::StorageFailed(error.to_string()))?;

            pruned += 1;
        }

        Ok(pruned)
    }
}

impl KeyPackageStorage for SealedKeyPackageStorage {
    type Error = MlsError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        self.store
            .delete(MlsNamespace::KeyPackage, id.to_vec())
            .map_err(|error| MlsError::StorageFailed(error.to_string()))
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        let encoded = Zeroizing::new(
            pkg.mls_encode_to_vec()
                .map_err(|_| MlsError::InvalidKeyPackage)?,
        );

        let sealed = self
            .sealing_key
            .seal(MlsNamespace::KeyPackage, &id, &encoded)?;

        self.store
            .put(MlsNamespace::KeyPackage, id, sealed)
            .map_err(|error| MlsError::StorageFailed(error.to_string()))
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        let Some(sealed) = self
            .store
            .get(MlsNamespace::KeyPackage, id.to_vec())
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?
        else {
            return Ok(None);
        };

        let encoded = self
            .sealing_key
            .unseal(MlsNamespace::KeyPackage, id, &sealed)?;

        KeyPackageData::mls_decode(&mut &encoded[..])
            .map(Some)
            .map_err(|_| MlsError::StorageIntegrityFailed)
    }
}
