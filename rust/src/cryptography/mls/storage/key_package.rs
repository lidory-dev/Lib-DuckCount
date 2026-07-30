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
/// package. mls-rs deletes a record as soon as its key package is used to join
/// a group, which is what makes a one-time key package one-time.
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
