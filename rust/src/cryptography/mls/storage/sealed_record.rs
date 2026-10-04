//! Authenticated encryption of every record handed to the host.
//!
//! # Record format
//!
//! ```text
//! sealed  := nonce (12 bytes) || AES-256-GCM(sealing_key, nonce, payload, aad = slot)
//! slot    := namespace_tag (1 byte) || key
//! ```
//!
//! The namespace and key are authenticated as associated data rather than left
//! implicit, and never stored. A record lifted out of one slot and dropped into
//! another (a different group, a different epoch, another user's identity pin)
//! then fails to open instead of being silently accepted, which is what stops a
//! host with write access to its own database from confusing one group's state
//! for another's.

use argon2::password_hash::SaltString;
use rand::rngs::OsRng;
use std::sync::Arc;
use zeroize::Zeroizing;

use crate::cryptography::{
    encryption::{
        decrypt::decrypt_using_symmetric_key_with_associated_data,
        encrypt::encrypt_using_symmetric_key_with_associated_data,
        keys::{KeyUsage, derive_key},
    },
    mls::{
        MlsError,
        storage::{MlsNamespace, MlsStore},
    },
};

/// Nonce length of AES-256-GCM, in bytes.
const NONCE_LENGTH: usize = 12;

/// Key under which the sealing salt is stored, in [`MlsNamespace::Metadata`].
const SEALING_SALT_KEY: &[u8] = b"sealing-salt";

/// The key that seals every record before it leaves this crate.
///
/// Cloning is cheap and shares one derivation: the key is derived once with
/// Argon2id when the client starts, not per record.
#[derive(Clone)]
pub struct SealingKey {
    key: Arc<Zeroizing<Vec<u8>>>,
}

impl SealingKey {
    /// Derives the sealing key from the user's secret and the salt kept
    /// alongside the MLS state, generating and storing that salt on first use.
    ///
    /// The salt is stored unsealed in [`MlsNamespace::Metadata`]: it is not
    /// secret, and it has to be readable before any key exists to open it with.
    ///
    /// # Arguments
    ///
    /// * `secret` - The user's vault secret; the same secret must be supplied
    ///   on every run or previously stored records become unreadable.
    /// * `store` - The host storage holding (or about to hold) the salt.
    ///
    /// # Returns
    ///
    /// * `Result<SealingKey, MlsError>` - The derived key.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If reading or writing the salt fails.
    /// * `MlsError::StorageIntegrityFailed` - If the stored salt is not valid UTF-8.
    /// * `MlsError::KeyDerivationFailed` - If Argon2id key derivation fails.
    pub fn load_or_create(
        secret: &Vec<u8>,
        store: &Arc<dyn MlsStore>,
    ) -> Result<SealingKey, MlsError> {
        let stored_salt = store
            .get(MlsNamespace::Metadata, SEALING_SALT_KEY.to_vec())
            .map_err(|error| MlsError::StorageFailed(error.to_string()))?;

        let salt = match stored_salt {
            Some(bytes) => {
                String::from_utf8(bytes).map_err(|_| MlsError::StorageIntegrityFailed)?
            }
            None => {
                let salt = SaltString::generate(&mut OsRng).to_string();

                store
                    .put(
                        MlsNamespace::Metadata,
                        SEALING_SALT_KEY.to_vec(),
                        salt.as_bytes().to_vec(),
                    )
                    .map_err(|error| MlsError::StorageFailed(error.to_string()))?;

                salt
            }
        };

        let key = derive_key(secret, salt, KeyUsage::NonDeterministic)
            .map_err(|_| MlsError::KeyDerivationFailed)?;

        Ok(SealingKey {
            key: Arc::new(Zeroizing::new(key)),
        })
    }

    /// Seals `payload` for one specific slot of the host store.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace the record will live in.
    /// * `key` - The key the record will be stored under.
    /// * `payload` - The plaintext to protect.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, MlsError>` - The sealed record, safe to hand to the host.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageIntegrityFailed` - If encryption fails.
    pub fn seal(
        &self,
        namespace: MlsNamespace,
        key: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, MlsError> {
        let payload = Zeroizing::new(payload.to_vec());

        let encrypted = encrypt_using_symmetric_key_with_associated_data(
            &self.key,
            &payload,
            &slot(namespace, key),
        )
        .map_err(|_| MlsError::StorageIntegrityFailed)?;

        let mut sealed = encrypted.nonce;
        sealed.extend_from_slice(&encrypted.ciphertext);

        Ok(sealed)
    }

    /// Opens a record sealed by [`seal`](Self::seal) for the same slot.
    ///
    /// # Arguments
    ///
    /// * `namespace` - The namespace the record was read from.
    /// * `key` - The key the record was read from.
    /// * `sealed` - The bytes the host returned.
    ///
    /// # Returns
    ///
    /// * `Result<Zeroizing<Vec<u8>>, MlsError>` - The original plaintext.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageIntegrityFailed` - If the record is truncated, was
    ///   sealed under a different secret, was tampered with, or was stored under
    ///   a different namespace or key than the one being read.
    pub fn unseal(
        &self,
        namespace: MlsNamespace,
        key: &[u8],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, MlsError> {
        if sealed.len() <= NONCE_LENGTH {
            return Err(MlsError::StorageIntegrityFailed);
        }

        let (nonce, ciphertext) = sealed.split_at(NONCE_LENGTH);

        decrypt_using_symmetric_key_with_associated_data(
            &self.key,
            &ciphertext.to_vec(),
            &nonce.to_vec(),
            &slot(namespace, key),
        )
        .map(Zeroizing::new)
        .map_err(|_| MlsError::StorageIntegrityFailed)
    }
}

/// The slot a record is sealed for, as the associated data that binds it there.
///
/// The tag has a fixed length, so no two slots give the same bytes.
fn slot(namespace: MlsNamespace, key: &[u8]) -> Vec<u8> {
    let mut slot = Vec::with_capacity(1 + key.len());

    slot.push(namespace.tag());
    slot.extend_from_slice(key);

    slot
}
