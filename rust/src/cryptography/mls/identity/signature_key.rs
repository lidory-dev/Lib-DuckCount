//! The local user's long-term MLS signature key pair.
//!
//! This key *is* the user's MLS identity. Peers pin its public half the first
//! time they see it (see [`super::pinning_provider`]), so losing it is not a
//! local inconvenience: every peer will refuse the replacement until the user
//! re-verifies out of band. It therefore belongs in the user's vault, where it
//! survives a reinstall, as well as in local storage where it is used.

use std::sync::Arc;

use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};

use crate::cryptography::mls::{
    MlsError,
    config::generate_signature_key_pair,
    storage::{MlsNamespace, MlsStore, sealed_record::SealingKey},
};

/// A signature key pair as held in storage.
pub struct SignatureKeyPair {
    pub secret: SignatureSecretKey,
    pub public: SignaturePublicKey,
}

impl SignatureKeyPair {
    /// Encodes the pair as `secret_length || secret || public`.
    fn encode(&self) -> Vec<u8> {
        let secret = self.secret.as_ref();
        let public = self.public.as_ref();

        let mut encoded = Vec::with_capacity(4 + secret.len() + public.len());

        encoded.extend_from_slice(&(secret.len() as u32).to_be_bytes());
        encoded.extend_from_slice(secret);
        encoded.extend_from_slice(public);

        encoded
    }

    /// Decodes a pair written by [`encode`](Self::encode).
    fn decode(encoded: &[u8]) -> Result<Self, MlsError> {
        if encoded.len() < 4 {
            return Err(MlsError::StorageIntegrityFailed);
        }

        let secret_length =
            u32::from_be_bytes([encoded[0], encoded[1], encoded[2], encoded[3]]) as usize;

        let public_start = 4usize
            .checked_add(secret_length)
            .ok_or(MlsError::StorageIntegrityFailed)?;

        if encoded.len() <= public_start {
            return Err(MlsError::StorageIntegrityFailed);
        }

        Ok(SignatureKeyPair {
            secret: SignatureSecretKey::from(encoded[4..public_start].to_vec()),
            public: SignaturePublicKey::new(encoded[public_start..].to_vec()),
        })
    }
}

/// Reads the stored signature key pair of `user_uuid`, if there is one.
///
/// # Errors
///
/// * `MlsError::StorageFailed` - If the host storage fails.
/// * `MlsError::StorageIntegrityFailed` - If the stored pair fails authentication
///   or is malformed.
pub fn load(
    store: &Arc<dyn MlsStore>,
    sealing_key: &SealingKey,
    user_uuid: &str,
) -> Result<Option<SignatureKeyPair>, MlsError> {
    let key = user_uuid.as_bytes();

    let Some(sealed) = store
        .get(MlsNamespace::Signer, key.to_vec())
        .map_err(|error| MlsError::StorageFailed(error.to_string()))?
    else {
        return Ok(None);
    };

    let encoded = sealing_key.unseal(MlsNamespace::Signer, key, &sealed)?;

    SignatureKeyPair::decode(&encoded).map(Some)
}

/// Stores `key_pair` as the signature key pair of `user_uuid`, replacing any
/// existing one.
///
/// # Errors
///
/// * `MlsError::StorageFailed` - If the host storage fails.
/// * `MlsError::StorageIntegrityFailed` - If sealing fails.
pub fn save(
    store: &Arc<dyn MlsStore>,
    sealing_key: &SealingKey,
    user_uuid: &str,
    key_pair: &SignatureKeyPair,
) -> Result<(), MlsError> {
    let key = user_uuid.as_bytes();

    let sealed = sealing_key.seal(MlsNamespace::Signer, key, &key_pair.encode())?;

    store
        .put(MlsNamespace::Signer, key.to_vec(), sealed)
        .map_err(|error| MlsError::StorageFailed(error.to_string()))
}

/// Reads the stored signature key pair of `user_uuid`, generating and storing a
/// fresh one the first time.
///
/// # Errors
///
/// * `MlsError::StorageFailed` - If the host storage fails.
/// * `MlsError::StorageIntegrityFailed` - If the stored pair fails authentication.
/// * `MlsError::ProtocolFailed` - If key generation fails.
pub fn load_or_create(
    store: &Arc<dyn MlsStore>,
    sealing_key: &SealingKey,
    user_uuid: &str,
) -> Result<SignatureKeyPair, MlsError> {
    if let Some(key_pair) = load(store, sealing_key, user_uuid)? {
        return Ok(key_pair);
    }

    let (secret, public) = generate_signature_key_pair()?;
    let key_pair = SignatureKeyPair { secret, public };

    save(store, sealing_key, user_uuid, &key_pair)?;

    Ok(key_pair)
}
