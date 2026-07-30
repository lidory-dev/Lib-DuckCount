//! The MLS client: one user's identity, key packages, and groups.

use std::sync::{Arc, Mutex};

use mls_rs::identity::SigningIdentity;
use mls_rs::{Client, ExtensionList, MlsMessage};
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
use rand::RngCore;
use rand::rngs::OsRng;

use crate::cryptography::mls::{
    MlsError,
    config::{DuckCountMlsConfig, build_client},
    group::MlsGroup,
    identity::{
        credential::credential_for,
        fingerprint::fingerprint,
        pinning_provider::PinningIdentityProvider,
        signature_key::{self, SignatureKeyPair},
    },
    invitation::{match_welcomes, validate_invitees},
    key_package::generate_key_packages::generate_key_packages,
    storage::{
        MlsStore, group_state::SealedGroupStateStorage, identity_pin::IdentityPinStore,
        key_package::SealedKeyPackageStorage, sealed_record::SealingKey,
    },
    types::{GroupCreation, InviteeKeyPackage, KeyPackageBundle},
};

/// Length of a generated MLS group identifier, in bytes.
///
/// Group ids must be unique across every group a client belongs to, and are
/// chosen by whoever creates the group. 32 random bytes make a collision
/// impossible in practice without any coordination.
const GROUP_ID_LENGTH: usize = 32;

/// One user's MLS client.
///
/// # Relationship to the DuckCount API
///
/// Every method here produces bytes for exactly one API call, or consumes bytes
/// from one. The client knows nothing about server group UUIDs, HTTP, or
/// message ordering (those belong to the host).
///
/// # Threading
///
/// The client is safe to share between threads, but MLS operations on one
/// client are serialised: they mutate stored state, and interleaving them would
/// corrupt it.
#[derive(uniffi::Object)]
pub struct MlsClient {
    user_uuid: String,
    client: Mutex<Client<DuckCountMlsConfig>>,
    signature_key_pair: SignatureKeyPair,
    pins: IdentityPinStore,
    group_states: SealedGroupStateStorage,
}

#[uniffi::export]
impl MlsClient {
    /// Opens the MLS client for a user, creating its identity on first use.
    ///
    /// The first call generates the user's long-term signature key pair and
    /// stores it sealed. Later calls reuse it. `secret` must be the same value
    /// every time, it is what the stored state is sealed with, so a different
    /// secret makes every existing group unreadable.
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - The user's UUID, in canonical hyphenated lowercase form.
    /// * `secret` - The user's vault secret, used to derive the sealing key.
    /// * `store` - Host storage for MLS state.
    ///
    /// # Returns
    ///
    /// * `Result<Self, MlsError>` - The ready client.
    ///
    /// # Errors
    ///
    /// * `MlsError::InvalidCredential` - If `user_uuid` is not a canonical UUID.
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If stored state fails authentication,
    ///   which is what a wrong `secret` looks like.
    /// * `MlsError::KeyDerivationFailed` - If deriving the sealing key fails.
    /// * `MlsError::ProtocolFailed` - If generating the signature key pair fails.
    #[uniffi::constructor]
    pub fn new(
        user_uuid: String,
        secret: Vec<u8>,
        store: Arc<dyn MlsStore>,
    ) -> Result<Self, MlsError> {
        let sealing_key = SealingKey::load_or_create(&secret, &store)?;

        let signature_key_pair = signature_key::load_or_create(&store, &sealing_key, &user_uuid)?;

        Self::assemble(user_uuid, store, sealing_key, signature_key_pair)
    }

    /// Opens the MLS client for a user, installing a signature key recovered
    /// from their vault.
    ///
    /// Use this on a fresh device. Restoring the original key is what lets
    /// existing peers keep recognising the user: a newly generated key would be
    /// rejected by everyone who has already pinned the old one.
    ///
    /// Any signature key already stored locally is replaced.
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - The user's UUID, in canonical hyphenated lowercase form.
    /// * `secret` - The user's vault secret, used to derive the sealing key.
    /// * `store` - Host storage for MLS state.
    /// * `signature_private_key` - The private key previously returned by
    ///   [`signature_private_key`](Self::signature_private_key).
    /// * `signature_public_key` - Its matching public key.
    ///
    /// # Returns
    ///
    /// * `Result<Self, MlsError>` - The ready client.
    ///
    /// # Errors
    ///
    /// * `MlsError::InvalidCredential` - If `user_uuid` is not a canonical UUID.
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::KeyDerivationFailed` - If deriving the sealing key fails.
    #[uniffi::constructor]
    pub fn restore(
        user_uuid: String,
        secret: Vec<u8>,
        store: Arc<dyn MlsStore>,
        signature_private_key: Vec<u8>,
        signature_public_key: Vec<u8>,
    ) -> Result<Self, MlsError> {
        let sealing_key = SealingKey::load_or_create(&secret, &store)?;

        let signature_key_pair = SignatureKeyPair {
            secret: SignatureSecretKey::from(signature_private_key),
            public: SignaturePublicKey::new(signature_public_key),
        };

        signature_key::save(&store, &sealing_key, &user_uuid, &signature_key_pair)?;

        Self::assemble(user_uuid, store, sealing_key, signature_key_pair)
    }

    /// The user's MLS signature public key.
    ///
    /// This is the value to publish as the account's public key at registration,
    /// and the value peers pin. It is not secret.
    pub fn signature_public_key(&self) -> Vec<u8> {
        self.signature_key_pair.public.as_ref().to_vec()
    }

    /// The user's MLS signature private key.
    ///
    /// # Warning
    ///
    /// This is the user's MLS identity. It is exposed for one purpose: storing
    /// it in the user's vault so a reinstall can recover it with
    /// [`restore`](Self::restore). It must never be logged, sent anywhere
    /// unencrypted, or persisted outside the vault.
    pub fn signature_private_key(&self) -> Vec<u8> {
        self.signature_key_pair.secret.as_ref().to_vec()
    }

    /// The safety number of the user's own signature key, for reading out to a
    /// peer who is verifying them.
    pub fn fingerprint(&self) -> String {
        fingerprint(self.signature_key_pair.public.as_ref())
    }

    /// Generates key packages to publish so peers can add this user to groups
    /// while they are offline.
    ///
    /// See
    /// [`generate_key_packages`](crate::cryptography::mls::key_package::generate_key_packages::generate_key_packages)
    /// for what the bundle contains and how often to republish.
    ///
    /// # Arguments
    ///
    /// * `one_time_count` - How many one-time key packages to generate.
    ///
    /// # Returns
    ///
    /// * `Result<KeyPackageBundle, MlsError>` - The key packages to publish.
    ///
    /// # Errors
    ///
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If key package generation fails.
    /// * `MlsError::StorageFailed` - If the generated secrets cannot be stored.
    pub fn generate_key_packages(&self, one_time_count: u32) -> Result<KeyPackageBundle, MlsError> {
        let client = self.client.lock().map_err(|_| MlsError::LockPoisoned)?;

        generate_key_packages(&client, one_time_count)
    }

    /// Creates a group containing this user and the given invitees.
    ///
    /// The group is created and the invitees added in one step, so the returned
    /// state is final: there is no Commit to distribute, because nobody else was
    /// in the group to receive one. That matches `POST /groups`, which takes
    /// only the per-invitee Welcomes.
    ///
    /// The group exists locally as soon as this returns. If the server rejects
    /// the request, call [`delete_group`](Self::delete_group) to discard it.
    ///
    /// # Arguments
    ///
    /// * `invitees` - The user UUID and fetched key package of each invitee.
    ///
    /// # Returns
    ///
    /// * `Result<GroupCreation, MlsError>` - The new group's id and one Welcome
    ///   per invitee.
    ///
    /// # Errors
    ///
    /// * `MlsError::InvalidKeyPackage` - If a key package is unusable.
    /// * `MlsError::InvalidCredential` - If a key package asserts a different user
    ///   than the one it was fetched for.
    /// * `MlsError::IdentityKeyMismatch` - If an invitee's signature key differs
    ///   from the one pinned for them.
    /// * `MlsError::UnmatchedWelcome` - If any invitee ends up without a Welcome.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If the group or commit cannot be built.
    /// * `MlsError::StorageFailed` - If the new group cannot be stored.
    pub fn create_group(
        &self,
        invitees: Vec<InviteeKeyPackage>,
    ) -> Result<GroupCreation, MlsError> {
        let invitees = validate_invitees(invitees)?;

        let client = self.client.lock().map_err(|_| MlsError::LockPoisoned)?;

        let mut group_id = vec![0u8; GROUP_ID_LENGTH];
        OsRng.fill_bytes(&mut group_id);

        let mut group = client.create_group_with_id(
            group_id.clone(),
            ExtensionList::default(),
            ExtensionList::default(),
            None,
        )?;

        // A group with no invitees is just this user; there is nothing to commit
        // and no Welcome to produce.
        if invitees.is_empty() {
            group.write_to_storage()?;

            return Ok(GroupCreation {
                mls_group_id: group_id,
                welcomes: Vec::new(),
            });
        }

        let mut commit_builder = group.commit_builder();

        for invitee in &invitees {
            commit_builder = commit_builder.add_member(invitee.key_package.clone())?;
        }

        let commit_output = commit_builder.build()?;

        // Matched before anything is persisted: a group that cannot produce a
        // Welcome for every invitee is unusable, and failing here leaves no
        // orphaned state behind for the host to clean up blind.
        let welcomes = match_welcomes(&commit_output.welcome_messages, &invitees)?;

        // Applying immediately is safe here, and only here: this user is the
        // only member, so no other view of the group can diverge from it.
        group.apply_pending_commit()?;
        group.write_to_storage()?;

        Ok(GroupCreation {
            mls_group_id: group_id,
            welcomes,
        })
    }

    /// Joins a group from a Welcome message.
    ///
    /// # Arguments
    ///
    /// * `welcome` - The Welcome ciphertext drained from the group's messages.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, MlsError>` - The MLS group id of the joined group. The
    ///   host is responsible for recording which server group UUID it belongs to.
    ///
    /// # Errors
    ///
    /// * `MlsError::InvalidMessage` - If the Welcome cannot be parsed.
    /// * `MlsError::IdentityKeyMismatch` - If a member's signature key differs
    ///   from the one pinned for them.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If the Welcome is not addressed to this
    ///   user, or its key package has already been used.
    /// * `MlsError::StorageFailed` - If the joined group cannot be stored.
    pub fn join_group(&self, welcome: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        let welcome = MlsMessage::from_bytes(&welcome).map_err(|_| MlsError::InvalidMessage)?;

        let client = self.client.lock().map_err(|_| MlsError::LockPoisoned)?;

        let (mut group, _) = client.join_group(None, &welcome, None)?;

        group.write_to_storage()?;

        Ok(group.group_id().to_vec())
    }

    /// Opens a group this user already belongs to.
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - The group id returned by [`create_group`](Self::create_group)
    ///   or [`join_group`](Self::join_group).
    ///
    /// # Returns
    ///
    /// * `Result<Arc<MlsGroup>, MlsError>` - The group.
    ///
    /// # Errors
    ///
    /// * `MlsError::GroupNotFound` - If no such group is stored.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::StorageIntegrityFailed` - If the stored state fails authentication.
    pub fn load_group(&self, mls_group_id: Vec<u8>) -> Result<Arc<MlsGroup>, MlsError> {
        let client = self.client.lock().map_err(|_| MlsError::LockPoisoned)?;

        let group = client.load_group(&mls_group_id)?;

        Ok(Arc::new(MlsGroup::new(group)))
    }

    /// Deletes a group's stored state and every retained prior epoch.
    ///
    /// Call this once the user has left a group, been removed from one, or when
    /// a group creation was rejected by the server. Nothing else removes group
    /// secrets: MLS keeps them even after the local member is removed.
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - The group to forget.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    pub fn delete_group(&self, mls_group_id: Vec<u8>) -> Result<(), MlsError> {
        self.group_states.delete_group(&mls_group_id)
    }

    /// The safety number pinned for another user, if they have been seen.
    ///
    /// Shown next to a peer so two users can compare the same string over a
    /// channel the server does not control.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If the stored pin fails authentication.
    pub fn pinned_fingerprint(&self, user_uuid: String) -> Result<Option<String>, MlsError> {
        Ok(self
            .pins
            .pinned_key(&user_uuid)?
            .map(|signature_key| fingerprint(&signature_key)))
    }

    /// The signature key pinned for another user, if they have been seen.
    ///
    /// Pins live in the host's store, which on a device is the app's database,
    /// and a log-out empties it. The signature key pair itself survives, backed
    /// up by the host and restored through [`MlsClient::restore`], but the pins
    /// do not, and a client that has forgotten them trusts the next key package
    /// the server serves for each peer. Handing the pins out lets the host keep
    /// them wherever it keeps the rest of what must outlive the device, and put
    /// them back with [`MlsClient::pin_identity`] before anything is sent.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If the stored pin fails authentication.
    pub fn pinned_signature_key(&self, user_uuid: String) -> Result<Option<Vec<u8>>, MlsError> {
        self.pins.pinned_key(&user_uuid)
    }

    /// Pins `signature_key` to `user_uuid`, unless a different one is already
    /// pinned.
    ///
    /// For putting back pins the host kept, see
    /// [`MlsClient::pinned_signature_key`]. It refuses rather than overwrites:
    /// a restored pin disagreeing with one this client already holds is the
    /// same event pinning exists to report, and the fact that one of the two
    /// came from a backup makes it no less worth reporting.
    ///
    /// # Errors
    ///
    /// * `MlsError::IdentityKeyMismatch` - If a different key is already pinned.
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If a stored pin fails authentication.
    pub fn pin_identity(
        &self,
        user_uuid: String,
        signature_key: Vec<u8>,
    ) -> Result<(), MlsError> {
        self.pins.verify_or_pin(&user_uuid, &signature_key)
    }

    /// Forgets the signature key pinned for a user, so the next one seen is
    /// accepted and pinned afresh.
    ///
    /// # Warning
    ///
    /// This is the escape hatch for `IdentityKeyMismatch`, and it discards the
    /// only evidence that something changed. Call it *after* the user has
    /// compared the new safety number with the peer out of band, never
    /// automatically in response to the error, which would reduce pinning to
    /// no protection at all.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    pub fn clear_identity_pin(&self, user_uuid: String) -> Result<(), MlsError> {
        self.pins.clear(&user_uuid)
    }

    /// The UUID of the user this client belongs to.
    pub fn user_uuid(&self) -> String {
        self.user_uuid.clone()
    }
}

/// Deliberately opaque: the client holds the user's signature private key and
/// every group secret derived from it, none of which may reach a log.
impl std::fmt::Debug for MlsClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsClient")
            .field("user_uuid", &self.user_uuid)
            .finish_non_exhaustive()
    }
}

impl MlsClient {
    /// Wires the storage adapters and the mls-rs client together.
    fn assemble(
        user_uuid: String,
        store: Arc<dyn MlsStore>,
        sealing_key: SealingKey,
        signature_key_pair: SignatureKeyPair,
    ) -> Result<Self, MlsError> {
        let pins = IdentityPinStore::new(store.clone(), sealing_key.clone());
        let key_packages = SealedKeyPackageStorage::new(store.clone(), sealing_key.clone());
        let group_states = SealedGroupStateStorage::new(store, sealing_key);

        let signing_identity = SigningIdentity::new(
            credential_for(&user_uuid)?,
            signature_key_pair.public.clone(),
        );

        let client = build_client(
            signing_identity,
            signature_key_pair.secret.clone(),
            key_packages,
            group_states.clone(),
            PinningIdentityProvider::new(pins.clone()),
        );

        Ok(MlsClient {
            user_uuid,
            client: Mutex::new(client),
            signature_key_pair,
            pins,
            group_states,
        })
    }
}
