//! The MLS client: one user's identity, key packages, and groups.

use std::sync::{Arc, Mutex};

use mls_rs::identity::SigningIdentity;
use mls_rs::time::MlsTime;
use mls_rs::{Client, ExtensionList, MlsMessage};
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
use rand::RngCore;
use rand::rngs::OsRng;

use crate::cryptography::mls::{
    MlsError,
    config::{DuckCountMlsConfig, KEY_PACKAGE_RETENTION_AFTER_EXPIRY, build_client},
    group::{MlsGroup, expected_peers, pin_peers},
    identity::{
        credential::credential_for,
        fingerprint::fingerprint,
        pinning_provider::PinningIdentityProvider,
        signature_key::{self, SignatureKeyPair},
    },
    invitation::{match_welcomes, pin_invitees, validate_invitees},
    key_package::generate_key_packages::generate_key_packages,
    one_time_expense::{self, OneTimeExpenseManifest},
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

/// The highest epoch a Welcome may put a joined group at.
///
/// A group moves one epoch per commit, so no real group comes near it, and it
/// sits far enough below `u64::MAX` that no run of commits can overflow the
/// `epoch += 1` mls-rs makes on each one, which panics in a debug build. A
/// Welcome is the only way an epoch this device did not count up to itself
/// reaches its state, and it is its author's to write.
const MAX_JOINED_EPOCH: u64 = u32::MAX as u64;

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
    key_packages: SealedKeyPackageStorage,
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

    /// Signs one version of a one-time expense this user is the creditor of.
    ///
    /// See [`one_time_expense`] for what the signature covers, and
    /// [`verify_one_time_expense`](one_time_expense::verify_one_time_expense)
    /// for checking it.
    ///
    /// # Errors
    ///
    /// * `MlsError::ProtocolFailed` - If the manifest cannot be encoded or signed.
    pub fn sign_one_time_expense(
        &self,
        manifest: OneTimeExpenseManifest,
    ) -> Result<Vec<u8>, MlsError> {
        one_time_expense::sign(&self.signature_key_pair.secret, &self.user_uuid, manifest)
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

    /// Deletes the secrets of the key packages that expired long enough ago
    /// that no Welcome can still need them, and returns how many went.
    ///
    /// Call it after publishing, which is when they pile up, and only once
    /// nothing waiting for the user on the server is left unread. See
    /// [`KEY_PACKAGE_RETENTION_AFTER_EXPIRY`](crate::cryptography::mls::config::KEY_PACKAGE_RETENTION_AFTER_EXPIRY)
    /// for how long an expired key package is kept, and why.
    ///
    /// # Errors
    ///
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::StorageFailed` - If the host storage fails. The records
    ///   deleted before it did stay deleted.
    pub fn prune_key_packages(&self) -> Result<u32, MlsError> {
        let expired_before = MlsTime::now()
            .seconds_since_epoch()
            .saturating_sub(KEY_PACKAGE_RETENTION_AFTER_EXPIRY.as_secs());

        self.prune_key_packages_expired_before(expired_before)
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
    /// Each invitee's signature key is pinned to them either way.
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
    /// * `MlsError::GroupStateTooLarge` - If the group would grow past the most a
    ///   group may store.
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

        pin_invitees(&self.pins, &invitees)?;

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
    /// A Welcome is its author's word for who is in the group, so it is only
    /// accepted when the group holds exactly this user and `expected_members`,
    /// the users the host knows the Welcome to be about (for a contact
    /// request, its sender as the server authenticated them).
    ///
    /// The members are checked against the keys already pinned for them, and
    /// only pinned when `pin_members` says the host already trusts them. A
    /// Welcome read to find out who sent it, and then refused, must not decide
    /// who anybody is: the host pins those with [`MlsGroup::pin_members`] once
    /// it trusts them.
    ///
    /// A Welcome for a group this device has already joined is refused, even
    /// once the group is deleted. A last-resort key package survives the joins
    /// it serves, so the same Welcome can be replayed, and joining it again
    /// would put the group back at the epoch the Welcome was for.
    ///
    /// # Arguments
    ///
    /// * `welcome` - The Welcome ciphertext drained from the group's messages.
    /// * `expected_members` - The UUIDs of every member other than this user.
    /// * `pin_members` - Whether to pin them now.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, MlsError>` - The MLS group id of the joined group. The
    ///   host is responsible for recording which server group UUID it belongs to.
    ///
    /// # Errors
    ///
    /// * `MlsError::GroupStateTooLarge` - If the group would grow past the most a
    ///   group may store.
    /// * `MlsError::InvalidMessage` - If the Welcome cannot be parsed, or puts
    ///   the group at an epoch past 2^32 - 1, which no real group reaches.
    /// * `MlsError::IdentityKeyMismatch` - If a member's signature key differs
    ///   from the one pinned for them.
    /// * `MlsError::InvalidCredential` - If a member's credential is malformed.
    /// * `MlsError::UnexpectedMembers` - If the group's members are not exactly
    ///   this user and `expected_members`.
    /// * `MlsError::GroupAlreadyJoined` - If this device has joined the group before.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If the Welcome is not addressed to this
    ///   user, or its one-time key package has already been used.
    /// * `MlsError::StorageFailed` - If the joined group cannot be stored.
    pub fn join_group(
        &self,
        welcome: Vec<u8>,
        expected_members: Vec<String>,
        pin_members: bool,
    ) -> Result<Vec<u8>, MlsError> {
        let welcome = MlsMessage::from_bytes(&welcome).map_err(|_| MlsError::InvalidMessage)?;

        let client = self.client.lock().map_err(|_| MlsError::LockPoisoned)?;

        // Joined in memory only: mls-rs stores nothing, and spends no key
        // package, until `write_to_storage`.
        let (mut group, _) = client.join_group(None, &welcome, None)?;

        if group.current_epoch() > MAX_JOINED_EPOCH {
            return Err(MlsError::InvalidMessage);
        }

        if self.group_states.has_held(group.group_id())? {
            return Err(MlsError::GroupAlreadyJoined);
        }

        let peers = expected_peers(&group, expected_members)?;

        // Before the group is stored, so that a join failing to store it can
        // simply be tried again: once stored, it is never joined again.
        if pin_members {
            pin_peers(&self.pins, &peers)?;
        }

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

        Ok(Arc::new(MlsGroup::new(group, self.pins.clone())))
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
    pub fn pin_identity(&self, user_uuid: String, signature_key: Vec<u8>) -> Result<(), MlsError> {
        self.pins.verify_or_pin(&user_uuid, &signature_key)
    }

    /// Forgets the signature key pinned for a user, so the next one they are
    /// invited or trusted with is pinned afresh.
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
    /// [`MlsClient::prune_key_packages`], deleting the key packages that
    /// expired before `expired_before`, in seconds since the Unix epoch, so a
    /// test can stand in for the months it takes.
    pub(crate) fn prune_key_packages_expired_before(
        &self,
        expired_before: u64,
    ) -> Result<u32, MlsError> {
        // Under the client lock, like every other MLS operation: a join reads
        // the record of the key package its Welcome was sealed to, then
        // deletes it.
        let _client = self.client.lock().map_err(|_| MlsError::LockPoisoned)?;

        self.key_packages.prune_expired(expired_before)
    }

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
            key_packages.clone(),
            group_states.clone(),
            PinningIdentityProvider::new(pins.clone()),
        );

        Ok(MlsClient {
            user_uuid,
            client: Mutex::new(client),
            signature_key_pair,
            pins,
            group_states,
            key_packages,
        })
    }
}
