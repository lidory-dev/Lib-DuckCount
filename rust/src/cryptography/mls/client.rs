//! The MLS client: one user's identity, key packages, and groups.

use std::sync::{Arc, Mutex};

use mls_rs::extension::ExtensionType;
use mls_rs::extension::built_in::RatchetTreeExt;
use mls_rs::identity::SigningIdentity;
use mls_rs::time::MlsTime;
use mls_rs::{Client, ExtensionList, Group, MlsMessage};
use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};

use crate::cryptography::mls::{
    MAX_GROUP_MEMBERS, MlsError,
    config::{DuckCountMlsConfig, KEY_PACKAGE_RETENTION_AFTER_EXPIRY, build_client},
    group::{MlsGroup, expected_peers, peers, pin_peers, store},
    group_expense::{self, GroupExpenseDeletion, GroupExpenseVersion},
    group_id::{self, new_mls_group_id, server_group_id},
    group_information::{self, GroupInformation},
    identity::{
        credential::{credential_for, user_uuid_from},
        fingerprint::safety_number,
        pinning_provider::PinningIdentityProvider,
        signature_key::{self, SignatureKeyPair},
    },
    invitation::{
        pin_invitees, shared_welcome, validate_invitees, welcome_payload,
        welcome_payload_extensions,
    },
    key_package::generate_key_packages::generate_key_packages,
    one_time_expense::{self, OneTimeExpenseManifest, OneTimeExpenseSettledMark},
    storage::{
        MlsStore, group_state::SealedGroupStateStorage, identity_pin::IdentityPinStore,
        key_package::SealedKeyPackageStorage, sealed_record::SealingKey,
    },
    types::{GroupCreation, GroupRejoin, InviteeKeyPackage, KeyPackageBundle, WelcomeInspection},
};

/// The highest epoch a Welcome, or a GroupInfo a rejoin is built from, may
/// put a joined group at.
///
/// A group moves one epoch per commit, so no real group comes near it, and it
/// sits far enough below `u64::MAX` that no run of commits can overflow the
/// `epoch += 1` mls-rs makes on each one, which panics in a debug build. A
/// Welcome and a GroupInfo are the only ways an epoch this device did not
/// count up to itself reaches its state, and each is its author's to write.
const MAX_JOINED_EPOCH: u64 = u32::MAX as u64;

/// One user's MLS client.
///
/// # Relationship to the DuckCount API
///
/// Every method here produces bytes for exactly one API call, or consumes bytes
/// from one, or both, as a rejoin does. The client knows nothing about HTTP or
/// message ordering (those belong to the host), and of the API's group UUIDs
/// only that the id of a group it holds is derived from one, see [`group_id`].
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

    /// Signs the mark saying whether a one-time expense this user is the
    /// creditor of has been paid back.
    ///
    /// See [`OneTimeExpenseSettledMark`] for what it covers, and
    /// [`verify_one_time_expense_settled_mark`](one_time_expense::verify_one_time_expense_settled_mark)
    /// for checking it.
    ///
    /// # Errors
    ///
    /// * `MlsError::ProtocolFailed` - If the mark cannot be encoded or signed.
    pub fn sign_one_time_expense_settled_mark(
        &self,
        mark: OneTimeExpenseSettledMark,
    ) -> Result<Vec<u8>, MlsError> {
        one_time_expense::sign_settled_mark(&self.signature_key_pair.secret, &self.user_uuid, mark)
    }

    /// Signs one version of the information of a group this user owns.
    ///
    /// See [`group_information`] for what the signature covers, and
    /// [`verify_group_information`](group_information::verify_group_information)
    /// for checking it.
    ///
    /// # Errors
    ///
    /// * `MlsError::ProtocolFailed` - If the information cannot be encoded or
    ///   signed.
    pub fn sign_group_information(
        &self,
        information: GroupInformation,
    ) -> Result<Vec<u8>, MlsError> {
        group_information::sign(
            &self.signature_key_pair.secret,
            &self.user_uuid,
            information,
        )
    }

    /// Signs one version of a group expense this user writes, be it the
    /// expense's creation or an edit. A settlement's verifies only when this
    /// user is the member it was paid to and the version is its creation, a
    /// settlement being never edited.
    ///
    /// See [`group_expense`] for what the signature covers, and
    /// [`verify_group_expense`](group_expense::verify_group_expense) for
    /// checking it.
    ///
    /// # Errors
    ///
    /// * `MlsError::ProtocolFailed` - If the version cannot be encoded or
    ///   signed.
    pub fn sign_group_expense(&self, version: GroupExpenseVersion) -> Result<Vec<u8>, MlsError> {
        group_expense::sign(&self.signature_key_pair.secret, &self.user_uuid, version)
    }

    /// Signs the flag saying whether a group expense is deleted, as this user
    /// deletes or restores it. A settlement's verifies only when this user is
    /// the member it was paid to and the flag deletes it.
    ///
    /// See [`GroupExpenseDeletion`] for what it covers, and
    /// [`verify_group_expense_deletion`](group_expense::verify_group_expense_deletion)
    /// for checking it.
    ///
    /// # Errors
    ///
    /// * `MlsError::ProtocolFailed` - If the flag cannot be encoded or signed.
    pub fn sign_group_expense_deletion(
        &self,
        deletion: GroupExpenseDeletion,
    ) -> Result<Vec<u8>, MlsError> {
        group_expense::sign_deletion(&self.signature_key_pair.secret, &self.user_uuid, deletion)
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
    /// The records of the deleted groups go too once every key package held
    /// when they were deleted is pruned: no Welcome this device was joined from
    /// can be opened again, so none can put such a group back at an epoch this
    /// device held, see [`delete_group`](Self::delete_group). A Welcome adding
    /// this device back to one of them, for a later epoch, is joined before as
    /// after.
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
    /// only the one Welcome every invitee joins from.
    ///
    /// The group exists locally as soon as this returns. If the server rejects
    /// the request, call [`delete_group`](Self::delete_group) to discard it.
    /// Each invitee's signature key is pinned to them either way.
    ///
    /// `welcome_payload` is how the host hands the invitees what they need
    /// beside the group itself, such as the keys to its members' profiles. It
    /// travels inside the Welcome, encrypted to them and signed by this user,
    /// and each reads it back from [`WelcomeInspection::welcome_payload`].
    /// This library does not look inside. The key the group's own fields are
    /// sealed under is not for it to carry: every member derives it from the
    /// epoch they are in, see
    /// [`MlsGroup::content_key`](crate::cryptography::mls::group::MlsGroup::content_key).
    ///
    /// The group's id is derived from `group_uuid`, see [`group_id`], which
    /// the invitees join it as.
    ///
    /// # Arguments
    ///
    /// * `group_uuid` - The UUID the DuckCount API is to hold the group under,
    ///   as [`new_group_id`](crate::cryptography::group_uuid::new_group_id)
    ///   minted it for this user, or `None` for a group it holds none for: a
    ///   direct channel or a contact request.
    /// * `invitees` - The user UUID and fetched key package of each invitee.
    /// * `welcome_payload` - What to hand the invitees, if anything.
    ///
    /// # Returns
    ///
    /// * `Result<GroupCreation, MlsError>` - The new group's id and the Welcome.
    ///
    /// # Errors
    ///
    /// * `MlsError::TooManyMembers` - If the group would hold more than
    ///   [`MAX_GROUP_MEMBERS`] members, this user included. Nothing is done.
    /// * `MlsError::GroupStateTooLarge` - If the group would grow past the most a
    ///   group may store.
    /// * `MlsError::UnusableKeyPackages` - Naming every invitee whose key
    ///   package cannot be used, see [`validate_invitees`]. Nothing is done.
    /// * `MlsError::IdentityKeyMismatch` - If an invitee's signature key differs
    ///   from the one pinned for them.
    /// * `MlsError::UnmatchedWelcome` - If an invitee has no secret in the Welcome.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If `invitees` is empty (nothing is done),
    ///   or the group or commit cannot be built.
    /// * `MlsError::StorageFailed` - If the new group cannot be stored.
    pub fn create_group(
        &self,
        group_uuid: Option<String>,
        invitees: Vec<InviteeKeyPackage>,
        welcome_payload: Option<Vec<u8>>,
    ) -> Result<GroupCreation, MlsError> {
        // This user counts. Before anything else, so that a list the host let
        // grow too long costs nothing, not even a pin.
        if invitees.len() + 1 > MAX_GROUP_MEMBERS {
            return Err(MlsError::TooManyMembers);
        }

        // A group of this user alone would have no Welcome to send, and the
        // DuckCount API refuses to create one.
        if invitees.is_empty() {
            return Err(MlsError::ProtocolFailed(
                "A group is created with at least one invitee.".to_string(),
            ));
        }

        let invitees = validate_invitees(invitees)?;

        let client = self.client.lock().map_err(|_| MlsError::LockPoisoned)?;

        let (group_id, mut group_info_extensions) = new_mls_group_id(group_uuid.as_deref());

        let mut group = client.create_group_with_id(
            group_id.clone(),
            ExtensionList::default(),
            ExtensionList::default(),
            None,
        )?;

        group_info_extensions.append(welcome_payload_extensions(welcome_payload));

        let mut commit_builder = group
            .commit_builder()
            .set_group_info_ext(group_info_extensions);

        for invitee in &invitees {
            commit_builder = commit_builder.add_member(invitee.key_package.clone())?;
        }

        let commit_output = commit_builder.build()?;

        // Checked before anything is persisted: a group whose Welcome does not
        // open for every invitee is unusable, and failing here leaves no
        // orphaned state behind for the host to clean up blind.
        let welcome = shared_welcome(&commit_output.welcome_messages, &invitees)?;

        pin_invitees(&self.pins, &invitees)?;

        // Applying immediately is safe here, and only here: this user is the
        // only member, so no other view of the group can diverge from it.
        group.apply_pending_commit()?;
        store(&mut group)?;

        Ok(GroupCreation {
            mls_group_id: group_id,
            welcome,
        })
    }

    /// Reads what a Welcome says without joining the group it is for.
    ///
    /// It runs every check [`join_group`](Self::join_group) runs before it
    /// stores the group but the one against the members the host expects,
    /// which is what this tells it instead: who wrote the Welcome, who else is
    /// in the group, and what was handed with it. It stores nothing, pins
    /// nobody and spends no key package, so the Welcome joins afterwards all
    /// the same.
    ///
    /// It exists for a host that decides whether to trust a Welcome from what
    /// the Welcome itself says, its committer and its payload. That decision
    /// has to come before [`join_group`](Self::join_group) stores the group,
    /// since a Welcome once joined can never be joined again, even if its
    /// group is deleted at once: one joined only to be found wanting, or left
    /// for later, would leave its group unjoinable on this device until a
    /// later Welcome added this user to it again. Once the host trusts it, it
    /// joins with [`WelcomeInspection::member_uuids`] as the expected members.
    ///
    /// The group's id is checked against the one derived for
    /// `expected_group_uuid`, as on a join, so no Welcome to another group is
    /// read as one to the group the host expects. What it cannot tell is the
    /// Welcome the DuckCount API stored with a group it holds from one a
    /// member posted there later, for a group of their own under the same
    /// UUID, see [`group_id`]: the host inspects only the one it would join
    /// from, as [`join_group`](Self::join_group) says.
    ///
    /// The members' keys are checked against those already pinned for them,
    /// as on a join, so a Welcome whose committer the host has pinned was
    /// signed with the pinned key.
    ///
    /// # Arguments
    ///
    /// * `welcome` - The Welcome ciphertext, as on
    ///   [`join_group`](Self::join_group).
    /// * `expected_group_uuid` - The UUID of the group the host expects it to
    ///   be for, as on [`join_group`](Self::join_group).
    ///
    /// # Returns
    ///
    /// * `Result<WelcomeInspection, MlsError>` - Who wrote the Welcome, the
    ///   other members, and what was handed with it.
    ///
    /// # Errors
    ///
    /// * `MlsError::TooManyMembers` - If the group holds more than
    ///   [`MAX_GROUP_MEMBERS`] members.
    /// * `MlsError::InvalidMessage` - As on [`join_group`](Self::join_group).
    /// * `MlsError::UnexpectedGroupId` - As on [`join_group`](Self::join_group).
    /// * `MlsError::IdentityKeyMismatch` - If a member's signature key differs
    ///   from the one pinned for them.
    /// * `MlsError::InvalidCredential` - If a member's credential is malformed.
    /// * `MlsError::GroupAlreadyJoined` - As on [`join_group`](Self::join_group).
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If the Welcome is not addressed to this
    ///   user, or its one-time key package has already been used.
    /// * `MlsError::StorageFailed` - If the host storage fails.
    pub fn inspect_welcome(
        &self,
        welcome: Vec<u8>,
        expected_group_uuid: Option<String>,
    ) -> Result<WelcomeInspection, MlsError> {
        let client = self.client.lock().map_err(|_| MlsError::LockPoisoned)?;

        let opened = self.open_welcome(&client, welcome, expected_group_uuid.as_deref())?;

        Ok(WelcomeInspection {
            committer_user_uuid: opened.committer_user_uuid,
            member_uuids: peers(&opened.group)?
                .into_iter()
                .map(|(user_uuid, _)| user_uuid)
                .collect(),
            welcome_payload: opened.welcome_payload,
        })
    }

    /// Joins a group from a Welcome message.
    ///
    /// A Welcome is its author's word for who is in the group, so it is only
    /// accepted when the group holds exactly this user and `expected_members`,
    /// the users the host knows the Welcome to be about (for a contact
    /// request, its sender as the server authenticated them).
    ///
    /// A host that cannot know them any better than the Welcome does takes
    /// them from it, with [`inspect_welcome`](Self::inspect_welcome), once it
    /// trusts its committer. A server's list of a group's members is one it
    /// cannot go by: it is today's, while the Welcome's tree is of the epoch
    /// it opens, and a member who has left since, with nobody committing their
    /// removal yet, is still in the tree but gone from the list.
    ///
    /// The members are checked against the keys already pinned for them, and
    /// only pinned when `pin_members` says the host already trusts them. A
    /// Welcome read to find out who sent it, and then refused, must not decide
    /// who anybody is: the host pins those with [`MlsGroup::pin_members`] once
    /// it trusts them, or, in a group the DuckCount API holds, any one of them
    /// with [`MlsGroup::pin_member`], on the word of its creator.
    ///
    /// A Welcome for a group of more than [`MAX_GROUP_MEMBERS`] members is
    /// refused as well, whoever wrote it, before anything is stored or pinned.
    ///
    /// So is one for any group but the one the host expects, before anything
    /// looks the group up: its id has to be the one derived for
    /// `expected_group_uuid`, see [`group_id`]. A channel or a contact request,
    /// which a host joins from anybody, can then never take the id of a group
    /// the DuckCount API holds, and no Welcome is joined as one to a group it
    /// is not for.
    ///
    /// The id of a group the API holds is anybody's to derive who knows its
    /// UUID, though, as every one of its members does, and any of them can
    /// create a group of their own under it and post its Welcome to the
    /// others, which the API lets any member do. Once this device joined
    /// theirs, the refusal below would keep it out of the real one for good.
    /// So a host joins a group the API holds only from the Welcome the API
    /// stored with it, or with the addition of this user to it, which comes
    /// first among the messages waiting for this user there, and never from
    /// one posted later.
    ///
    /// A Welcome for a group this device holds is refused, and so is one for a
    /// group it deleted, unless it is for an epoch past the one the group was
    /// at when deleted. A last-resort key package survives the joins it
    /// serves, so the same Welcome can be replayed, and joining it again would
    /// put the group back at the epoch the Welcome was for: any Welcome this
    /// device was joined from is for that epoch or an earlier one. A deleted
    /// group is forgotten once that key package is pruned, see
    /// [`prune_key_packages`](Self::prune_key_packages): no such Welcome opens
    /// by then. With the id derived, and the Welcome to a group the API holds
    /// the one it stored, a Welcome refused this way is one to the group this
    /// device joined before, never a channel's or a contact request's that took
    /// its id.
    ///
    /// One for a later epoch is let through, and is not necessarily the
    /// group's own: the creator adding this user back to a group they were
    /// removed from writes one, but so can anybody who knows the group's UUID,
    /// as every member does, for a group of their own under the same id,
    /// putting it at whichever epoch they like, see [`group_id`]. A host joining a group it
    /// left back does so only from the Welcome the API stored with this user's
    /// addition, as above, and only once
    /// [`inspect_welcome`](Self::inspect_welcome) names as its committer the
    /// creator it recorded for the group.
    ///
    /// # Arguments
    ///
    /// * `welcome` - The Welcome ciphertext: for a group the API holds, the one
    ///   it stored with the group, see above.
    /// * `expected_group_uuid` - The UUID the DuckCount API holds the group
    ///   under, in canonical hyphenated lowercase form, or `None` for a group
    ///   it holds none for: a direct channel or a contact request.
    /// * `expected_members` - The UUIDs of every member other than this user.
    /// * `pin_members` - Whether to pin them now.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, MlsError>` - The MLS group id of the joined group.
    ///
    /// # Errors
    ///
    /// * `MlsError::TooManyMembers` - If the group holds more than
    ///   [`MAX_GROUP_MEMBERS`] members.
    /// * `MlsError::GroupStateTooLarge` - If the group would grow past the most a
    ///   group may store.
    /// * `MlsError::InvalidMessage` - If the Welcome cannot be parsed, or puts
    ///   the group at an epoch past 2^32 - 1, which no real group reaches.
    /// * `MlsError::UnexpectedGroupId` - If the group's id is not the one
    ///   derived for `expected_group_uuid`.
    /// * `MlsError::IdentityKeyMismatch` - If a member's signature key differs
    ///   from the one pinned for them.
    /// * `MlsError::InvalidCredential` - If a member's credential is malformed.
    /// * `MlsError::UnexpectedMembers` - If the group's members are not exactly
    ///   this user and `expected_members`.
    /// * `MlsError::GroupAlreadyJoined` - If this device holds the group, or
    ///   deleted it at the Welcome's epoch or a later one and has not
    ///   forgotten it yet.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If the Welcome is not addressed to this
    ///   user, or its one-time key package has already been used.
    /// * `MlsError::StorageFailed` - If the joined group cannot be stored.
    pub fn join_group(
        &self,
        welcome: Vec<u8>,
        expected_group_uuid: Option<String>,
        expected_members: Vec<String>,
        pin_members: bool,
    ) -> Result<Vec<u8>, MlsError> {
        let client = self.client.lock().map_err(|_| MlsError::LockPoisoned)?;

        let mut opened = self.open_welcome(&client, welcome, expected_group_uuid.as_deref())?;

        let peers = expected_peers(&opened.group, expected_members)?;

        // Before the group is stored, so that a join failing to store it can
        // simply be tried again: once stored, it is never joined again.
        if pin_members {
            pin_peers(&self.pins, &peers)?;
        }

        store(&mut opened.group)?;

        Ok(opened.group.group_id().to_vec())
    }

    /// Rejoins a group the DuckCount API holds from outside it, with the
    /// GroupInfo `group_info` another member exported, see
    /// [`MlsGroup::rejoin_group_info`], for a member whose device holds none
    /// of the group's state: one a log-out emptied.
    ///
    /// A log-out takes every group's state with it, and a member who signs
    /// back in is still a member of each: the server lists them, the others
    /// keep encrypting to the leaf they had, but this device holds none of the
    /// secrets to read what they write. RFC 9420's resync brings it back: an
    /// external commit removing the leaf this user had and seating a new one,
    /// naming the same user under the same signature key, which
    /// [`restore`](Self::restore) put back from the vault. Nothing else
    /// changes, and every member takes it, from any member, see
    /// [`MlsGroup::process_incoming_message`]: the group holds the same
    /// members once it is applied, and the same keys but for the ones this
    /// device decrypts with. The Commit is for
    /// `POST /groups/{uuid}/commits/rejoin`, which stores it as the one Commit
    /// of the epoch the server lists the group in.
    ///
    /// The GroupInfo travels through the server unsealed, so before anything
    /// is built, it has to be one this device can take the word of, and for
    /// the group the host expects:
    ///
    /// * its signer, the member it names as having signed it, has to hold, in
    ///   the tree it carries, the key pinned for them, or be this user under
    ///   this user's own signature key, as a GroupInfo this user's device
    ///   exported before it was logged out is, and the signature has to hold:
    ///   anything else is the server's word for the group, and is refused as
    ///   [`MlsError::UntrustedGroupInfo`];
    /// * its group id has to be the one derived for `expected_group_uuid`, see
    ///   [`group_id`], and its epoch `expected_epoch`, the one the server
    ///   lists the group in, and stores the next Commit for;
    /// * its tree has to hold this user and exactly `expected_members`, at
    ///   most [`MAX_GROUP_MEMBERS`] in all, and hold this user under the
    ///   signature key this device holds: the leaf the Commit removes.
    ///
    /// Every leaf of the tree is then checked against the key pinned for whom
    /// it names, as on a join. Nobody is pinned, as on a join that pins
    /// nobody, see [`join_group`](Self::join_group): the members are who the
    /// signer, a member this device trusts, says they are, and the host pins
    /// any of them from the group as it would in a group it joined, with
    /// [`MlsGroup::pin_member`].
    ///
    /// mls-rs builds a Commit from outside a group applied: the group this
    /// stores is in the epoch the Commit makes, `expected_epoch + 1`, and holds
    /// no Commit pending, unlike after every other Commit, see
    /// [`MlsGroup::has_pending_commit`]. Nor does it hold anything of the epoch
    /// before, which this device never held: the content key of the epoch the
    /// GroupInfo is for is not this device's to derive, only that of the epoch
    /// the Commit makes, see [`MlsGroup::content_key`]. If the server refuses
    /// the Commit, its epoch taken by another, the host deletes the group, see
    /// [`delete_group`](Self::delete_group), and rejoins it from a GroupInfo
    /// of the epoch the server is in. A GroupInfo is for one Commit: members
    /// refuse a second built from it, its epoch gone once the first is
    /// applied.
    ///
    /// Whatever this device holds of the group already is deleted first: the
    /// state an earlier rejoin stored, whose Commit the host never sent or
    /// never recorded, and the records of epochs a write cut short left
    /// behind. The host rejoins a group only once it holds no record of it,
    /// so either would be an orphan of an earlier attempt, and either would
    /// keep mls-rs from storing the group it builds. It is deleted as
    /// [`delete_group`](Self::delete_group) deletes it, keeping the record of
    /// the epoch it was at, once the GroupInfo has passed every check above,
    /// and before mls-rs checks the tree against it: a GroupInfo refused then
    /// leaves the device with neither.
    ///
    /// [`MlsGroup::rejoin_group_info`]: crate::cryptography::mls::group::MlsGroup::rejoin_group_info
    /// [`MlsGroup::process_incoming_message`]: crate::cryptography::mls::group::MlsGroup::process_incoming_message
    /// [`MlsGroup::pin_member`]: crate::cryptography::mls::group::MlsGroup::pin_member
    /// [`MlsGroup::has_pending_commit`]: crate::cryptography::mls::group::MlsGroup::has_pending_commit
    /// [`MlsGroup::content_key`]: crate::cryptography::mls::group::MlsGroup::content_key
    ///
    /// # Arguments
    ///
    /// * `group_info` - The GroupInfo a member exported, as the server served
    ///   it.
    /// * `expected_group_uuid` - The UUID the DuckCount API holds the group
    ///   under, in canonical hyphenated lowercase form.
    /// * `expected_epoch` - The epoch the server lists the group in.
    /// * `expected_members` - The UUIDs of every member of the group other
    ///   than this user, as its tree holds them: the members the server
    ///   lists, and the departed ones whose removal nobody has committed yet.
    ///
    /// # Returns
    ///
    /// * `Result<GroupRejoin, MlsError>` - The group's id, the Commit, and the
    ///   epoch it takes the group to.
    ///
    /// # Errors
    ///
    /// * `MlsError::InvalidMessage` - If `group_info` cannot be parsed, is not
    ///   a GroupInfo, carries no ratchet tree or no key to build an external
    ///   commit with, as one [`MlsGroup::rejoin_group_info`] exports always
    ///   does, or is for an epoch other than `expected_epoch`, or past
    ///   2^32 - 1, which no real group reaches. Nothing is deleted.
    /// * `MlsError::UnexpectedGroupId` - If the group's id is not the one
    ///   derived for `expected_group_uuid`. Nothing is deleted.
    /// * `MlsError::TooManyMembers` - If the tree holds more than
    ///   [`MAX_GROUP_MEMBERS`] members. Nothing is deleted.
    /// * `MlsError::UntrustedGroupInfo` - If the GroupInfo's signer is neither
    ///   this user under their own signature key nor a member under the key
    ///   pinned for them, or its signature does not hold. Nothing is deleted,
    ///   and another member's GroupInfo may be taken.
    /// * `MlsError::UnexpectedMembers` - If the tree's members are not this
    ///   user and exactly `expected_members`, or hold this user under another
    ///   signature key than this device's. Nothing is deleted.
    /// * `MlsError::IdentityKeyMismatch` - If a member's signature key differs
    ///   from the one pinned for them.
    /// * `MlsError::InvalidCredential` - If a member's credential is malformed.
    /// * `MlsError::GroupStateTooLarge` - If the group would grow past the most
    ///   a group may store. Nothing is stored.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If the tree does not match the
    ///   GroupInfo, or the Commit cannot be built.
    /// * `MlsError::StorageFailed` - If the host storage fails.
    pub fn rejoin_group(
        &self,
        group_info: Vec<u8>,
        expected_group_uuid: String,
        expected_epoch: u64,
        expected_members: Vec<String>,
    ) -> Result<GroupRejoin, MlsError> {
        let client = self.client.lock().map_err(|_| MlsError::LockPoisoned)?;

        let group_info =
            MlsMessage::from_bytes(&group_info).map_err(|_| MlsError::InvalidMessage)?;

        let own_index = self.rejoined_leaf(
            &client,
            &group_info,
            &expected_group_uuid,
            expected_epoch,
            expected_members,
        )?;

        let group_id = server_group_id(&expected_group_uuid);

        self.delete_held_group(&client, &group_id)?;
        self.group_states.delete_epochs(&group_id)?;

        // With no time to check leaves against, as on a join: a member who
        // never committed keeps the leaf of the key package they were added
        // with, whose lifetime may have ended long since.
        let (mut group, commit) = client
            .external_commit_builder()?
            .with_removal(own_index)
            .build(group_info)?;

        store(&mut group)?;

        Ok(GroupRejoin {
            mls_group_id: group.group_id().to_vec(),
            commit: commit.to_bytes()?,
            epoch: group.current_epoch(),
        })
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
    /// The epoch the group is at is kept, so that every Welcome it was joined
    /// from stays refused, while a later one adding this user back to it can
    /// be joined, see [`join_group`](Self::join_group). A group whose stored
    /// state no longer opens is deleted too, every Welcome to it refused until
    /// [`prune_key_packages`](Self::prune_key_packages) forgets it. A group
    /// this device does not hold, deleted already or never joined, is left as
    /// it is.
    ///
    /// # Arguments
    ///
    /// * `mls_group_id` - The group to forget.
    ///
    /// # Errors
    ///
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::StorageFailed` - If the host storage fails.
    pub fn delete_group(&self, mls_group_id: Vec<u8>) -> Result<(), MlsError> {
        // Under the client lock, like every other MLS operation: a key package
        // generated, and joined from, between reading them and writing the
        // record would otherwise not count towards it.
        let client = self.client.lock().map_err(|_| MlsError::LockPoisoned)?;

        self.delete_held_group(&client, &mls_group_id)
    }

    /// The safety number of this user and another, if a key is pinned for them.
    ///
    /// Both users' devices show the same sixty digits, see [`safety_number`],
    /// as long as each holds the other's real key. Read to each other in person
    /// or over a call the two trust, matching digits mean nobody stands between
    /// them.
    ///
    /// Only the key pinned for the peer counts, never one a key package or
    /// anything else the server serves carries: the pin is what every message
    /// from them is checked against, so it is what the users have to verify.
    ///
    /// # Arguments
    ///
    /// * `peer_user_uuid` - The other user's UUID, in canonical hyphenated
    ///   lowercase form.
    ///
    /// # Returns
    ///
    /// * `Result<Option<String>, MlsError>` - The safety number, or `None` when
    ///   no key is pinned for them.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If the stored pin fails authentication.
    pub fn safety_number(&self, peer_user_uuid: String) -> Result<Option<String>, MlsError> {
        Ok(self
            .pins
            .pinned_key(&peer_user_uuid)?
            .map(|peer_signature_key| {
                safety_number(
                    &self.user_uuid,
                    self.signature_key_pair.public.as_ref(),
                    &peer_user_uuid,
                    &peer_signature_key,
                )
            }))
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
    /// only evidence that something changed. Call it only once the user has
    /// confirmed with the peer, out of band, that their key really changed,
    /// never automatically in response to the error, which would reduce
    /// pinning to no protection at all. The key pinned next is theirs to verify
    /// again, with [`safety_number`](Self::safety_number).
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

/// A Welcome joined in memory and checked, see [`MlsClient::open_welcome`].
struct OpenedWelcome {
    group: Group<DuckCountMlsConfig>,
    committer_user_uuid: String,
    welcome_payload: Option<Vec<u8>>,
}

impl MlsClient {
    /// Joins the group `welcome` is for in memory, through every check a join
    /// makes whoever the host expects in it, the group's id checked against
    /// the one derived for `expected_group_uuid`.
    ///
    /// It changes nothing, whatever it returns: mls-rs stores nothing, and
    /// spends no key package, until `write_to_storage`, and the identity
    /// provider it checks every member with only reads their pins. That is
    /// what lets [`inspect_welcome`](Self::inspect_welcome) and
    /// [`join_group`](Self::join_group) share it.
    ///
    /// `client` is the client, locked by the caller for as long as it needs
    /// the group.
    fn open_welcome(
        &self,
        client: &Client<DuckCountMlsConfig>,
        welcome: Vec<u8>,
        expected_group_uuid: Option<&str>,
    ) -> Result<OpenedWelcome, MlsError> {
        let welcome = MlsMessage::from_bytes(&welcome).map_err(|_| MlsError::InvalidMessage)?;

        let (group, new_member_info) = client.join_group(None, &welcome, None)?;

        if group.current_epoch() > MAX_JOINED_EPOCH {
            return Err(MlsError::InvalidMessage);
        }

        // Before the store is asked about the group: the id is the key of the
        // stored group, and of the record of its deletion, which outlives it.
        // Whoever wrote the Welcome chose it, and only its being derived from
        // the group the host expects keeps them from giving a channel or a
        // contact request the id of a group the API holds, or a Welcome to one
        // group the id of another, or making it as large as they like.
        group_id::check(
            group.group_id(),
            expected_group_uuid,
            &new_member_info.group_info_extensions,
        )?;

        // Counted from the tree the Welcome carries, the only word there is on
        // who is in the group, and its author's to write.
        if group.roster().members_iter().count() > MAX_GROUP_MEMBERS {
            return Err(MlsError::TooManyMembers);
        }

        if self
            .group_states
            .has_held(group.group_id(), group.current_epoch())?
        {
            return Err(MlsError::GroupAlreadyJoined);
        }

        // Whoever wrote the Welcome: mls-rs checked its GroupInfo against the
        // signature key of this leaf, which the identity provider checked
        // against the key pinned for them, if any.
        let committer = group.roster().member_with_index(new_member_info.sender)?;
        let committer_user_uuid = user_uuid_from(&committer.signing_identity.credential)?;

        Ok(OpenedWelcome {
            group,
            committer_user_uuid,
            welcome_payload: welcome_payload(&new_member_info.group_info_extensions),
        })
    }

    /// Deletes the group stored under `mls_group_id`, if this device holds it,
    /// as [`delete_group`](Self::delete_group) says.
    ///
    /// `client` is the client, locked by the caller.
    fn delete_held_group(
        &self,
        client: &Client<DuckCountMlsConfig>,
        mls_group_id: &[u8],
    ) -> Result<(), MlsError> {
        // A group no longer stored was either deleted already, and keeps the
        // record written then, with the epoch it was at, or never joined, and
        // has no Welcome to refuse. One whose state no longer opens, damaged
        // or written by another version of mls-rs, goes all the same, as
        // nothing else would ever remove it: not knowing the epoch it was at,
        // the record refuses every Welcome to it until pruning forgets it.
        // Only a storage failure says nothing of the state, and is worth
        // trying again.
        let epoch = match client.load_group(mls_group_id).map_err(MlsError::from) {
            Ok(group) => group.current_epoch(),
            Err(MlsError::GroupNotFound) => return Ok(()),
            Err(error @ MlsError::StorageFailed(_)) => return Err(error),
            Err(_) => u64::MAX,
        };

        // Holding none, it can open no Welcome, and the record may go at once.
        let openable_until = self.key_packages.latest_expiration()?.unwrap_or(0);

        self.group_states
            .delete_group(mls_group_id, openable_until, epoch)
    }

    /// The index of the leaf this user holds in the tree `group_info`
    /// carries, once it has passed every check
    /// [`rejoin_group`](Self::rejoin_group) makes before it builds anything.
    ///
    /// It changes nothing: the identity provider it checks the signer with
    /// only reads their pin.
    ///
    /// `client` is the client, locked by the caller.
    fn rejoined_leaf(
        &self,
        client: &Client<DuckCountMlsConfig>,
        group_info: &MlsMessage,
        expected_group_uuid: &str,
        expected_epoch: u64,
        mut expected_members: Vec<String>,
    ) -> Result<u32, MlsError> {
        let info = group_info.as_group_info().ok_or(MlsError::InvalidMessage)?;
        let context = info.group_context();

        // Every GroupInfo `MlsGroup::rejoin_group_info` exports carries both:
        // the tree, which the server does not store, and the key the Commit
        // is built with.
        if !info.extensions().has_extension(ExtensionType::EXTERNAL_PUB) {
            return Err(MlsError::InvalidMessage);
        }

        let tree = info
            .extensions()
            .get_as::<RatchetTreeExt>()
            .map_err(|_| MlsError::InvalidMessage)?
            .ok_or(MlsError::InvalidMessage)?;

        group_id::check(
            &context.group_id,
            Some(expected_group_uuid),
            info.extensions(),
        )?;

        // The one the server stores the next Commit for: a GroupInfo of any
        // other makes a Commit the server refuses, and members too.
        if context.epoch != expected_epoch || context.epoch > MAX_JOINED_EPOCH {
            return Err(MlsError::InvalidMessage);
        }

        let roster = tree.tree_data.roster();

        if roster.members_iter().count() > MAX_GROUP_MEMBERS {
            return Err(MlsError::TooManyMembers);
        }

        // Before the members are read: they are the signer's word, the tree
        // being covered by the signature, as all the GroupInfo says is.
        let signer = roster
            .member_with_index(info.sender())
            .map_err(|_| MlsError::UntrustedGroupInfo)?
            .signing_identity;

        if !self.trusts(&signer)? {
            return Err(MlsError::UntrustedGroupInfo);
        }

        client
            .validate_group_info(group_info, &signer)
            .map_err(|error| match error {
                mls_rs::error::MlsError::InvalidSignature => MlsError::UntrustedGroupInfo,
                error => error.into(),
            })?;

        let mut own_leaf = None;
        let mut peers = Vec::new();

        for member in roster.members_iter() {
            let user_uuid = user_uuid_from(&member.signing_identity.credential)?;

            if user_uuid == self.user_uuid {
                own_leaf = Some(member);
            } else {
                peers.push(user_uuid);
            }
        }

        // Exact, as in `expected_peers`: a tree in which two leaves share an
        // identity is refused as the Commit is built.
        peers.sort_unstable();
        expected_members.sort_unstable();

        if peers != expected_members {
            return Err(MlsError::UnexpectedMembers);
        }

        // The leaf the Commit removes, which members take only for a leaf
        // naming this user under the key the leaf the Commit seats holds,
        // this device's.
        own_leaf
            .filter(|member| {
                member.signing_identity.signature_key == self.signature_key_pair.public
            })
            .map(|member| member.index)
            .ok_or(MlsError::UnexpectedMembers)
    }

    /// Whether `signer` is somebody this device takes a GroupInfo from: this
    /// user under their own signature key, which only their devices hold, or
    /// a member under the key pinned for them.
    ///
    /// # Errors
    ///
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If a stored pin fails authentication.
    fn trusts(&self, signer: &SigningIdentity) -> Result<bool, MlsError> {
        let Ok(user_uuid) = user_uuid_from(&signer.credential) else {
            return Ok(false);
        };

        if user_uuid == self.user_uuid {
            return Ok(signer.signature_key == self.signature_key_pair.public);
        }

        Ok(self.pins.pinned_key(&user_uuid)?.as_deref() == Some(signer.signature_key.as_ref()))
    }

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

        let pruned = self.key_packages.prune_expired(expired_before)?;

        // By the same expiration: a record goes only once every key package it
        // was deleted alongside has gone just now.
        self.group_states.prune_deleted_groups(expired_before)?;

        Ok(pruned)
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
