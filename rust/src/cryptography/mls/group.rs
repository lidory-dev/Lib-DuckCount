//! One MLS group, and the discipline for changing it.
//!
//! # Applying a commit at the right moment
//!
//! Every method that produces a Commit leaves it *pending*: the local group has
//! not moved to the new epoch yet. The host sends the bytes to the server and
//! then reports what happened:
//!
//! - accepted → [`apply_pending_commit`](MlsGroup::apply_pending_commit);
//! - rejected → [`clear_pending_commit`](MlsGroup::clear_pending_commit).
//!
//! Applying before the server accepts would strand the local client an epoch
//! ahead of everybody else, unable to read anything they send.
//!
//! Pending commits are persisted, so a crash between sending and confirming is
//! recoverable rather than fatal: on restart [`has_pending_commit`](MlsGroup::has_pending_commit)
//! is still true, and the host resolves it the same way once it knows the
//! request's fate.
//!
//! # Concurrent commits
//!
//! MLS allows exactly one Commit per epoch, and the DuckCount API does not
//! serialise them, it stores whatever arrives. Two members committing at once
//! would fork the group, so clients converge on one rule: **the first Commit in
//! server order wins.**
//!
//! That order is observable and identical for everyone, since
//! `GET /groups/{uuid}/messages` returns rows by ascending id. Processing them
//! strictly in that order is therefore all a client has to do. If a Commit
//! arrives while this client has one pending, applying the incoming one clears
//! the pending commit automatically; the local change simply did not happen and
//! has to be reissued. Add and remove are owner-only server-side, so the case
//! that actually arises is two members calling [`update`](MlsGroup::update).

use std::sync::{Mutex, MutexGuard};

use mls_rs::group::{ApplicationMessageDescription, CommitEffect, ContentType, ReceivedMessage};
use mls_rs::{Group, MlsMessage, MlsMessageDescription, WireFormat};
use mls_rs_core::crypto::SignaturePublicKey;

use crate::cryptography::mls::{
    MlsError,
    config::DuckCountMlsConfig,
    identity::{credential::user_uuid_from, fingerprint::fingerprint},
    invitation::{match_welcomes, pin_invitees, validate_invitees},
    storage::identity_pin::IdentityPinStore,
    types::{
        AddMembersOutput, ApplicationMessage, InviteeKeyPackage, MemberInfo, ProcessedMessage,
    },
};

/// A group this user belongs to.
///
/// # Threading
///
/// Operations on one group are serialised: they mutate stored state, and
/// interleaving them would corrupt it.
#[derive(uniffi::Object)]
pub struct MlsGroup {
    group: Mutex<Group<DuckCountMlsConfig>>,
    pins: IdentityPinStore,
}

#[uniffi::export]
impl MlsGroup {
    /// The group's MLS identifier.
    ///
    /// # Errors
    ///
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    pub fn mls_group_id(&self) -> Result<Vec<u8>, MlsError> {
        Ok(self.locked()?.group_id().to_vec())
    }

    /// The epoch the group is currently in.
    ///
    /// # Errors
    ///
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    pub fn epoch(&self) -> Result<u64, MlsError> {
        Ok(self.locked()?.current_epoch())
    }

    /// The group's current members.
    ///
    /// UUIDs come from each member's credential, not from anything the server
    /// said, so this is the authoritative answer to who is in the group.
    ///
    /// # Errors
    ///
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::InvalidCredential` - If a member's credential is malformed.
    pub fn members(&self) -> Result<Vec<MemberInfo>, MlsError> {
        let group = self.locked()?;

        group
            .roster()
            .members()
            .iter()
            .map(|member| {
                Ok(MemberInfo {
                    user_uuid: user_uuid_from(&member.signing_identity.credential)?,
                    fingerprint: fingerprint(member.signing_identity.signature_key.as_ref()),
                })
            })
            .collect()
    }

    /// Pins to each of `expected_members` the signature key they hold in this
    /// group, provided it still holds exactly this user and them.
    ///
    /// This is the host saying it trusts them, for a group it joined without
    /// pinning anybody, see [`MlsClient::join_group`]: for a contact request,
    /// when the user accepts it. The roster is checked again because it can
    /// have changed since the join, and a member who committed others in must
    /// not get to decide who they are.
    ///
    /// [`MlsClient::join_group`]: crate::cryptography::mls::client::MlsClient::join_group
    ///
    /// # Errors
    ///
    /// * `MlsError::UnexpectedMembers` - If the members are no longer exactly
    ///   this user and `expected_members`.
    /// * `MlsError::IdentityKeyMismatch` - If a different key is pinned for one
    ///   of them by now.
    /// * `MlsError::InvalidCredential` - If a member's credential is malformed.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If a stored pin fails authentication.
    pub fn pin_members(&self, expected_members: Vec<String>) -> Result<(), MlsError> {
        let group = self.locked()?;

        pin_peers(&self.pins, &expected_peers(&group, expected_members)?)
    }

    /// Whether a Commit is waiting to be applied or discarded.
    ///
    /// After a restart this being true means a Commit was produced but its fate
    /// was never recorded. The host has to establish whether the server accepted
    /// it before calling [`apply_pending_commit`](Self::apply_pending_commit) or
    /// [`clear_pending_commit`](Self::clear_pending_commit).
    ///
    /// # Errors
    ///
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    pub fn has_pending_commit(&self) -> Result<bool, MlsError> {
        Ok(self.locked()?.has_pending_commit())
    }

    /// Adds members to the group.
    ///
    /// Produces the Commit for the members already in the group and one Welcome
    /// per new member, exactly the body of `POST /groups/{uuid}/members`. The
    /// Commit stays pending until the server accepts it. Each new member's
    /// signature key is pinned to them either way.
    ///
    /// # Arguments
    ///
    /// * `invitees` - The user UUID and fetched key package of each new member.
    ///
    /// # Returns
    ///
    /// * `Result<AddMembersOutput, MlsError>` - The Commit and the Welcomes.
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
    /// * `MlsError::ProtocolFailed` - If a Commit is already pending, or the
    ///   Commit cannot be built.
    /// * `MlsError::StorageFailed` - If the pending state cannot be stored.
    pub fn add_members(
        &self,
        invitees: Vec<InviteeKeyPackage>,
    ) -> Result<AddMembersOutput, MlsError> {
        let invitees = validate_invitees(invitees)?;

        let mut group = self.locked()?;

        let mut commit_builder = group.commit_builder();

        for invitee in &invitees {
            commit_builder = commit_builder.add_member(invitee.key_package.clone())?;
        }

        let commit_output = commit_builder.build()?;

        // Matched before anything is persisted, as in `MlsClient::create_group`.
        let welcomes = match_welcomes(&commit_output.welcome_messages, &invitees)?;

        pin_invitees(&self.pins, &invitees)?;

        group.write_to_storage()?;

        Ok(AddMembersOutput {
            commit: commit_output.commit_message.to_bytes()?,
            welcomes,
        })
    }

    /// Removes members from the group.
    ///
    /// The Commit is for `DELETE /groups/{uuid}/members` and stays pending until
    /// the server accepts it. The server delivers it to the removed members too,
    /// which is what lets their clients see they are out.
    ///
    /// # Arguments
    ///
    /// * `user_uuids` - The users to remove.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, MlsError>` - The Commit to distribute.
    ///
    /// # Errors
    ///
    /// * `MlsError::MemberNotFound` - If a UUID is not a current member.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If a Commit is already pending, the list is
    ///   empty, or it names this user (leaving is
    ///   [`propose_self_remove`](Self::propose_self_remove), not a removal).
    /// * `MlsError::StorageFailed` - If the pending state cannot be stored.
    pub fn remove_members(&self, user_uuids: Vec<String>) -> Result<Vec<u8>, MlsError> {
        let mut group = self.locked()?;

        // Indices are resolved up front: the roster cannot be queried once the
        // commit builder holds a mutable borrow of the group.
        let indices = user_uuids
            .iter()
            .map(|user_uuid| {
                group
                    .member_with_identity(user_uuid.as_bytes())
                    .map(|member| member.index)
                    .map_err(|_| MlsError::MemberNotFound(user_uuid.clone()))
            })
            .collect::<Result<Vec<_>, _>>()?;

        let mut commit_builder = group.commit_builder();

        for index in indices {
            commit_builder = commit_builder.remove_member(index)?;
        }

        let commit_output = commit_builder.build()?;

        group.write_to_storage()?;

        commit_output.commit_message.to_bytes().map_err(Into::into)
    }

    /// Rotates this member's own key material.
    ///
    /// Nothing about the membership changes; what changes is that any secret an
    /// attacker may have captured stops being useful, which is the whole point
    /// of doing it periodically. There is no dedicated API route, send the
    /// Commit through `POST /groups/{uuid}/messages` like any other message.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, MlsError>` - The Commit to distribute.
    ///
    /// # Errors
    ///
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If a Commit is already pending, or the
    ///   Commit cannot be built.
    /// * `MlsError::StorageFailed` - If the pending state cannot be stored.
    pub fn update(&self) -> Result<Vec<u8>, MlsError> {
        let mut group = self.locked()?;

        let commit_output = group.commit(Vec::new())?;

        group.write_to_storage()?;

        commit_output.commit_message.to_bytes().map_err(Into::into)
    }

    /// Proposes this user's own removal from the group.
    ///
    /// # Warning
    ///
    /// This returns a **proposal**, not a Commit. RFC 9420 does not let a member
    /// commit their own removal, so the user stays in the group until a
    /// remaining member commits this proposal after receiving it. The DuckCount
    /// API calls the corresponding field a "commit" in
    /// `PUT /users/{uuid}/deletion`, but it relays the bytes without inspecting
    /// them, so the proposal travels there unchanged.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, MlsError>` - The proposal to distribute.
    ///
    /// # Errors
    ///
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If this user has already proposed their
    ///   own removal in this epoch.
    /// * `MlsError::StorageFailed` - If the state cannot be stored.
    pub fn propose_self_remove(&self) -> Result<Vec<u8>, MlsError> {
        let mut group = self.locked()?;

        let proposal = group.propose_self_remove(Vec::new())?;

        group.write_to_storage()?;

        proposal.to_bytes().map_err(Into::into)
    }

    /// Encrypts a payload for the group.
    ///
    /// The payload is opaque to MLS: DuckCount uses it to broadcast per-expense
    /// encryption keys, but anything fits.
    ///
    /// # Arguments
    ///
    /// * `payload` - The plaintext to encrypt.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, MlsError>` - The ciphertext for `POST /groups/{uuid}/messages`.
    ///
    /// # Errors
    ///
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If proposals are pending and must be
    ///   committed first, or encryption fails.
    /// * `MlsError::StorageFailed` - If the advanced state cannot be stored.
    pub fn encrypt_application_message(&self, payload: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        let mut group = self.locked()?;

        let message = group.encrypt_application_message(&payload, Vec::new())?;

        group.write_to_storage()?;

        message.to_bytes().map_err(Into::into)
    }

    /// Processes one message drained from the group's queue.
    ///
    /// A Commit is applied and a Proposal kept, whichever member sent them. A
    /// group whose members never change is read with
    /// [`read_application_message`](Self::read_application_message) instead.
    ///
    /// # Warning
    ///
    /// Messages must be processed in the order the server returned them
    /// (ascending id). Out of order, a Commit will be rejected and the group
    /// left behind (see the module documentation on concurrent commits).
    ///
    /// # Arguments
    ///
    /// * `message` - The ciphertext from `GET /groups/{uuid}/messages`.
    ///
    /// # Returns
    ///
    /// * `Result<ProcessedMessage, MlsError>` - What the message turned out to be.
    ///
    /// # Errors
    ///
    /// * `MlsError::InvalidMessage` - If the message cannot be parsed, or was not
    ///   encrypted to the group.
    /// * `MlsError::IdentityKeyMismatch` - If a member's signature key differs
    ///   from the one pinned for them.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If the message belongs to another group, is
    ///   for an epoch too old to still be retained, or fails authentication.
    /// * `MlsError::StorageFailed` - If the resulting state cannot be stored.
    pub fn process_incoming_message(&self, message: Vec<u8>) -> Result<ProcessedMessage, MlsError> {
        let message = MlsMessage::from_bytes(&message).map_err(|_| MlsError::InvalidMessage)?;

        // Members encrypt their commits and proposals as well as their application
        // messages (see `mls_rules` in config.rs), so one never sends a PublicMessage.
        // What arrives as one comes from outside the group: mls-rs takes in an Add
        // proposal from a would-be member, signed by nothing but the key package it
        // carries and needing only the group id and epoch, which travel in the clear.
        // Kept pending, it would stop the group sending anything until committed.
        if message.wire_format() != WireFormat::PrivateMessage {
            return Err(MlsError::InvalidMessage);
        }

        let mut group = self.locked()?;

        let received = group.process_incoming_message(message)?;

        let processed = match received {
            ReceivedMessage::ApplicationMessage(description) => {
                let read = self.application_message(&group, &description)?;

                ProcessedMessage::ApplicationMessage {
                    sender_user_uuid: read.sender_user_uuid,
                    payload: read.payload,
                    is_sender_pinned: read.is_sender_pinned,
                }
            }
            ReceivedMessage::Commit(description) => ProcessedMessage::Commit {
                // Absent when the committer removed themselves: by the time the
                // Commit is applied they are no longer on the roster.
                committer_user_uuid: Self::member_uuid(&group, description.committer),
                epoch: group.current_epoch(),
                removed_self: matches!(description.effect, CommitEffect::Removed { .. }),
            },
            ReceivedMessage::Proposal(description) => ProcessedMessage::Proposal {
                sender_user_uuid: match description.sender {
                    mls_rs::group::ProposalSender::Member(index) => {
                        Self::member_uuid(&group, index)
                    }
                    _ => None,
                },
            },
            _ => ProcessedMessage::Ignored,
        };

        group.write_to_storage()?;

        Ok(processed)
    }

    /// Reads one application message, refusing anything else before it can
    /// change the group.
    ///
    /// For a group whose members are settled once it is created or joined,
    /// such as one shared with a single peer. A member could otherwise commit
    /// somebody else in behind the roster [`MlsClient::join_group`] checked, or
    /// leave a Proposal pending, which stops the group sending until somebody
    /// commits it.
    ///
    /// [`MlsClient::join_group`]: crate::cryptography::mls::client::MlsClient::join_group
    ///
    /// # Arguments
    ///
    /// * `message` - The ciphertext a peer sent to the group.
    ///
    /// # Returns
    ///
    /// * `Result<ApplicationMessage, MlsError>` - The plaintext and its sender.
    ///
    /// # Errors
    ///
    /// * `MlsError::InvalidMessage` - If the message cannot be parsed, or is
    ///   not an application message encrypted to the group.
    /// * `MlsError::InvalidCredential` - If the sender's credential is malformed.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If the message belongs to another group, is
    ///   for an epoch too old to still be retained, or fails authentication.
    /// * `MlsError::StorageFailed` - If the sender's pin cannot be read, or the
    ///   resulting state cannot be stored.
    /// * `MlsError::StorageIntegrityFailed` - If the sender's stored pin fails
    ///   authentication.
    pub fn read_application_message(
        &self,
        message: Vec<u8>,
    ) -> Result<ApplicationMessage, MlsError> {
        let message = MlsMessage::from_bytes(&message).map_err(|_| MlsError::InvalidMessage)?;

        // mls-rs applies a Commit and keeps a Proposal as it reads them, so what
        // the message is has to be known first. A PrivateMessage names its
        // content type in the clear, and its content is read as the type named:
        // a member who labels anything else an application message only sends
        // an application message, and a relay that relabels one fails its
        // authentication. This also refuses a PublicMessage, see
        // `process_incoming_message`.
        let is_application_message = matches!(
            message.description(),
            MlsMessageDescription::PrivateProtocolMessage {
                content_type: ContentType::Application,
                ..
            }
        );

        if !is_application_message {
            return Err(MlsError::InvalidMessage);
        }

        let mut group = self.locked()?;

        // Only there for the match to be exhaustive, the content being read as
        // the type checked above. It returns before anything is stored all the
        // same.
        let ReceivedMessage::ApplicationMessage(description) =
            group.process_incoming_message(message)?
        else {
            return Err(MlsError::ProtocolFailed(
                "An application message was read as something else.".to_string(),
            ));
        };

        let read = self.application_message(&group, &description)?;

        group.write_to_storage()?;

        Ok(read)
    }

    /// Applies the pending Commit, after the server accepted it.
    ///
    /// # Errors
    ///
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If no Commit is pending.
    /// * `MlsError::StorageFailed` - If the new state cannot be stored.
    pub fn apply_pending_commit(&self) -> Result<(), MlsError> {
        let mut group = self.locked()?;

        group.apply_pending_commit()?;
        group.write_to_storage()?;

        Ok(())
    }

    /// Discards the pending Commit, after the server rejected it.
    ///
    /// The group stays in its current epoch, and the change can be reissued.
    ///
    /// # Errors
    ///
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::StorageFailed` - If the state cannot be stored.
    pub fn clear_pending_commit(&self) -> Result<(), MlsError> {
        let mut group = self.locked()?;

        group.clear_pending_commit();
        group.write_to_storage()?;

        Ok(())
    }
}

/// Deliberately opaque: the group holds the epoch secrets protecting every
/// message in it, none of which may reach a log.
impl std::fmt::Debug for MlsGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsGroup").finish_non_exhaustive()
    }
}

impl MlsGroup {
    /// Wraps a loaded mls-rs group. `pins` is where [`add_members`](Self::add_members)
    /// and [`pin_members`](Self::pin_members) record the keys they pin.
    pub(crate) fn new(group: Group<DuckCountMlsConfig>, pins: IdentityPinStore) -> Self {
        MlsGroup {
            group: Mutex::new(group),
            pins,
        }
    }

    /// The application message `description` describes, with who sent it.
    fn application_message(
        &self,
        group: &Group<DuckCountMlsConfig>,
        description: &ApplicationMessageDescription,
    ) -> Result<ApplicationMessage, MlsError> {
        let sender = group
            .member_at_index(description.sender_index)
            .ok_or_else(|| {
                MlsError::ProtocolFailed(
                    "An application message came from an unknown member.".to_string(),
                )
            })?;

        let sender_user_uuid = user_uuid_from(&sender.signing_identity.credential)?;

        let is_sender_pinned = self.pins.pinned_key(&sender_user_uuid)?.as_deref()
            == Some(sender.signing_identity.signature_key.as_ref());

        Ok(ApplicationMessage {
            sender_user_uuid,
            payload: description.data().to_vec(),
            is_sender_pinned,
        })
    }

    /// Takes the group lock.
    fn locked(&self) -> Result<MutexGuard<'_, Group<DuckCountMlsConfig>>, MlsError> {
        self.group.lock().map_err(|_| MlsError::LockPoisoned)
    }

    /// The group's GroupInfo, tree included, for a test to play somebody outside it with.
    #[cfg(test)]
    pub(crate) fn group_info(&self) -> MlsMessage {
        self.locked().unwrap().group_info_message(true).unwrap()
    }

    /// Resolves a leaf index to the user UUID at that position, if anyone is
    /// still there.
    fn member_uuid(group: &Group<DuckCountMlsConfig>, index: u32) -> Option<String> {
        group
            .member_at_index(index)
            .and_then(|member| user_uuid_from(&member.signing_identity.credential).ok())
    }
}

/// The members of `group` other than this user, with their signature keys,
/// provided they are exactly `expected_members`.
///
/// Comparing sorted lists is exact because mls-rs refuses a tree in which two
/// leaves share an identity, so each UUID appears on the roster once.
///
/// # Errors
///
/// * `MlsError::UnexpectedMembers` - If the members differ from the expected ones.
/// * `MlsError::InvalidCredential` - If a member's credential is malformed.
pub(crate) fn expected_peers(
    group: &Group<DuckCountMlsConfig>,
    mut expected_members: Vec<String>,
) -> Result<Vec<(String, SignaturePublicKey)>, MlsError> {
    let mut peers = Vec::new();

    for member in group.roster().members() {
        if member.index != group.current_member_index() {
            let user_uuid = user_uuid_from(&member.signing_identity.credential)?;

            peers.push((user_uuid, member.signing_identity.signature_key));
        }
    }

    let mut peer_uuids = peers
        .iter()
        .map(|(user_uuid, _)| user_uuid.clone())
        .collect::<Vec<_>>();

    peer_uuids.sort_unstable();
    expected_members.sort_unstable();

    if peer_uuids != expected_members {
        return Err(MlsError::UnexpectedMembers);
    }

    Ok(peers)
}

/// Pins each of `peers` to the signature key paired with them.
///
/// # Errors
///
/// * `MlsError::IdentityKeyMismatch` - If a different key is pinned for one of them.
/// * `MlsError::StorageFailed` - If the host storage fails.
/// * `MlsError::StorageIntegrityFailed` - If a stored pin fails authentication.
pub(crate) fn pin_peers(
    pins: &IdentityPinStore,
    peers: &[(String, SignaturePublicKey)],
) -> Result<(), MlsError> {
    peers.iter().try_for_each(|(user_uuid, signature_key)| {
        pins.verify_or_pin(user_uuid, signature_key.as_ref())
    })
}
