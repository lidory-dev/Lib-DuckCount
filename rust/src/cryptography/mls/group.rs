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
//! has to be reissued.
//!
//! In a group the DuckCount API holds, only its creator commits, and every
//! member refuses a Commit from anybody else, see
//! [`process_incoming_message`](MlsGroup::process_incoming_message). A refused
//! Commit applies nothing and clears nothing, a Commit of the creator's still
//! pending included, so the creator's never lose to another member's: what
//! can still compete is two members of a group with no such rule calling
//! [`update`](MlsGroup::update).

use std::sync::{Mutex, MutexGuard};

use mls_rs::group::proposal::Proposal;
use mls_rs::group::{ApplicationMessageDescription, CommitEffect, ContentType, ReceivedMessage};
use mls_rs::{Group, MlsMessage, MlsMessageDescription, WireFormat};
use mls_rs_core::crypto::SignaturePublicKey;

use crate::cryptography::mls::{
    MAX_GROUP_MEMBERS, MlsError,
    config::{DuckCountMlsConfig, with_allowed_committer},
    identity::{credential::user_uuid_from, fingerprint::fingerprint},
    invitation::{pin_invitees, shared_welcome, validate_invitees, welcome_payload_extensions},
    storage::{
        group_state::{Allowance, with_allowance},
        identity_pin::IdentityPinStore,
    },
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
                let user_uuid = user_uuid_from(&member.signing_identity.credential)?;

                Ok(MemberInfo {
                    fingerprint: fingerprint(
                        &user_uuid,
                        member.signing_identity.signature_key.as_ref(),
                    ),
                    user_uuid,
                })
            })
            .collect()
    }

    /// Pins to each of `expected_members` the signature key they hold in this
    /// group, provided it still holds exactly this user and them.
    ///
    /// This is the host saying it trusts them, for a group it joined without
    /// pinning anybody, see [`MlsClient::join_group`]: for a contact request,
    /// once the server has taken the user's acceptance. The roster is checked
    /// again because it can have changed since the join, and a member who
    /// committed others in must not get to decide who they are.
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

    /// Pins to `user_uuid` the signature key they hold in this group, and
    /// nobody else.
    ///
    /// This is the host taking the group's word for one of its members, in a
    /// group the DuckCount API holds: before it sends a contact request to a
    /// member who is not a contact, so that the key package the server serves
    /// for them is checked against this key by [`MlsClient::create_group`],
    /// and refused if it carries another.
    ///
    /// The group's word is worth more than that key package, which the server
    /// serves on nobody's word but its own, because it is its creator's, and
    /// this device trusts them. The host joins such a group only from a
    /// Welcome its creator wrote, once it has pinned them, their leaf in it
    /// checked against that pin, see [`MlsClient::join_group`], so the tree it
    /// opens is the creator's word. Every change to its members since is a
    /// Commit of theirs, its members refusing anybody else's and every
    /// Proposal, see [`process_incoming_message`](Self::process_incoming_message).
    /// And the creator's host seats only contacts it has pinned, each checked
    /// against that pin as [`MlsClient::create_group`] or
    /// [`add_members`](Self::add_members) adds them. Both pin anybody not
    /// pinned yet from whichever key package the server served, and a member
    /// seated that way would hold a key resting on the server's word alone,
    /// which is why a host never seats one. The key a member holds in a group
    /// this device joined is the one its creator vouched for.
    ///
    /// It pins, and does not just check: the key stays pinned even if the
    /// request then fails. A pin is what every later appearance of theirs is
    /// checked against, a key package, a Welcome or Commit seating them, or
    /// their acceptance; it also makes a message of theirs read as from a
    /// pinned sender, and their safety number is made from it. Left behind,
    /// this one is harmless: it is the key their creator vouched for, and the
    /// one a request that went out would have left pinned,
    /// [`MlsClient::create_group`] pinning its invitees. They are then pinned
    /// as anybody the user sent a request to is, before they answer it, and
    /// the host goes by what they are to the user, not by the pin. A key
    /// already pinned for them is checked instead, and left as it was.
    ///
    /// [`MlsClient::join_group`]: crate::cryptography::mls::client::MlsClient::join_group
    /// [`MlsClient::create_group`]: crate::cryptography::mls::client::MlsClient::create_group
    ///
    /// # Arguments
    ///
    /// * `user_uuid` - The member's UUID, in canonical hyphenated lowercase
    ///   form.
    ///
    /// # Errors
    ///
    /// * `MlsError::UnexpectedMembers` - If no member of the group but this
    ///   user holds `user_uuid`, which is the case when it is this user's own.
    ///   Nobody is pinned.
    /// * `MlsError::IdentityKeyMismatch` - If a different key is pinned for
    ///   them already. It stays pinned.
    /// * `MlsError::InvalidCredential` - If a member's credential is malformed.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If a stored pin fails authentication.
    pub fn pin_member(&self, user_uuid: String) -> Result<(), MlsError> {
        let group = self.locked()?;

        // The one leaf holding it, if any: mls-rs refuses a tree in which two
        // leaves share an identity.
        let (_, signature_key) = peers(&group)?
            .into_iter()
            .find(|(peer_uuid, _)| *peer_uuid == user_uuid)
            .ok_or(MlsError::UnexpectedMembers)?;

        self.pins.verify_or_pin(&user_uuid, signature_key.as_ref())
    }

    /// Checks each of `expected_members` against the key pinned for them, if
    /// any, provided the group still holds exactly this user and them. Pins
    /// nobody.
    ///
    /// What [`pin_members`](Self::pin_members) checks, for a host about to
    /// trust them with something before it is known whether that lands: for
    /// a contact request, the acceptance the host sends. The request's sender
    /// is pinned only once the server has taken it: pinned before, they would
    /// stay pinned by an acceptance that was never taken.
    ///
    /// # Errors
    ///
    /// * `MlsError::UnexpectedMembers` - If the members are no longer exactly
    ///   this user and `expected_members`.
    /// * `MlsError::IdentityKeyMismatch` - If a different key is pinned for one
    ///   of them.
    /// * `MlsError::InvalidCredential` - If a member's credential is malformed.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::StorageFailed` - If the host storage fails.
    /// * `MlsError::StorageIntegrityFailed` - If a stored pin fails authentication.
    pub fn verify_members(&self, expected_members: Vec<String>) -> Result<(), MlsError> {
        let group = self.locked()?;

        expected_peers(&group, expected_members)?
            .iter()
            .try_for_each(|(user_uuid, signature_key)| {
                self.pins.verify(user_uuid, signature_key.as_ref())
            })
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
    /// Produces the Commit for the members already in the group and the one
    /// Welcome every new member joins from, exactly the body of
    /// `POST /groups/{uuid}/members`. The Commit stays pending until the server
    /// accepts it. Each new member's signature key is pinned to them either way.
    ///
    /// # Arguments
    ///
    /// * `invitees` - The user UUID and fetched key package of each new member.
    /// * `welcome_payload` - What to hand the new members, if anything, as
    ///   [`MlsClient::create_group`] does. The members already in the group
    ///   can read it too.
    ///
    /// [`MlsClient::create_group`]: crate::cryptography::mls::client::MlsClient::create_group
    ///
    /// # Returns
    ///
    /// * `Result<AddMembersOutput, MlsError>` - The Commit and the Welcome.
    ///
    /// # Errors
    ///
    /// * `MlsError::TooManyMembers` - If the group would hold more than
    ///   [`MAX_GROUP_MEMBERS`] members. Nothing is built.
    /// * `MlsError::UnexpectedMembers` - If a member's proposal to add somebody
    ///   is held for this epoch, which the Commit would add as well. Nothing is
    ///   built.
    /// * `MlsError::GroupStateTooLarge` - If the group would grow past the most a
    ///   group may store.
    /// * `MlsError::UnusableKeyPackages` - Naming every invitee whose key
    ///   package cannot be used, see
    ///   [`validate_invitees`](crate::cryptography::mls::invitation::validate_invitees).
    ///   Nothing is built.
    /// * `MlsError::IdentityKeyMismatch` - If an invitee's signature key differs
    ///   from the one pinned for them.
    /// * `MlsError::UnmatchedWelcome` - If an invitee has no secret in the Welcome.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If `invitees` is empty (nothing is built),
    ///   a Commit is already pending, or the Commit cannot be built.
    /// * `MlsError::StorageFailed` - If the pending state cannot be stored.
    pub fn add_members(
        &self,
        invitees: Vec<InviteeKeyPackage>,
        welcome_payload: Option<Vec<u8>>,
    ) -> Result<AddMembersOutput, MlsError> {
        let mut group = self.locked()?;

        // Before anything is built: refused once built, the Commit would stay
        // pending in memory, and stop this group making any other.
        if invitees.is_empty() {
            return Err(MlsError::ProtocolFailed(
                "A commit adding nobody produces no Welcome.".to_string(),
            ));
        }

        // mls-rs commits every proposal held for the epoch along with the
        // invitees, and any member can have proposed adding somebody: the
        // Commit would add them too, uncounted, and the Welcome open for them.
        if group
            .get_cached_proposals()
            .iter()
            .any(|cached| matches!(cached.proposal(), Proposal::Add(_)))
        {
            return Err(MlsError::UnexpectedMembers);
        }

        let member_count = member_count(&group) + invitees.len();

        if member_count > MAX_GROUP_MEMBERS {
            return Err(MlsError::TooManyMembers);
        }

        let invitees = validate_invitees(invitees)?;

        let mut commit_builder = group
            .commit_builder()
            .set_group_info_ext(welcome_payload_extensions(welcome_payload));

        for invitee in &invitees {
            commit_builder = commit_builder.add_member(invitee.key_package.clone())?;
        }

        let commit_output = commit_builder.build()?;

        // Checked before anything is persisted, as in `MlsClient::create_group`.
        let welcome = shared_welcome(&commit_output.welcome_messages, &invitees)?;

        pin_invitees(&self.pins, &invitees)?;

        // As the group the Commit makes: the state it keeps pending is that
        // group's, beside the one it is now.
        store_within(&mut group, Allowance::BuildingCommit(member_count))?;

        Ok(AddMembersOutput {
            commit: commit_output.commit_message.to_bytes()?,
            welcome,
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
    /// * `MlsError::GroupStateTooLarge` - If the group would grow past the most a
    ///   group may store.
    /// * `MlsError::MemberNotFound` - If a UUID is not a current member.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If the list is empty (nothing is built), a
    ///   Commit is already pending, or the list names this user (leaving is
    ///   [`propose_self_remove`](Self::propose_self_remove), not a removal).
    /// * `MlsError::StorageFailed` - If the pending state cannot be stored.
    pub fn remove_members(&self, user_uuids: Vec<String>) -> Result<Vec<u8>, MlsError> {
        let mut group = self.locked()?;

        // Before anything is built, as in `add_members`: mls-rs would build an
        // update the host never asked for, and keep it pending.
        if user_uuids.is_empty() {
            return Err(MlsError::ProtocolFailed(
                "A commit removing nobody removes nobody.".to_string(),
            ));
        }

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

        // As the group it removes them from, which it is until applied.
        let member_count = member_count(&group);

        store_within(&mut group, Allowance::BuildingCommit(member_count))?;

        commit_output.commit_message.to_bytes().map_err(Into::into)
    }

    /// Rotates this member's own key material.
    ///
    /// Nothing about the membership changes; what changes is that any secret an
    /// attacker may have captured stops being useful, which is the whole point
    /// of doing it periodically. There is no dedicated API route, send the
    /// Commit through `POST /groups/{uuid}/messages` like any other message.
    ///
    /// Members allowing a single committer, see
    /// [`process_incoming_message`](Self::process_incoming_message), refuse it
    /// from anybody else.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, MlsError>` - The Commit to distribute.
    ///
    /// # Errors
    ///
    /// * `MlsError::GroupStateTooLarge` - If the group would grow past the most a
    ///   group may store.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If a Commit is already pending, or the
    ///   Commit cannot be built.
    /// * `MlsError::StorageFailed` - If the pending state cannot be stored.
    pub fn update(&self) -> Result<Vec<u8>, MlsError> {
        let mut group = self.locked()?;

        let commit_output = group.commit(Vec::new())?;

        let member_count = member_count(&group);

        store_within(&mut group, Allowance::BuildingCommit(member_count))?;

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
    /// Members allowing a single committer, see
    /// [`process_incoming_message`](Self::process_incoming_message), refuse it:
    /// there, the user is out once that member removes them.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, MlsError>` - The proposal to distribute.
    ///
    /// # Errors
    ///
    /// * `MlsError::GroupStateTooLarge` - If the group would grow past the most a
    ///   group may store.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If this user has already proposed their
    ///   own removal in this epoch.
    /// * `MlsError::StorageFailed` - If the state cannot be stored.
    pub fn propose_self_remove(&self) -> Result<Vec<u8>, MlsError> {
        let mut group = self.locked()?;

        let proposal = group.propose_self_remove(Vec::new())?;

        store(&mut group)?;

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
    /// * `MlsError::GroupStateTooLarge` - If the group would grow past the most a
    ///   group may store. While a Commit of this user's is pending, this can
    ///   be for the room the Commit takes, and the payload is then sent once
    ///   the Commit is applied or discarded, see [`MlsError::GroupStateTooLarge`].
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If proposals are pending and must be
    ///   committed first, or encryption fails.
    /// * `MlsError::StorageFailed` - If the advanced state cannot be stored.
    pub fn encrypt_application_message(&self, payload: Vec<u8>) -> Result<Vec<u8>, MlsError> {
        let mut group = self.locked()?;

        let message = group.encrypt_application_message(&payload, Vec::new())?;

        store(&mut group)?;

        message.to_bytes().map_err(Into::into)
    }

    /// Processes one message drained from the group's queue.
    ///
    /// An application message is read whichever member sent it. A Commit is
    /// applied and a Proposal kept, whichever member sent them, unless
    /// `allowed_committer` names the one member who may change the group: a
    /// Commit from anybody else is then refused, and so is every Proposal,
    /// that member's own included. A group whose members never change is read
    /// with [`read_application_message`](Self::read_application_message)
    /// instead.
    ///
    /// The members of a group the DuckCount API holds name its creator, who
    /// alone adds and removes members. A Commit from anybody else would add or
    /// remove whoever they chose, and a Proposal is of no use to the creator,
    /// who commits what they change themselves: kept, it would stop the group
    /// sending until somebody committed it, and be committed along with the
    /// creator's next change, adding or removing somebody they never chose. A
    /// departing member's proposal to remove themselves goes the same way: it
    /// is for the creator to remove them.
    ///
    /// A Commit from anybody else is refused before mls-rs checks anything it
    /// carries, the members it adds or updates above all: whoever may not
    /// commit gets no other error than this one out of it, nor one naming a
    /// member of their choosing, such as an `IdentityKeyMismatch` for a
    /// contact of this user's whose key never changed. Only what fails before
    /// mls-rs gets to what the Commit changes, authentication above all, is
    /// refused otherwise, with an error that names nobody.
    ///
    /// A refused message stores nothing and leaves the group as it was, a
    /// Commit of this user's still pending included: the next message is
    /// processed as if it had never come.
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
    /// * `allowed_committer` - The UUID of the only member whose Commits are
    ///   applied, in canonical hyphenated lowercase form, or `None` to apply
    ///   any member's, and keep their Proposals.
    ///
    /// # Returns
    ///
    /// * `Result<ProcessedMessage, MlsError>` - What the message turned out to be.
    ///
    /// # Errors
    ///
    /// * `MlsError::UnauthorizedChange` - If `allowed_committer` is given and
    ///   the message is a Commit from anybody else, or a Proposal. Nothing is
    ///   stored.
    /// * `MlsError::InvalidMessage` - If the message cannot be parsed, or was not
    ///   encrypted to the group.
    /// * `MlsError::GroupStateTooLarge` - If what the message did would grow
    ///   the group past the most a group may store. While a Commit of this
    ///   user's is pending, this can be for the room the Commit takes, and the
    ///   message is then read once the Commit is applied or discarded: keep it
    ///   until then, see [`MlsError::GroupStateTooLarge`].
    /// * `MlsError::IdentityKeyMismatch` - If a member's signature key differs
    ///   from the one pinned for them: a member the Commit adds or updates,
    ///   from the committer allowed if one is given.
    /// * `MlsError::LockPoisoned` - If a previous MLS call panicked.
    /// * `MlsError::ProtocolFailed` - If the message belongs to another group, is
    ///   for an epoch too old to still be retained, or fails authentication.
    /// * `MlsError::StorageFailed` - If the resulting state cannot be stored.
    pub fn process_incoming_message(
        &self,
        message: Vec<u8>,
        allowed_committer: Option<String>,
    ) -> Result<ProcessedMessage, MlsError> {
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

        self.change_and_store(|group| {
            let received = with_allowed_committer(allowed_committer.clone(), || {
                group.process_incoming_message(message)
            })?;

            let processed = match received {
                ReceivedMessage::ApplicationMessage(description) => {
                    let read = self.application_message(group, &description)?;

                    ProcessedMessage::ApplicationMessage {
                        sender_user_uuid: read.sender_user_uuid,
                        payload: read.payload,
                        is_sender_pinned: read.is_sender_pinned,
                    }
                }
                ReceivedMessage::Commit(description) => ProcessedMessage::Commit {
                    // Read once mls-rs has processed the Commit, from the leaf
                    // it was sent from, which is still the committer's: mls-rs
                    // refuses a Commit removing its own committer, and lets a
                    // member's leaf pass to nobody else, see `valid_successor`
                    // in `pinning_provider.rs`.
                    committer_user_uuid: Self::member_uuid(group, description.committer),
                    epoch: group.current_epoch(),
                    removed_self: matches!(description.effect, CommitEffect::Removed { .. }),
                },
                ReceivedMessage::Proposal(_) if allowed_committer.is_some() => {
                    return Err(MlsError::UnauthorizedChange);
                }
                ReceivedMessage::Proposal(description) => ProcessedMessage::Proposal {
                    sender_user_uuid: match description.sender {
                        mls_rs::group::ProposalSender::Member(index) => {
                            Self::member_uuid(group, index)
                        }
                        _ => None,
                    },
                },
                _ => ProcessedMessage::Ignored,
            };

            Ok(processed)
        })
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
    /// A message that would grow the group past the most a group may store is
    /// refused as well: mls-rs keeps a key for every generation its sender
    /// skipped, and a peer skipping as many as allowed, message after message,
    /// would otherwise grow the group without end.
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
    /// * `MlsError::GroupStateTooLarge` - If reading the message would grow the
    ///   group past the most a group may store.
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

        self.change_and_store(|group| {
            // Only there for the match to be exhaustive, the content being read
            // as the type checked above. It returns before anything is stored
            // all the same.
            let ReceivedMessage::ApplicationMessage(description) =
                group.process_incoming_message(message)?
            else {
                return Err(MlsError::ProtocolFailed(
                    "An application message was read as something else.".to_string(),
                ));
            };

            self.application_message(group, &description)
        })
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

        let members_before = member_count(&group);

        group.apply_pending_commit()?;
        store_applied(&mut group, members_before)?;

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

        // As building the Commit was, which this ends. Building it took the
        // key the Commit is encrypted with, a few hundred bytes the group
        // keeps, and held to what it may store at rest, a group as full as it
        // may be would keep its Commit pending for good. It may then be past
        // that by as much, and refuse what it would store at rest until its
        // next Commit is applied.
        let member_count = member_count(&group);

        store_within(&mut group, Allowance::BuildingCommit(member_count))?;

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
    /// Wraps a loaded mls-rs group. `pins` is where [`add_members`](Self::add_members),
    /// [`pin_members`](Self::pin_members) and [`pin_member`](Self::pin_member)
    /// record the keys they pin.
    pub(crate) fn new(group: Group<DuckCountMlsConfig>, pins: IdentityPinStore) -> Self {
        MlsGroup {
            group: Mutex::new(group),
            pins,
        }
    }

    /// Runs `change` on the group and stores what it did, leaving the group as
    /// it was, in memory as in storage, when the change fails or is refused
    /// for its size.
    ///
    /// mls-rs advances the group as it reads, keys skipped included, before
    /// anything is stored. Left in memory, a change that was not stored would
    /// be stored by whichever operation comes next, or, refused for its size,
    /// make that one fail as well. Any other storage failure keeps the change
    /// in memory, as storage may hold part of it already: epoch records are
    /// written before the state.
    fn change_and_store<T>(
        &self,
        change: impl FnOnce(&mut Group<DuckCountMlsConfig>) -> Result<T, MlsError>,
    ) -> Result<T, MlsError> {
        let mut group = self.locked()?;

        let before = group.clone();
        let members_before = member_count(&group);

        let value = match change(&mut group) {
            Ok(value) => value,
            Err(error) => {
                *group = before;

                return Err(error);
            }
        };

        // A message read changes no member, and a Commit applied is stored
        // as the larger group, the one it ends or the one it makes.
        match store_applied(&mut group, members_before) {
            Ok(()) => Ok(value),
            Err(error) => {
                // Refused before anything was written.
                if matches!(error, MlsError::GroupStateTooLarge) {
                    *group = before;
                }

                Err(error)
            }
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
    /// there.
    fn member_uuid(group: &Group<DuckCountMlsConfig>, index: u32) -> Option<String> {
        group
            .member_at_index(index)
            .and_then(|member| user_uuid_from(&member.signing_identity.credential).ok())
    }
}

/// Stores `group` at rest, holding it to what a group of the members it has
/// may store but as it builds a Commit, see
/// [`max_group_state_len_at_rest`](crate::cryptography::mls::storage::group_state::max_group_state_len_at_rest).
///
/// A group holding a pending Commit is held to it too, the Commit included:
/// an addition many times the group's size, or any Commit of a large group,
/// may leave no room for what reading or sending a message stores meanwhile,
/// which is then refused until the Commit is applied or discarded.
///
/// # Errors
///
/// * `MlsError::GroupStateTooLarge` - If the group is past what it may store.
/// * `MlsError::StorageFailed` - If the host storage fails.
pub(crate) fn store(group: &mut Group<DuckCountMlsConfig>) -> Result<(), MlsError> {
    let member_count = member_count(group);

    store_within(group, Allowance::AtRest(member_count))
}

/// Stores `group` at rest once a Commit was applied to it, or could have
/// been, holding it to what the larger of the group of `members_before`
/// members and the group it is now may store.
///
/// The record of the epoch a Commit ends goes with it, holding what the group
/// took in as it was then, see
/// [`max_group_state_len_at_rest`](crate::cryptography::mls::storage::group_state::max_group_state_len_at_rest).
///
/// # Errors
///
/// * `MlsError::GroupStateTooLarge` - If the group is past what it may store.
/// * `MlsError::StorageFailed` - If the host storage fails.
fn store_applied(
    group: &mut Group<DuckCountMlsConfig>,
    members_before: usize,
) -> Result<(), MlsError> {
    let member_count = members_before.max(member_count(group));

    store_within(group, Allowance::AtRest(member_count))
}

/// Stores `group`, holding it to `allowance`.
///
/// # Errors
///
/// * `MlsError::GroupStateTooLarge` - If the group is past what it may store.
/// * `MlsError::StorageFailed` - If the host storage fails.
fn store_within(
    group: &mut Group<DuckCountMlsConfig>,
    allowance: Allowance,
) -> Result<(), MlsError> {
    with_allowance(allowance, || group.write_to_storage()).map_err(Into::into)
}

/// How many members `group` holds, in the epoch it is in.
fn member_count(group: &Group<DuckCountMlsConfig>) -> usize {
    group.roster().members_iter().count()
}

/// The members of `group` other than this user, with their signature keys,
/// sorted by user UUID.
///
/// # Errors
///
/// * `MlsError::InvalidCredential` - If a member's credential is malformed.
pub(crate) fn peers(
    group: &Group<DuckCountMlsConfig>,
) -> Result<Vec<(String, SignaturePublicKey)>, MlsError> {
    let mut peers = Vec::new();

    for member in group.roster().members() {
        if member.index != group.current_member_index() {
            let user_uuid = user_uuid_from(&member.signing_identity.credential)?;

            peers.push((user_uuid, member.signing_identity.signature_key));
        }
    }

    peers.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));

    Ok(peers)
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
    let peers = peers(group)?;

    expected_members.sort_unstable();

    if !peers
        .iter()
        .map(|(user_uuid, _)| user_uuid)
        .eq(&expected_members)
    {
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
