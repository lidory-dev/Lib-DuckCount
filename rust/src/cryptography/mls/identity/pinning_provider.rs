//! Identity provider checking each user UUID against the signature key pinned
//! for it.
//!
//! # Why this exists
//!
//! A basic credential is an unverified assertion: it says "I am user X" and
//! nothing more. The party that decides which key package a peer receives is
//! the server, so with no further checking the server could hand out a key
//! package carrying its own signature key under a member's UUID and read every
//! message in the group. That would make the server a trusted party, which the
//! rest of DuckCount deliberately avoids.
//!
//! Pinning closes the gap without a PKI. The signature key a user is first
//! invited or trusted with is remembered; every later appearance must match it.
//! A server that swaps in its own key is rejected the moment it tries, and a
//! user who legitimately rotates their key has to be re-verified out of band
//! (see [`super::fingerprint`]).
//!
//! # Who gets pinned
//!
//! This provider only checks. mls-rs consults it for every leaf of every tree,
//! Welcome and commit it validates, often before the signatures around that
//! leaf are checked, and a tree is only its author's word for who everybody
//! else in it is. Pinning from here would let whoever wrote a Welcome decide
//! the keys of people this user has never met.
//!
//! Pins are written instead once mls-rs has validated everything, and only
//! for the users the host chose: the invitees it fetched key packages for,
//! the members of a group it joined once it trusts them, at the join or
//! later with
//! [`MlsGroup::pin_members`](crate::cryptography::mls::group::MlsGroup::pin_members),
//! and a member of a group the DuckCount API holds, one at a time with
//! [`MlsGroup::pin_member`](crate::cryptography::mls::group::MlsGroup::pin_member).
//! That tree's word is taken, unlike any other's, because its author is
//! somebody this device trusts: the group's creator, whom the host pinned
//! before joining from their Welcome, and the one member whose Commits seat
//! anybody in it. Any other member's Commit is applied only to remove
//! members who have departed, see
//! [`MlsGroup::process_incoming_message`](crate::cryptography::mls::group::MlsGroup::process_incoming_message),
//! which seats nobody, and the update path it carries keeps the leaf its
//! committer had, signature key included, see `check_member_committer_leaf`
//! in `config.rs`. So every leaf in the tree was added by the creator, and
//! holds the key the creator seated it with.

use mls_rs::ExtensionList;
use mls_rs::identity::{CredentialType, SigningIdentity};
use mls_rs::time::MlsTime;
use mls_rs_core::identity::{IdentityProvider, MemberValidationContext};

use crate::cryptography::mls::{
    MlsError, config::check_member_committer_leaf, identity::credential::user_uuid_from,
    storage::identity_pin::IdentityPinStore,
};

/// Identity provider that accepts basic credentials holding a user UUID, and
/// rejects any signature key differing from the one pinned for that UUID.
#[derive(Clone)]
pub struct PinningIdentityProvider {
    pins: IdentityPinStore,
}

impl PinningIdentityProvider {
    /// Creates a provider checking members against `pins`.
    pub fn new(pins: IdentityPinStore) -> Self {
        Self { pins }
    }
}

impl IdentityProvider for PinningIdentityProvider {
    type Error = MlsError;

    fn validate_member(
        &self,
        signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        let user_uuid = user_uuid_from(&signing_identity.credential)?;

        // Before the pin, which would refuse a leaf a member other than the
        // creator may not commit on some devices and not on others.
        check_member_committer_leaf(&user_uuid, &signing_identity.signature_key)?;

        self.pins
            .verify(&user_uuid, signing_identity.signature_key.as_ref())
    }

    fn validate_external_sender(
        &self,
        _signing_identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        // DuckCount groups never carry an external senders extension: every
        // message originates from a member. Rejecting unconditionally means a
        // group that somehow acquired one cannot be driven from outside.
        Err(MlsError::InvalidCredential)
    }

    fn identity(
        &self,
        signing_identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        user_uuid_from(&signing_identity.credential).map(|user_uuid| user_uuid.into_bytes())
    }

    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        // Consulted whenever a member's leaf node is replaced, which with an
        // update path required on every commit, is constantly, not just on the
        // external commits the name suggests. A member may succeed themselves
        // and nobody else, so both identities have to name the same user.
        //
        // With the signature key their leaf already had, too. A user has one
        // signature key, the same in every group, and this library never
        // commits another, so a new one is a member's own doing: checked
        // against the pin alone, in `validate_member`, it would be taken by
        // every member who has none for them, the group splitting in two over
        // one Commit, and the key a member's leaf holds would no longer be the
        // one the creator seated it with, which is what pinning a member from
        // the tree of a group the DuckCount API holds goes by.
        //
        // mls-rs asks this only once `validate_member` has taken the new leaf,
        // though, which a member who has a key pinned for its committer
        // refuses first, with an `IdentityKeyMismatch`. So a committer other
        // than the creator has the leaf held to theirs before the pin is
        // consulted, see `check_member_committer_leaf` in `config.rs`, and
        // every member refuses it alike. The creator's is held to the key the
        // host pinned for them before joining from their Welcome.
        Ok(
            user_uuid_from(&predecessor.credential)? == user_uuid_from(&successor.credential)?
                && predecessor.signature_key == successor.signature_key,
        )
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::BASIC]
    }
}
