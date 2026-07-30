//! Identity provider binding user UUIDs to signature keys on first use.
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
//! Pinning closes the gap without a PKI. The first signature key seen for a
//! user UUID is remembered; every later appearance must match it. A server that
//! swaps in its own key is rejected the moment it tries, and a user who
//! legitimately rotates their key has to be re-verified out of band (see
//! [`super::fingerprint`]).

use mls_rs::ExtensionList;
use mls_rs::identity::{CredentialType, SigningIdentity};
use mls_rs::time::MlsTime;
use mls_rs_core::identity::{IdentityProvider, MemberValidationContext};

use crate::cryptography::mls::{
    MlsError, identity::credential::user_uuid_from, storage::identity_pin::IdentityPinStore,
};

/// Identity provider that accepts basic credentials holding a user UUID, and
/// pins the signature key each UUID first appeared with.
#[derive(Clone)]
pub struct PinningIdentityProvider {
    pins: IdentityPinStore,
}

impl PinningIdentityProvider {
    /// Creates a provider recording its pins in `pins`.
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

        self.pins
            .verify_or_pin(&user_uuid, signing_identity.signature_key.as_ref())
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
        // and nobody else, so the answer is whether both identities name the
        // same user.
        //
        // This does not let a member quietly swap their signature key: the new
        // leaf still goes through `validate_member`, where the pin decides.
        Ok(user_uuid_from(&predecessor.credential)? == user_uuid_from(&successor.credential)?)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::BASIC]
    }
}
