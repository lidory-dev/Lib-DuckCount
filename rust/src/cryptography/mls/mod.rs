//! Messaging Layer Security (RFC 9420) group messaging.
//!
//! DuckCount groups are MLS groups. The server relays Welcomes, Commits and
//! application messages as opaque ciphertext and never holds group secrets;
//! every cryptographic decision lives here.
//!
//! # Cipher suite
//!
//! Exactly one cipher suite is enabled: [`CIPHER_SUITE`], the X-Wing hybrid of
//! ML-KEM-768 and X25519. Confidentiality survives a break of *either*
//! primitive, which is what protects today's traffic against a
//! harvest-now-decrypt-later adversary. Enabling a single suite also means a
//! peer cannot negotiate a group down onto a classical one.
//!
//! # Single active client per user
//!
//! A user has one long-term MLS signature key, recovered from their vault. Two
//! devices running with the same identity and the same stored state would fork
//! the group, so exactly one active client per user is assumed (the same
//! assumption the vault design already makes).

pub mod client;
pub mod config;
pub mod group;
pub mod identity;
pub mod invitation;
pub mod key_package;
pub mod one_time_expense;
pub mod storage;
pub mod types;

use std::fmt::Display;

use mls_rs::CipherSuite;
use mls_rs_core::error::IntoAnyError;

/// The only cipher suite this library speaks: the X-Wing hybrid combining
/// ML-KEM-768 with X25519 (`CipherSuite(65100)`).
///
/// The identifier sits in the private-use range because hybrid post-quantum MLS
/// cipher suites are not yet IANA-registered. That is safe here because both
/// ends of every DuckCount session are this library, but it means the suite is
/// worth recording alongside each group so a future migration is a data change
/// rather than a code change.
pub const CIPHER_SUITE: CipherSuite = CipherSuite::ML_KEM_768_X25519;

/// MLS related errors.
#[derive(Debug, Clone, uniffi::Error)]
pub enum MlsError {
    /// The host's storage callback failed.
    StorageFailed(String),
    /// A stored record could not be authenticated: it was truncated, tampered
    /// with, sealed under a different secret, or moved to another slot.
    StorageIntegrityFailed,
    /// The sealing key could not be derived from the provided secret.
    KeyDerivationFailed,
    /// The underlying MLS implementation rejected the operation.
    ProtocolFailed(String),
    /// A member presented a signature key differing from the one pinned for
    /// their user UUID on first contact. Carries the offending user UUID.
    ///
    /// This is either a legitimate key rotation or an impersonation attempt.
    /// The library cannot tell them apart, so it fails closed and leaves the
    /// decision to the user; see
    /// [`clear_identity_pin`](identity::fingerprint::clear_identity_pin).
    IdentityKeyMismatch(String),
    /// A credential was not a basic credential holding a valid user UUID.
    InvalidCredential,
    /// A key package could not be parsed, or was not a key package at all.
    InvalidKeyPackage,
    /// A Welcome message could not be matched back to the invitee it was
    /// produced for. Carries the user UUID left without a Welcome.
    UnmatchedWelcome(String),
    /// No group with the given MLS group id is stored locally.
    GroupNotFound,
    /// A Welcome is for a group this device has already joined, whether it
    /// still holds it or deleted it since. Joining it again would put that
    /// group back at the epoch the Welcome was for.
    GroupAlreadyJoined,
    /// A group, one a Welcome is for or one already joined, holds members
    /// other than exactly this user and the ones the host expected.
    UnexpectedMembers,
    /// No member of the group holds the given user UUID.
    MemberNotFound(String),
    /// An MLS message could not be decoded.
    InvalidMessage,
    /// Storing a group would grow its state, or the record of an epoch it
    /// retains, past the most a group may store, see `MAX_GROUP_STATE_LEN` in
    /// `storage/group_state.rs`. Nothing was stored. A message refused this way
    /// leaves the group as it was; after any other operation, the group in
    /// memory may still hold the refused change, and has to be loaded again.
    GroupStateTooLarge,
    /// A lock guarding MLS state was poisoned by a panic in another thread.
    LockPoisoned,
}

impl Display for MlsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlsError::StorageFailed(error) => write!(f, "MLS storage failed: {}", error),
            MlsError::StorageIntegrityFailed => {
                write!(f, "A stored MLS record failed authentication.")
            }
            MlsError::KeyDerivationFailed => write!(f, "MLS key derivation failed."),
            MlsError::ProtocolFailed(error) => write!(f, "MLS protocol error: {}", error),
            MlsError::IdentityKeyMismatch(user_uuid) => write!(
                f,
                "The signature key of user {} does not match the pinned one.",
                user_uuid
            ),
            MlsError::InvalidCredential => write!(f, "Invalid MLS credential."),
            MlsError::InvalidKeyPackage => write!(f, "Invalid MLS key package."),
            MlsError::UnmatchedWelcome(user_uuid) => {
                write!(f, "No Welcome message was produced for user {}.", user_uuid)
            }
            MlsError::GroupNotFound => write!(f, "MLS group not found."),
            MlsError::GroupAlreadyJoined => write!(f, "MLS group already joined."),
            MlsError::UnexpectedMembers => {
                write!(f, "The MLS group does not hold the expected members.")
            }
            MlsError::MemberNotFound(user_uuid) => {
                write!(f, "User {} is not a member of this group.", user_uuid)
            }
            MlsError::InvalidMessage => write!(f, "Invalid MLS message."),
            MlsError::GroupStateTooLarge => {
                write!(f, "The MLS group state would grow too large to store.")
            }
            MlsError::LockPoisoned => write!(f, "MLS state lock was poisoned."),
        }
    }
}

impl std::error::Error for MlsError {}

impl IntoAnyError for MlsError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

impl From<mls_rs::error::MlsError> for MlsError {
    fn from(error: mls_rs::error::MlsError) -> Self {
        // Our identity provider and storage adapters fail with our own errors,
        // which mls-rs wraps before they reach the caller. Unwrap them so the
        // host still sees the actionable variant, a pin mismatch or a storage
        // failure worth retrying, rather than an opaque protocol failure.
        if let mls_rs::error::MlsError::IdentityProviderError(any_error)
        | mls_rs::error::MlsError::GroupStorageError(any_error)
        | mls_rs::error::MlsError::KeyPackageRepoError(any_error) = &error
            && let Some(ours) = any_error.inner_dyn_error().downcast_ref::<MlsError>()
        {
            return ours.clone();
        }

        if matches!(error, mls_rs::error::MlsError::GroupNotFound) {
            return MlsError::GroupNotFound;
        }

        MlsError::ProtocolFailed(error.to_string())
    }
}
