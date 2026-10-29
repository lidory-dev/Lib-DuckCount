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
pub mod group_id;
pub mod group_information;
pub mod identity;
pub mod invitation;
pub mod key_package;
pub mod one_time_expense;
pub mod sign_content;
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

/// The most members a group may hold, its creator included.
///
/// Every member stores the whole ratchet tree, and the Welcome adding anybody
/// carries it, so both grow with the group: a group of a hundred is created
/// and joined in some 300 KB of state, to which a pending Commit adds up to
/// some 830 KB, both within the most a group of a hundred may store (see
/// `max_group_state_len_at_rest` and `max_group_state_len` in
/// `storage/group_state.rs`). Its one Welcome is some 280 KB, which the
/// DuckCount API is handed in Base64, some 370 KB, within the cap it holds a
/// Welcome to, see `tests/wire_sizes.rs`. The API refuses a larger group too,
/// and the two change together; a Welcome for one is refused on joining,
/// whoever wrote it.
pub const MAX_GROUP_MEMBERS: usize = 100;

/// Exposes [`MAX_GROUP_MEMBERS`] to the foreign bindings so clients can show the
/// limit and keep a selection within it instead of hardcoding it.
///
/// UniFFI has no `usize` support, so the value is narrowed to `u16`.
#[uniffi::export]
pub fn max_group_members() -> u16 {
    MAX_GROUP_MEMBERS as u16
}

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
    /// [`clear_identity_pin`](client::MlsClient::clear_identity_pin).
    IdentityKeyMismatch(String),
    /// A credential was not a basic credential holding a valid user UUID.
    InvalidCredential,
    /// A key package could not be parsed, or was not a key package at all.
    InvalidKeyPackage,
    /// The key packages fetched for some invitees are none they can be added
    /// with: unparsable, not key packages, of another cipher suite, expired,
    /// or asserting a user other than the one they were fetched for. Carries
    /// the user UUID of every such invitee, in the order they were given.
    UnusableKeyPackages(Vec<String>),
    /// The Welcome a commit produced carries no secret for one of the invitees
    /// it was built for. Carries that invitee's user UUID.
    UnmatchedWelcome(String),
    /// No group with the given MLS group id is stored locally.
    GroupNotFound,
    /// A Welcome is for a group this device holds, or for one it deleted at
    /// the epoch the Welcome is for or a later one, until pruning forgets the
    /// deletion. Joining it would put that group back at an epoch this device
    /// held already.
    GroupAlreadyJoined,
    /// A Welcome is for a group whose id is not the one derived for the group
    /// the host expects it to be, see [`group_id`]: whoever wrote it gave it
    /// the id of another group, or one no client of this library derives.
    UnexpectedGroupId,
    /// A group, one a Welcome is for or one already joined, holds members
    /// other than exactly this user and the ones the host expected, or does
    /// not hold, besides this user, the one member the host named, or a
    /// Commit adding members would add somebody another member proposed too.
    UnexpectedMembers,
    /// A group would hold more than [`MAX_GROUP_MEMBERS`] members: one being
    /// created or added to, refused before anything is built, or one a
    /// Welcome is for, refused before anything is stored or pinned.
    TooManyMembers,
    /// No member of the group holds the given user UUID.
    MemberNotFound(String),
    /// An MLS message could not be decoded, or describes a group no client of
    /// this library produces.
    InvalidMessage,
    /// A message would change a group in a way the host does not allow: a
    /// Commit from a member other than the one allowed to commit, refused
    /// before anything it carries is checked, or a Proposal, which no member
    /// may send where one is, see
    /// [`process_incoming_message`](group::MlsGroup::process_incoming_message).
    /// Nothing was stored, and the group is as it was.
    UnauthorizedChange,
    /// Storing a group would grow its state, or the record of an epoch it
    /// retains, past the most a group of its members may store, see
    /// `max_group_state_len_at_rest` in `storage/group_state.rs`. Nothing was
    /// stored. A message refused this way leaves the group as it was; after
    /// any other operation, the group in memory may still hold the refused
    /// change, and has to be loaded again.
    ///
    /// At rest, a message refused stays refused, and so does every later one
    /// its sender sent in that epoch, see `MAX_GROUP_STATE_LEN`. While a
    /// Commit of this user's is pending, though, the refusal can be for the
    /// room the Commit takes, as a large one leaves no room to read or send
    /// anything beside it: the message is then read, or sent, once the Commit
    /// is applied or discarded, and has to be kept until then.
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
            MlsError::UnusableKeyPackages(user_uuids) => write!(
                f,
                "The key packages of users {} cannot be used.",
                user_uuids.join(", ")
            ),
            MlsError::UnmatchedWelcome(user_uuid) => {
                write!(
                    f,
                    "The Welcome message carries no secret for user {}.",
                    user_uuid
                )
            }
            MlsError::GroupNotFound => write!(f, "MLS group not found."),
            MlsError::GroupAlreadyJoined => write!(f, "MLS group already joined."),
            MlsError::UnexpectedGroupId => {
                write!(
                    f,
                    "The MLS group id is not the one the group is expected to have."
                )
            }
            MlsError::UnexpectedMembers => {
                write!(f, "The MLS group does not hold the expected members.")
            }
            MlsError::TooManyMembers => write!(
                f,
                "An MLS group cannot hold more than {} members.",
                MAX_GROUP_MEMBERS
            ),
            MlsError::MemberNotFound(user_uuid) => {
                write!(f, "User {} is not a member of this group.", user_uuid)
            }
            MlsError::InvalidMessage => write!(f, "Invalid MLS message."),
            MlsError::UnauthorizedChange => {
                write!(
                    f,
                    "The MLS message changes the group in a way that is not allowed."
                )
            }
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
        // Our identity provider, storage adapters and rules fail with our own
        // errors, which mls-rs wraps before they reach the caller. Unwrap them
        // so the host still sees the actionable variant, a pin mismatch, a
        // storage failure worth retrying or a change it does not allow, rather
        // than an opaque protocol failure.
        if let mls_rs::error::MlsError::IdentityProviderError(any_error)
        | mls_rs::error::MlsError::GroupStorageError(any_error)
        | mls_rs::error::MlsError::KeyPackageRepoError(any_error)
        | mls_rs::error::MlsError::MlsRulesError(any_error) = &error
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
