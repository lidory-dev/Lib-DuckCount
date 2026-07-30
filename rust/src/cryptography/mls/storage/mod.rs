//! Persistence for MLS state.
//!
//! mls-rs needs somewhere to keep group state and key package secrets between
//! calls. Rather than owning a database, this library splits the job:
//!
//! - the **host** (Kotlin) implements [`MlsStore`] and persists opaque
//!   byte blobs where it already keeps encrypted data;
//! - **this crate** seals every blob before handing it over and opens it on the
//!   way back, so MLS secrets remain protected even if the host's own storage
//!   encryption is defeated.
//!
//! The host therefore never sees group secrets, and a bug on the host side
//! cannot silently downgrade the protection of the ones it stores.

pub mod group_state;
pub mod identity_pin;
pub mod key_package;
pub mod sealed_record;

/// Logical partitions of the host's MLS store.
///
/// Hosts should treat a namespace as a table (or a key prefix): keys are only
/// unique *within* one, and [`MlsStore::keys`] must not leak across them.
#[derive(uniffi::Enum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsNamespace {
    /// Current state of a group, keyed by MLS group id.
    GroupState,
    /// A retained prior epoch of a group, keyed by group id and epoch number.
    GroupEpoch,
    /// Secrets backing a published key package, keyed by key package reference.
    KeyPackage,
    /// The signature key pinned for a user UUID on first contact.
    IdentityPin,
    /// The local user's own long-term signature key pair.
    Signer,
    /// Bookkeeping owned by the library itself. Unlike every other namespace,
    /// records here are **not** sealed, because they hold no secrets, the
    /// sealing salt lives here, and a salt is public by construction.
    Metadata,
}

impl MlsNamespace {
    /// Stable byte tag mixed into every sealed record.
    ///
    /// Changing a value here invalidates all previously stored records, so the
    /// tags are assigned explicitly rather than derived from the variant order.
    pub(crate) fn tag(&self) -> u8 {
        match self {
            MlsNamespace::GroupState => 1,
            MlsNamespace::GroupEpoch => 2,
            MlsNamespace::KeyPackage => 3,
            MlsNamespace::IdentityPin => 4,
            MlsNamespace::Metadata => 5,
            MlsNamespace::Signer => 6,
        }
    }
}

/// Errors a host storage implementation may report.
#[derive(Debug, uniffi::Error)]
pub enum MlsStoreError {
    /// The underlying storage failed. The message is for diagnostics only and
    /// must not contain secret material.
    Failed(String),
}

impl std::fmt::Display for MlsStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlsStoreError::Failed(error) => write!(f, "MLS store failed: {}", error),
        }
    }
}

impl std::error::Error for MlsStoreError {}

/// Key-value storage supplied by the host.
///
/// Implementations are expected to be durable and to survive process restarts;
/// losing a record means losing access to a group. Values are opaque sealed
/// bytes, do not inspect, re-encode, or reorder them.
///
/// # Consistency
///
/// [`crate::cryptography::mls::storage::group_state::SealedGroupStateStorage`]
/// writes a group's prior epochs *before* the group state record that refers to
/// them, and treats the state record as the commit point. A host that cannot
/// offer a transaction across several calls therefore degrades safely: a crash
/// mid-write leaves unreferenced epoch records behind rather than a group state
/// pointing at epochs that were never stored. Hosts that *can* wrap the calls
/// in a transaction should still do so.
///
/// # Threading
///
/// Methods may be called from any thread and must be internally synchronised.
#[uniffi::export(with_foreign)]
pub trait MlsStore: Send + Sync {
    /// Reads the value stored at `key`, or `None` when the slot is empty.
    fn get(&self, namespace: MlsNamespace, key: Vec<u8>) -> Result<Option<Vec<u8>>, MlsStoreError>;

    /// Writes `value` at `key`, replacing any previous value.
    fn put(
        &self,
        namespace: MlsNamespace,
        key: Vec<u8>,
        value: Vec<u8>,
    ) -> Result<(), MlsStoreError>;

    /// Removes the value at `key`. Removing an absent key is not an error.
    ///
    /// # Warning
    ///
    /// Values hold sealed secret material. Implementations should delete
    /// rather than tombstone, and should let the underlying store reclaim the
    /// space.
    fn delete(&self, namespace: MlsNamespace, key: Vec<u8>) -> Result<(), MlsStoreError>;

    /// Lists every key currently present in `namespace`, in any order.
    fn keys(&self, namespace: MlsNamespace) -> Result<Vec<Vec<u8>>, MlsStoreError>;
}
