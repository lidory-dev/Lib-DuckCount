//! The UUID of a group expense, derived rather than chosen, see
//! [`derived_uuid`](crate::cryptography::derived_uuid).
//!
//! The author's device has to know an expense's UUID before posting it: the
//! version it posts is sealed bound to that UUID and signed with it, see
//! [`group_expense`](crate::cryptography::mls::group_expense), and goes in the
//! same request.

use base64::Engine;
use base64::prelude::BASE64_STANDARD;

use crate::cryptography::derived_uuid::mint;

/// The identity of a new group expense: the UUID, and the nonce to send the
/// server for it to derive the same one.
#[derive(uniffi::Record)]
pub struct GroupExpenseId {
    pub uuid: String,
    /// The 16 bytes drawn, in standard Base64, as the request creating the
    /// expense carries them: the host sends it as it is, and the server
    /// derives the UUID from what it decodes to.
    pub nonce: String,
}

/// Mints the identity of a new group expense written by `author_uuid`.
///
/// A creation the host sends again, its answer lost, has to carry the same
/// nonce to name the same expense, which the server then refuses as one it
/// holds rather than storing it twice.
///
/// # Returns
///
/// * `Option<GroupExpenseId>` - The UUID and the nonce, or `None` when
///   `author_uuid` is not a UUID.
#[uniffi::export]
pub fn new_group_expense_id(author_uuid: String) -> Option<GroupExpenseId> {
    let (nonce, uuid) = mint(&author_uuid)?;

    Some(GroupExpenseId {
        uuid,
        nonce: BASE64_STANDARD.encode(nonce),
    })
}
