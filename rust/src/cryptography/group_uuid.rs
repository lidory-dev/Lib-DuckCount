//! The UUID of a group the DuckCount API holds, derived rather than chosen, see
//! [`derived_uuid`](crate::cryptography::derived_uuid).
//!
//! The creator's device has to know a group's UUID before posting it: the
//! group's MLS id is derived from it, see
//! [`group_id`](crate::cryptography::mls::group_id), and the Welcome to that
//! group goes in the same request.

use crate::cryptography::derived_uuid::mint;

/// The identity of a new group: the nonce to send the server, and the UUID it
/// derives from.
#[derive(uniffi::Record)]
pub struct GroupId {
    pub nonce: Vec<u8>,
    pub uuid: String,
}

/// Mints the identity of a new group created by `creator_uuid`, whose UUID
/// [`MlsClient::create_group`] is then given.
///
/// The host keeps the nonce until the server has the group: a creation it sends
/// again has to send the same nonce to name the same group.
///
/// # Returns
///
/// * `Option<GroupId>` - The nonce and the UUID, or `None` when `creator_uuid`
///   is not a UUID.
///
/// [`MlsClient::create_group`]: crate::cryptography::mls::client::MlsClient::create_group
#[uniffi::export]
pub fn new_group_id(creator_uuid: String) -> Option<GroupId> {
    let (nonce, uuid) = mint(&creator_uuid)?;

    Some(GroupId { nonce, uuid })
}
