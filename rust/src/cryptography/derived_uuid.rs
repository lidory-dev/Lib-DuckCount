//! The UUID of what a client creates on the DuckCount API, derived rather than
//! chosen: a one-time expense's, see
//! [`one_time_expense_id`](crate::cryptography::one_time_expense_id), a
//! group's, see [`group_uuid`](crate::cryptography::group_uuid), and a group
//! expense's, see [`group_expense_id`](crate::cryptography::group_expense_id).
//!
//! The creator's device has to know the UUID before posting: what it posts
//! along with it names it. Letting the device pick the UUID would let a client
//! aim at the one it wants, somebody else's: the server refusing a UUID that is
//! taken would tell it whether that expense or group exists, and once one is
//! deleted, it could create its own under the old UUID, which for a group
//! would take the old group's MLS id, see
//! [`group_id`](crate::cryptography::mls::group_id). So the device picks a
//! nonce instead, and the UUID is derived from the nonce and its user's own
//! UUID exactly as the server derives it: the first 128 bits of
//! SHA3-256(creator UUID ‖ nonce), as a UUIDv8 (RFC 9562, section 5.8). Every
//! UUID a client can reach is then its own user's, and the server refusing one
//! tells it only that it sent the same nonce before.

use rand::{RngCore, rngs::OsRng};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

/// Length of the nonce a UUID is derived from, in bytes.
pub(crate) const NONCE_LENGTH: usize = 16;

/// Draws a nonce for something new `creator_uuid` creates, and derives its
/// UUID from it.
///
/// # Returns
///
/// * `Option<(Vec<u8>, String)>` - The nonce and the UUID, or `None` when
///   `creator_uuid` is not a UUID.
pub(crate) fn mint(creator_uuid: &str) -> Option<(Vec<u8>, String)> {
    let creator_uuid = Uuid::parse_str(creator_uuid).ok()?;

    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);

    Some((nonce.to_vec(), derive(&creator_uuid, &nonce).to_string()))
}

/// The UUID of what `creator_uuid` creates with `nonce`.
pub(crate) fn derive(creator_uuid: &Uuid, nonce: &[u8; NONCE_LENGTH]) -> Uuid {
    let digest = Sha3_256::new()
        .chain_update(creator_uuid.as_bytes())
        .chain_update(nonce)
        .finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);

    Uuid::new_v8(bytes)
}
