//! The UUID of a one-time expense, derived rather than chosen.
//!
//! The creditor's device has to know an expense's UUID before posting it: the
//! copy of the expense key it keeps on the server names the expense, and goes
//! in the same request. Letting the device pick the UUID would let a client
//! aim at the one it wants, so it picks a nonce instead, and the UUID is
//! derived from the nonce and the creditor's own UUID exactly as the server
//! derives it: the first 128 bits of SHA3-256(creditor UUID ‖ nonce),
//! as a UUIDv8 (RFC 9562, section 5.8).

use rand::{RngCore, rngs::OsRng};
use sha3::{Digest, Sha3_256};
use uuid::Uuid;

/// Length of the nonce a one-time expense's UUID is derived from, in bytes.
const NONCE_LENGTH: usize = 16;

/// The identity of a new one-time expense: the nonce to send the server, and
/// the UUID it derives from.
#[derive(uniffi::Record)]
pub struct OneTimeExpenseId {
    pub nonce: Vec<u8>,
    pub uuid: String,
}

/// Mints the identity of a new one-time expense created by `creditor_uuid`.
///
/// # Returns
///
/// * `Option<OneTimeExpenseId>` - The nonce and the UUID, or `None` when
///   `creditor_uuid` is not a UUID.
#[uniffi::export]
pub fn new_one_time_expense_id(creditor_uuid: String) -> Option<OneTimeExpenseId> {
    let creditor_uuid = Uuid::parse_str(&creditor_uuid).ok()?;

    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);

    Some(OneTimeExpenseId {
        nonce: nonce.to_vec(),
        uuid: derive(&creditor_uuid, &nonce).to_string(),
    })
}

/// The UUID of the one-time expense `creditor_uuid` creates with `nonce`.
pub(crate) fn derive(creditor_uuid: &Uuid, nonce: &[u8; NONCE_LENGTH]) -> Uuid {
    let digest = Sha3_256::new()
        .chain_update(creditor_uuid.as_bytes())
        .chain_update(nonce)
        .finalize();

    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);

    Uuid::new_v8(bytes)
}
