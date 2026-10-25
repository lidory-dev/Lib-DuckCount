//! The UUID of a one-time expense, derived rather than chosen, see
//! [`derived_uuid`](crate::cryptography::derived_uuid).
//!
//! The creditor's device has to know an expense's UUID before posting it: the
//! copy of the expense key it keeps on the server names the expense, and goes
//! in the same request.

use uuid::Uuid;

use crate::cryptography::derived_uuid::{NONCE_LENGTH, derive, mint};

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
    let (nonce, uuid) = mint(&creditor_uuid)?;

    Some(OneTimeExpenseId { nonce, uuid })
}

/// Whether `nonce` derives `expense_uuid` from `creditor_uuid`: whether the
/// one-time expense with that UUID, if there is one, is theirs.
///
/// Nobody but the creditor can show it of themselves: the UUID was derived from
/// their own UUID and the nonce they drew, and a nonce that derives the same
/// UUID from anybody else's has to match the 122 bits of SHA3-256 the UUID
/// keeps, some 2^122 tries. The nonce is no secret, since it travels with every
/// copy of the expense's key, so this says who handed a key over only when
/// `creditor_uuid` is whoever the channel it arrived over authenticated. Then a
/// participant can tell, as the key arrives, whether it came from the creditor,
/// without taking the server's word for who that is.
///
/// # Returns
///
/// * `bool` - Whether `nonce` derives `expense_uuid` from `creditor_uuid`. False
///   as well when `creditor_uuid` is not a UUID, `nonce` is not 16 bytes, or
///   `expense_uuid` is not written the way this crate writes one.
#[uniffi::export]
pub fn is_one_time_expense_creditor(
    expense_uuid: String,
    creditor_uuid: String,
    nonce: Vec<u8>,
) -> bool {
    let Ok(creditor_uuid) = Uuid::parse_str(&creditor_uuid) else {
        return false;
    };

    let Ok(nonce) = <[u8; NONCE_LENGTH]>::try_from(nonce.as_slice()) else {
        return false;
    };

    derive(&creditor_uuid, &nonce).to_string() == expense_uuid
}
