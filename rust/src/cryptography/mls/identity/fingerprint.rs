//! Human-comparable rendering of who two users are to each other.
//!
//! Pinning catches a key that *changes*, but it cannot tell a legitimate
//! rotation from an impersonation attempt, and it trusts whatever key it saw
//! first. Closing both gaps needs a human: two users read the same short string
//! to each other over a channel the server does not control, and confirm they
//! match.
//!
//! That string is the [`safety_number`] of the pair: the [`fingerprint`] of
//! each of the two identities, in an order both devices agree on, so both show
//! the same sixty digits and the users make a single comparison.
//!
//! # Why two halves
//!
//! Each half is derived from one identity alone, the user's UUID and the key
//! bound to it. A man in the middle passing his own key off as a user's changes
//! that user's half only, and the other half still matches, so a mismatch tells
//! the two users whose key was substituted, and so which of their devices
//! holds a wrong pin, where a single hash over both identities would only tell
//! them that something is wrong.

use sha3::{Digest, Sha3_256};

/// Domain separator, so a fingerprint can never collide with any other hash
/// this crate computes over the same bytes.
const DOMAIN: &[u8] = b"DuckCount MLS identity fingerprint v1";

/// Number of five-digit groups in a fingerprint.
const GROUP_COUNT: usize = 6;

/// Bytes of digest consumed per group.
const BYTES_PER_GROUP: usize = 5;

/// Renders an identity, a user UUID and the signature key bound to it, as
/// thirty digits.
///
/// The result is six groups of five digits (close to 100 bits of the digest),
/// short enough to read aloud and long enough that producing a second key with
/// the same fingerprint is infeasible. It is the identity's half of every
/// [`safety_number`] it is part of.
///
/// The UUID is hashed along with the key, so the digits vouch for the binding
/// a pin holds rather than for a bare key: the same key bound to somebody else
/// renders differently. Each input is length-prefixed, so no two identities
/// hash the same bytes.
///
/// # Arguments
///
/// * `user_uuid` - The user's UUID, in canonical hyphenated lowercase form.
/// * `signature_key` - The signature public key bound to them.
///
/// # Returns
///
/// * `String` - The fingerprint, for example `12345 67890 09876 54321 13579 24680`.
pub fn fingerprint(user_uuid: &str, signature_key: &[u8]) -> String {
    let mut hasher = Sha3_256::new();

    hasher.update(DOMAIN);
    update_length_prefixed(&mut hasher, user_uuid.as_bytes());
    update_length_prefixed(&mut hasher, signature_key);

    let digest = hasher.finalize();

    digest
        .as_chunks::<BYTES_PER_GROUP>()
        .0
        .iter()
        .take(GROUP_COUNT)
        .map(|chunk| {
            let value = chunk
                .iter()
                .fold(0u64, |accumulator, byte| (accumulator << 8) | *byte as u64);

            format!("{:05}", value % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Renders the pair of two users' identities as the sixty digits they compare.
///
/// The two [`fingerprint`]s are put in the byte order of the user UUIDs, which
/// for canonical UUIDs is also the order of the 16 bytes they spell. The order
/// depends on the UUIDs alone and never on which side computes it, so both
/// devices render the same twelve groups of five digits as long as each holds
/// the other's real key. A UUID spelled any other way renders another number,
/// which fails the comparison rather than passing it.
///
/// # Arguments
///
/// * `user_uuid` - One user's UUID, in canonical hyphenated lowercase form.
/// * `signature_key` - Their signature public key.
/// * `peer_user_uuid` - The other user's UUID, in the same form.
/// * `peer_signature_key` - Their signature public key.
///
/// # Returns
///
/// * `String` - The safety number: the fingerprint of the lower UUID, a space,
///   then the fingerprint of the higher one.
///
/// # Example
///
/// ```rust
/// # use lib_duckcount::cryptography::mls::identity::fingerprint::safety_number;
///
/// let alice = "0bc71677-dd22-4c60-a0ad-81c2ecbff650";
/// let bob = "8a813c98-58dd-4a90-9dbc-602cb7f3de48";
///
/// let on_alices_device = safety_number(alice, b"alice's key", bob, b"bob's key");
/// let on_bobs_device = safety_number(bob, b"bob's key", alice, b"alice's key");
///
/// // Twelve groups of five digits, the same on both devices.
/// assert_eq!(on_alices_device.len(), 71);
/// assert_eq!(on_alices_device, on_bobs_device);
/// ```
pub fn safety_number(
    user_uuid: &str,
    signature_key: &[u8],
    peer_user_uuid: &str,
    peer_signature_key: &[u8],
) -> String {
    let own = fingerprint(user_uuid, signature_key);
    let peer = fingerprint(peer_user_uuid, peer_signature_key);

    // `str` orders by bytes.
    if user_uuid <= peer_user_uuid {
        format!("{own} {peer}")
    } else {
        format!("{peer} {own}")
    }
}

/// Feeds `value` to `hasher` behind its length, so that where one input ends
/// and the next begins is part of what is hashed.
fn update_length_prefixed(hasher: &mut Sha3_256, value: &[u8]) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value);
}
