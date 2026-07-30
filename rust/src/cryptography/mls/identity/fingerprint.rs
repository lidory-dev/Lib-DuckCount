//! Human-comparable rendering of a member's signature key.
//!
//! Pinning catches a key that *changes*, but it cannot tell a legitimate
//! rotation from an impersonation attempt, and it trusts whatever key it saw
//! first. Closing both gaps needs a human: two users read the same short string
//! to each other over a channel the server does not control, and confirm they
//! match.

use sha3::{Digest, Sha3_256};

/// Domain separator, so a fingerprint can never collide with any other hash
/// this crate computes over the same bytes.
const DOMAIN: &[u8] = b"DuckCount MLS identity fingerprint v1";

/// Number of five-digit groups in a fingerprint.
const GROUP_COUNT: usize = 6;

/// Bytes of digest consumed per group.
const BYTES_PER_GROUP: usize = 5;

/// Renders a signature public key as a safety number.
///
/// The result is six groups of five digits (thirty digits, close to 100 bits
/// of the digest) which is short enough to read aloud and long enough that
/// producing a second key with the same fingerprint is infeasible.
///
/// # Arguments
///
/// * `signature_key` - The member's signature public key, as carried in their
///   signing identity.
///
/// # Returns
///
/// * `String` - The fingerprint, for example `12345 67890 09876 54321 13579 24680`.
///
/// # Example
///
/// ```rust
/// use lib_duckcount::cryptography::mls::identity::fingerprint::fingerprint;
///
/// let signature_key = b"a signature public key".to_vec();
///
/// let fingerprint = fingerprint(&signature_key);
///
/// assert_eq!(fingerprint.len(), 35);
///
/// // The same key always renders the same way, which is what makes it
/// // comparable between two devices.
/// assert_eq!(fingerprint, lib_duckcount::cryptography::mls::identity::fingerprint::fingerprint(&signature_key));
/// ```
pub fn fingerprint(signature_key: &[u8]) -> String {
    let mut hasher = Sha3_256::new();

    hasher.update(DOMAIN);
    hasher.update(signature_key);

    let digest = hasher.finalize();

    digest
        .chunks_exact(BYTES_PER_GROUP)
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
