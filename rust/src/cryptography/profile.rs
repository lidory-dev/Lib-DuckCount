use crate::cryptography::hashing::hash_with_domain;

/// Domain separator prepended to the profile encryption key before it is hashed
/// into the proof that its holder may read the profile it seals.
pub const PROFILE_ENCRYPTION_KEY_DOMAIN: &str = "duckcount:profile-encryption-key:v1:";

/// How many characters of the digest the server is given.
const PARTIAL_HASH_LENGTH: usize = 10;

/// Hashes a profile encryption key into the partial digest that proves possession
/// of it without transmitting it.
///
/// Only a prefix is sent, enough to tell a holder of the key from anybody else,
/// while giving away as little of the digest as possible. Guessing it buys nothing
/// on its own, the profile it unlocks is ciphertext to anyone without the key.
///
/// # Arguments
///
/// * `profile_encryption_key` - The key that seals the profile.
///
/// # Returns
///
/// The first [PARTIAL_HASH_LENGTH] characters of the digest, lowercase hexadecimal.
///
/// # Example
///
/// ```rust
/// # use lib_duckcount::cryptography::{
/// #     encryption::keys::generate_symmetric_encryption_key,
/// #     profile::profile_encryption_key_partial_hash,
/// # };
/// let key = generate_symmetric_encryption_key();
///
/// let partial_hash = profile_encryption_key_partial_hash(&key);
///
/// assert_eq!(partial_hash.len(), 10);
/// // The same key always proves possession the same way.
/// assert_eq!(partial_hash, profile_encryption_key_partial_hash(&key));
/// ```
#[uniffi::export]
pub fn profile_encryption_key_partial_hash(profile_encryption_key: &Vec<u8>) -> String {
    hash_with_domain(PROFILE_ENCRYPTION_KEY_DOMAIN, profile_encryption_key)
        .chars()
        .take(PARTIAL_HASH_LENGTH)
        .collect()
}
