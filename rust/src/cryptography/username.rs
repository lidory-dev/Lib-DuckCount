use sha3::{Digest, Sha3_512};
use thiserror::Error;

/// Domain separator prepended to a handle before it is hashed into a reserved
/// username digest.
///
/// A digest minted for discovery can therefore never collide with one minted for
/// another purpose over the same handle, which is what the server relies on when
/// it refuses a reserved username equal to the caller's login username. The
/// trailing `:` cannot occur in a validated handle (they are `[a-z0-9]` only), so
/// the concatenation is unambiguous, and the `v1` leaves room to rotate the
/// scheme without silently changing everybody's digest.
pub const RESERVED_USERNAME_DOMAIN: &str = "duckcount:reserved-username:v1:";

/// Represents possible errors that can occur when handling a username.
#[derive(Error, Debug, PartialEq, uniffi::Error)]
pub enum UsernameError {
    /// A username is required.
    #[error("A username is required.")]
    Empty,
    /// A username must start with a letter.
    #[error("A username must start with a letter.")]
    MustStartWithLetter,
    /// A username may only contain letters and digits.
    #[error("A username may only contain letters and digits.")]
    InvalidCharacter,
}

/// Validates a username and returns its normalized form.
///
/// Normalizing means trimming the surrounding whitespace and lowercasing, so that
/// the same handle typed with a different case or stray spaces always hashes to
/// the same digest. Only ASCII letters and digits are accepted: the digest is
/// computed independently by every client that resolves the handle, and Unicode
/// would make the encoding ambiguous (the same handle can be spelled with
/// different byte sequences under NFC and NFD).
///
/// # Arguments
///
/// * `username` - The handle as the user typed it.
///
/// # Returns
///
/// A `Result` containing the normalized username if it is valid, or a
/// [UsernameError] otherwise.
///
/// # Errors
///
/// This function will return an error if:
/// - The username is empty, or only whitespace.
/// - The username does not start with a letter.
/// - The username contains anything other than letters and digits.
///
/// # Example
///
/// ```rust
/// use lib_duckcount::cryptography::username::validate_username;
///
/// assert_eq!(validate_username("  Alice42 ").unwrap(), "alice42");
/// assert!(validate_username("42alice").is_err());
/// ```
#[uniffi::export]
pub fn validate_username(username: &str) -> Result<String, UsernameError> {
    let normalized = username.trim().to_ascii_lowercase();

    let first_character = normalized.chars().next().ok_or(UsernameError::Empty)?;

    if !first_character.is_ascii_alphabetic() {
        return Err(UsernameError::MustStartWithLetter);
    }

    if !normalized
        .chars()
        .all(|character| character.is_ascii_alphanumeric())
    {
        return Err(UsernameError::InvalidCharacter);
    }

    Ok(normalized)
}

/// Hashes a username into the digest the server stores as a reserved username.
///
/// The username is validated and normalized first, then hashed with SHA3-512
/// under the [RESERVED_USERNAME_DOMAIN] separator. The server never sees the
/// handle itself, only this digest, and a peer looking the user up computes it
/// from the handle they already know.
///
/// # Arguments
///
/// * `username` - The handle as the user typed it.
///
/// # Returns
///
/// A `Result` containing the digest, encoded as 128 lowercase hexadecimal
/// characters, or a [UsernameError] if the username is not valid.
///
/// # Errors
///
/// Returns the same errors as [validate_username].
///
/// # Example
///
/// ```rust
/// use lib_duckcount::cryptography::username::hash_reserved_username;
///
/// let digest = hash_reserved_username("Alice").unwrap();
///
/// assert_eq!(digest.len(), 128);
/// // Normalization makes the casing irrelevant.
/// assert_eq!(digest, hash_reserved_username("alice").unwrap());
/// ```
#[uniffi::export]
pub fn hash_reserved_username(username: &str) -> Result<String, UsernameError> {
    let normalized = validate_username(username)?;

    let mut hasher = Sha3_512::new();
    hasher.update(RESERVED_USERNAME_DOMAIN.as_bytes());
    hasher.update(normalized.as_bytes());

    Ok(hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
