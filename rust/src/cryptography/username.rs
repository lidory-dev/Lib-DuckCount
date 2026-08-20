use sha3::{Digest, Sha3_512};
use thiserror::Error;

/// Domain separator prepended to a handle before it is hashed into a discovery
/// username digest.
///
/// A digest minted for discovery can therefore never collide with one minted for
/// another purpose over the same handle.
pub const DISCOVERY_USERNAME_DOMAIN: &str = "duckcount:discovery-username:v1:";

/// Domain separator prepended to the OPAQUE login username before it is hashed.
///
/// Distinct from [DISCOVERY_USERNAME_DOMAIN] on purpose: the same handle used for
/// both purposes yields two unrelated digests, so a discovery username can never
/// double as a credential identifier.
pub const LOGIN_USERNAME_DOMAIN: &str = "duckcount:login-username:v1:";

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

#[uniffi::export]
pub fn normalize_username(username: &str) -> String {
    username
        .to_lowercase()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect()
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
/// # use lib_duckcount::cryptography::username::validate_username;
/// assert!(validate_username("  Alice42 ").is_err());
/// assert!(validate_username("42alice").is_err());
/// ```
#[uniffi::export]
pub fn validate_username(username: &str) -> Result<(), UsernameError> {
    let normalized_username = normalize_username(username);

    if normalized_username.len() == 0 {
        return Err(UsernameError::Empty);
    }

    if username != normalized_username {
        return Err(UsernameError::InvalidCharacter);
    }

    let first_character = username.chars().next().ok_or(UsernameError::Empty)?;

    if !first_character.is_ascii_alphabetic() {
        return Err(UsernameError::MustStartWithLetter);
    }

    Ok(())
}

/// Hashes a username into the digest the server stores as a discovery username.
///
/// The username is validated and normalized first, then hashed with SHA3-512
/// under the [DISCOVERY_USERNAME_DOMAIN] separator. The server never sees the
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
/// # use lib_duckcount::cryptography::username::hash_discovery_username;
/// let digest = hash_discovery_username("Alice").unwrap();
///
/// assert_eq!(digest.len(), 128);
/// // Normalization makes the casing irrelevant.
/// assert_eq!(digest, hash_discovery_username("alice").unwrap());
/// ```
#[uniffi::export]
pub fn hash_discovery_username(username: &str) -> Result<String, UsernameError> {
    let normalized_username = normalize_username(username);

    validate_username(&normalized_username)?;

    Ok(hash_with_domain(
        DISCOVERY_USERNAME_DOMAIN,
        &normalized_username,
    ))
}

/// Hashes the OPAQUE login username into the digest the server knows the account by.
///
/// Unlike a discovery username, this one is an opaque credential identifier that is
/// never shared.
///
/// # Arguments
///
/// * `username` - The login username as the user typed it.
///
/// # Returns
///
/// The digest, encoded as 128 lowercase hexadecimal characters.
/// If an error occurs, returns the same errors as [validate_username].
///
/// # Example
///
/// ```rust
/// # use lib_duckcount::cryptography::username::{hash_login_username, hash_discovery_username};
/// let digest = hash_login_username("Alice").unwrap();
///
/// assert_eq!(digest.len(), 128);
/// assert_eq!(digest, hash_login_username("alice").unwrap());
/// // The same handle never yields the same digest for both purposes.
/// assert_ne!(digest, hash_discovery_username("alice").unwrap());
/// ```
#[uniffi::export]
pub fn hash_login_username(username: &str) -> Result<String, UsernameError> {
    let normalized_username = normalize_username(username);

    validate_username(&normalized_username)?;

    Ok(hash_with_domain(
        LOGIN_USERNAME_DOMAIN,
        &normalized_username,
    ))
}

/// Hashes `value` under `domain` with SHA3-512, hexadecimal encoded.
fn hash_with_domain(domain: &str, value: &str) -> String {
    let mut hasher = Sha3_512::new();

    hasher.update(domain.as_bytes());
    hasher.update(value.as_bytes());

    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
