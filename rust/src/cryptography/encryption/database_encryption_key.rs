use rand::{Rng, rngs::OsRng};

pub const ENCRYPTION_KEY_LENGHT: i8 = 64;
const ENCRYPTION_KEY_CHARSET: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Generates a random encryption key for the database (SQLCipher).
///
/// This function creates a random encryption key of a predefined `ENCRYPTION_KEY_LENGHT` using a predefined `ENCRYPTION_KEY_CHARSET`.
/// It utilizes an operating system provided random number generator for secure random number generation.
///
/// # Returns
///
/// A `String` containing the randomly generated encryption key.
#[uniffi::export]
pub fn generate_database_encryption_key() -> String {
    let mut rng = OsRng;

    let mut password = String::new();

    for _ in 0..ENCRYPTION_KEY_LENGHT {
        password
            .push(ENCRYPTION_KEY_CHARSET[rng.gen_range(0..ENCRYPTION_KEY_CHARSET.len())] as char);
    }

    password
}
