use rand::{Rng, rngs::OsRng};

pub const PASSWORD_LENGHT: i8 = 20;
const PASSWORD_CHARSET: &[u8] =
    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_#$%&()*+;[]";

/// Generates a random password.
///
/// This function creates a random password of a predefined `PASSWORD_LENGHT` using a predefined `PASSWORD_CHARSET`.
/// It utilizes an operating system provided random number generator for secure random number generation.
///
/// # Returns
///
/// A `String` containing the randomly generated password.
#[uniffi::export]
pub fn generate_password() -> String {
    let mut rng = OsRng;

    let mut password = String::new();

    for _ in 0..PASSWORD_LENGHT {
        password.push(PASSWORD_CHARSET[rng.gen_range(0..PASSWORD_CHARSET.len())] as char);
    }

    password
}
