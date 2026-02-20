#[cfg(test)]
mod tests {
    use crate::cryptography::password::{PASSWORD_LENGHT, generate_password};

    #[test]
    fn test_generate_password() {
        let password = generate_password();
        let password_bis = generate_password();

        assert!(password.len() == PASSWORD_LENGHT as usize);

        assert_ne!(password, password_bis);
    }
}
