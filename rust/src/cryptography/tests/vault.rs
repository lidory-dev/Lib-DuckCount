#[cfg(test)]
mod tests {
    use crate::cryptography::vault::vault::UserVault;

    const PASSWORD: &str = "&eHml-C_AFyWdylXLd50";

    // TODO: Find a way to better test the user vault creation.
    #[test]
    fn test_new_vault() {
        UserVault::new(&PASSWORD.as_bytes().to_vec()).unwrap();
    }

    #[test]
    fn test_vault_serialization() {
        let user_vault = UserVault::new(&PASSWORD.as_bytes().to_vec()).unwrap();

        user_vault.to_json().unwrap();
    }

    #[test]
    fn test_vault_groups_metadata() {
        let user_vault = UserVault::new(&PASSWORD.as_bytes().to_vec()).unwrap();

        user_vault
            .groups_metadata(&PASSWORD.as_bytes().to_vec())
            .unwrap();
    }
}
