use std::fmt::Display;

use argon2::password_hash::SaltString;

use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

use crate::cryptography::{
    encryption::{
        EncryptionError, KeyError,
        decrypt::decrypt_using_symmetric_key,
        keys::{KeyUsage, derive_key},
    },
    vault::{encrypted_field::EncryptedField, group_metadata::GroupMetadata},
};

/// User vault related errors.
#[derive(Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum UserVaultError {
    KeyError(KeyError),
    EncryptionError(EncryptionError),
    SerializationFailed,
    DeserializationFailed,
}

impl Display for UserVaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserVaultError::KeyError(e) => write!(f, "Key error: {}", e),
            UserVaultError::EncryptionError(e) => write!(f, "Encryption error: {}", e),
            UserVaultError::SerializationFailed => write!(f, "Serialization failed."),
            UserVaultError::DeserializationFailed => write!(f, "Deserialization failed."),
        }
    }
}

/// The user vault, which stores all user information securely on the server.
///
/// The server has no access to any fields of the vault, as everything is encrypted
/// before being sent to the server.
#[derive(uniffi::Object, Serialize, Deserialize, Clone)]
pub struct UserVault {
    salt: String,
    /// An encrypted JSON object representing a list of group UUID,
    /// along with their corresponding group master key.
    groups_metadata: EncryptedField,
}

#[uniffi::export]
impl UserVault {
    /// Creates a new, empty `UserVault` instance using the provided secret.
    ///
    /// This constructor generates a cryptographically secure salt, derives an encryption key from the provided `secret`, and generated salt.
    /// An empty list of groups metadata is encrypted using the derived key and stored in the vault.
    ///
    /// # Arguments
    ///
    /// * `secret` - A reference to a byte vector used as the base for key derivation. This secret is required to encrypt and decrypt the vault's contents.
    ///
    /// # Returns
    ///
    /// * `Result<Self, UserVaultError>` - A new `UserVault` instance if successful, or an error if key derivation or encryption fails.
    ///
    /// # Errors
    ///
    /// * `UserVaultError::KeyError` - If the encryption key derivation fails.
    /// * `UserVaultError::EncryptionError` - If encrypting the groups metadata fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lib_duckcount::cryptography::vault::vault::UserVault;
    ///
    /// let secret = "&eHml-C_AFyWdylXLd50".as_bytes().to_vec();
    ///
    /// let user_vault = UserVault::new(&secret).unwrap();
    /// ```
    #[uniffi::constructor]
    pub fn new(secret: &Vec<u8>) -> Result<Self, UserVaultError> {
        let salt = SaltString::generate(&mut OsRng);

        let encryption_key = derive_key(secret, salt.to_string(), KeyUsage::NonDeterministic)
            .map_err(|_| UserVaultError::KeyError(KeyError::DerivationFailed))?;

        let encrypted_groups_metadata =
            EncryptedField::new(&encryption_key, &"[]".as_bytes().to_vec())
                .map_err(|_| UserVaultError::EncryptionError(EncryptionError::EncryptionFailed))?;

        Ok(UserVault {
            salt: salt.to_string(),
            groups_metadata: encrypted_groups_metadata,
        })
    }

    /// Creates a new `UserVault` instance by deserializing a JSON string.
    ///
    /// This constructor parses the provided JSON string and constructs a `UserVault` instance.
    /// It is useful for restoring a previously serialized vault, such as from persistent storage.
    ///
    /// # Arguments
    ///
    /// * `json` - A string slice containing the JSON representation of a `UserVault`.
    ///
    /// # Returns
    ///
    /// * `Result<Self, UserVaultError>` - A new `UserVault` instance if deserialization succeeds, or an error if the JSON is malformed or invalid.
    ///
    /// # Errors
    ///
    /// * `UserVaultError::DeserializationFailed` - If the JSON string cannot be deserialized into a `UserVault`.
    #[uniffi::constructor]
    pub fn from_json(json: &str) -> Result<Self, UserVaultError> {
        serde_json::from_str(json).map_err(|_| UserVaultError::DeserializationFailed)
    }

    /// Serializes the `UserVault` instance into a JSON string.
    ///
    /// This method converts the current `UserVault` into its JSON representation,
    /// which can be used for storage or transmission. The resulting JSON string
    /// can later be deserialized back into a `UserVault` using the `from_json` constructor.
    ///
    /// # Returns
    ///
    /// * `Result<String, UserVaultError>` - A JSON string representing the `UserVault` if serialization succeeds,
    ///   or an error if the serialization process fails.
    ///
    /// # Errors
    ///
    /// * `UserVaultError::SerializationFailed` - If the `UserVault` cannot be serialized into a JSON string.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lib_duckcount::cryptography::vault::vault::UserVault;
    ///
    /// let secret = "&eHml-C_AFyWdylXLd50".as_bytes().to_vec();
    ///
    /// let user_vault = UserVault::new(&secret).unwrap();
    ///
    /// let user_vault_json = user_vault.to_json().unwrap();
    ///
    /// println!("Serialized vault: {}", user_vault_json);
    /// ```
    pub fn to_json(&self) -> Result<String, UserVaultError> {
        serde_json::to_string(&self).map_err(|_| UserVaultError::SerializationFailed)
    }

    /// Derives an encryption key from the provided secret and the vault's salt.
    ///
    /// This method uses the vault's stored salt to derive a symmetric encryption key.
    /// The derived key is used for encrypting and decrypting sensitive data within the vault.
    ///
    /// # Arguments
    ///
    /// * `secret` - A secret key (as a byte vector) used as the base for key derivation.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<u8>, UserVaultError>` - The derived encryption key as a byte vector, or an error if key derivation fails.
    ///
    /// # Errors
    ///
    /// * `UserVaultError::KeyError` - If the key derivation process fails.
    fn derive_encryption_key(&self, secret: &Vec<u8>) -> Result<Vec<u8>, UserVaultError> {
        derive_key(secret, self.salt.to_string(), KeyUsage::NonDeterministic)
            .map_err(|_| UserVaultError::KeyError(KeyError::DerivationFailed))
    }

    /// Retrieves the list of group metadata stored in the vault.
    ///
    /// This method decrypts the encrypted list of group metadata using the provided `secret`,
    /// and returns the deserialized list as a vector of `GroupMetadata` objects.
    ///
    /// # Arguments
    ///
    /// * `secret` - A secret key (as a byte vector) used to derive the encryption key for decrypting the list of group metadata.
    ///
    /// # Returns
    ///
    /// * `Result<Vec<GroupMetadata>, UserVaultError>` - A vector of `GroupMetadata` objects, each containing the metadata for a group,
    ///   or an error if decryption or deserialization fails.
    ///
    /// # Errors
    ///
    /// * `UserVaultError::KeyError` - If the encryption key derivation fails.
    /// * `UserVaultError::EncryptionError` - If decryption of the list of group metadata fails.
    /// * `UserVaultError::DeserializationFailed` - If deserialization of the decrypted data into `Vec<GroupMetadata>` fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lib_duckcount::cryptography::vault::vault::UserVault;
    ///
    /// let secret = "&eHml-C_AFyWdylXLd50".as_bytes().to_vec();
    ///
    /// // Please note that the list of groups metadata is empty for a new vault.
    /// let user_vault = UserVault::new(&secret).unwrap();
    ///
    /// let groups_metadata = user_vault.groups_metadata(&secret).unwrap();
    /// for group_metadata in groups_metadata {
    ///     println!("Group metadata: {:?}", group_metadata.uuid);
    /// }
    /// ```
    pub fn groups_metadata(&self, secret: &Vec<u8>) -> Result<Vec<GroupMetadata>, UserVaultError> {
        let encryption_key = self.derive_encryption_key(secret)?;

        let decrypted_groups_metadata = decrypt_using_symmetric_key(
            &encryption_key,
            &self.groups_metadata.field,
            &self.groups_metadata.nonce,
        )
        .map_err(|_| UserVaultError::EncryptionError(EncryptionError::DecryptionFailed))?;

        Ok(serde_json::from_slice(decrypted_groups_metadata.as_slice())
            .map_err(|_| UserVaultError::DeserializationFailed)?)
    }

    /// Creates a new `UserVault` with an additional group metadata.
    ///
    /// This method decrypts the current list of groups metadata, appends the new `GroupMetadata`,
    /// re-encrypts the updated list, and returns a new `UserVault` instance with the updated state.
    ///
    /// # Arguments
    ///
    /// * `secret` - A secret key (as a byte vector) used to derive the encryption key for decrypting and re-encrypting the groups metadata.
    /// * `group_metadata` - The new `GroupMetadata` to add to the vault's list of groups metadata.
    ///
    /// # Returns
    ///
    /// * `Result<UserVault, UserVaultError>` - A new `UserVault` instance with the updated list of groups metadata,
    ///     or an error if decryption, serialization, or encryption fails.
    ///
    /// # Errors
    ///
    /// * `UserVaultError::KeyError` - If the encryption key derivation fails.
    /// * `UserVaultError::EncryptionError` - If decryption or encryption of the group master keys fails.
    /// * `UserVaultError::DeserializationFailed` - If deserialization of the list of groups metadata fails during the process.
    ///
    /// # Example
    ///
    /// ```rust
    /// use lib_duckcount::cryptography::vault::{group_metadata::GroupMetadata, vault::UserVault};
    ///
    /// let secret = "&eHml-C_AFyWdylXLd50".as_bytes().to_vec();
    ///
    /// let user_vault = UserVault::new(&secret).unwrap();
    ///
    /// let group_uuid = String::from("deab0e9a-1c9a-4028-81f6-8a76688af5fb");
    /// let group_master_key = "6%CejBWW@fq*...".as_bytes().to_vec();
    /// let group = GroupMetadata { uuid: group_uuid, master_key: group_master_key };
    ///
    /// let updated_vault = user_vault.with_added_group(&secret, group).unwrap();
    /// ```
    pub fn with_added_group(
        &self,
        secret: &Vec<u8>,
        group_metadata: GroupMetadata,
    ) -> Result<UserVault, UserVaultError> {
        let mut groups_metadata = self.groups_metadata(secret)?;

        groups_metadata.push(group_metadata);

        let encryption_key = self.derive_encryption_key(secret)?;

        let serialized_groups_metadata = serde_json::to_string(&groups_metadata)
            .map_err(|_| UserVaultError::DeserializationFailed)?;

        let encrypted_groups_metadata = EncryptedField::new(
            &encryption_key,
            &serialized_groups_metadata.as_bytes().to_vec(),
        )
        .map_err(|_| UserVaultError::EncryptionError(EncryptionError::EncryptionFailed))?;

        let mut new_vault = self.clone();

        new_vault.groups_metadata = encrypted_groups_metadata;

        Ok(new_vault)
    }
}
