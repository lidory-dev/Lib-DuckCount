#[cfg(test)]
mod tests {
    use opaque_ke::{
        CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin,
        ServerLoginStartParameters, ServerRegistration, ServerSetup,
    };
    use rand::rngs::OsRng;

    use crate::cryptography::{
        authentication::{
            AuthenticationError, DefaultCipherSuite, login::Login, registration::Registration,
            registration::RegistrationFinishResult,
        },
        vault::encrypted_field::EncryptedField,
    };

    const USERNAME: &str = "duckcountgreatestuser";
    const PASSWORD: &str = "GJJ%As6Vkdz3m$Ujj$#v";
    const OTHER_PASSWORD: &str = "Cu2ScxGK0tvMA^6MBz3@";

    /// Runs a whole OPAQUE registration against an in-process server, returning
    /// what each side ends up holding: the client's finish result (which carries
    /// the vault root key, in the clear and sealed) and the server's password
    /// file.
    ///
    /// The server half is the same three-step exchange as `finish_registration`
    /// in DuckCount-API, kept here so the client can be tested without one.
    fn register(
        server_setup: &ServerSetup<DefaultCipherSuite>,
        password: &str,
    ) -> (RegistrationFinishResult, Vec<u8>) {
        let registration = Registration::new();

        let request_bytes = registration.start(password).unwrap();

        let server_start = ServerRegistration::<DefaultCipherSuite>::start(
            server_setup,
            RegistrationRequest::deserialize(&request_bytes).unwrap(),
            USERNAME.as_bytes(),
        )
        .unwrap();

        let finish_result = registration
            .finish(&server_start.message.serialize().to_vec(), password)
            .unwrap();

        let password_file = ServerRegistration::finish(
            RegistrationUpload::<DefaultCipherSuite>::deserialize(&finish_result.message).unwrap(),
        );

        (finish_result, password_file.serialize().to_vec())
    }

    /// Runs a whole OPAQUE login against an in-process server, returning the
    /// [Login] that finished it.
    ///
    /// The returned object still holds the export key, so it is the only thing
    /// that can unseal a root key, and only once.
    fn log_in(
        server_setup: &ServerSetup<DefaultCipherSuite>,
        password: &str,
        password_file_bytes: &[u8],
    ) -> Login {
        let login = Login::new();

        let credential_request_bytes = login.start(password).unwrap();

        let password_file =
            ServerRegistration::<DefaultCipherSuite>::deserialize(password_file_bytes).unwrap();

        let server_start = ServerLogin::start(
            &mut OsRng,
            server_setup,
            Some(password_file),
            CredentialRequest::deserialize(&credential_request_bytes).unwrap(),
            USERNAME.as_bytes(),
            ServerLoginStartParameters::default(),
        )
        .unwrap();

        login
            .finish(&server_start.message.serialize().to_vec(), password)
            .unwrap();

        login
    }

    /// The round trip the whole scheme rests on: what registration sealed under
    /// the export key, a later login with the same password unseals byte for
    /// byte.
    ///
    /// This is what catches the export key being the wrong width for the AEAD
    /// helpers: [DefaultCipherSuite] hashes with SHA-512, so the export key is
    /// 64 bytes while AES-256-GCM takes 32, and without
    /// [root_key_wrapping_key](crate::cryptography::authentication::root_key_wrapping_key)
    /// registration fails outright.
    #[test]
    fn test_root_key_survives_a_registration_and_login_round_trip() {
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

        let (registration_result, password_file) = register(&server_setup, PASSWORD);

        let login = log_in(&server_setup, PASSWORD, &password_file);

        let sealed_root_key = EncryptedField::from_parts(
            &registration_result.encrypted_root_key.cipher_text,
            &registration_result.encrypted_root_key.nonce,
        );

        let root_key = login.unseal_root_key(&sealed_root_key).unwrap();

        assert_eq!(root_key, registration_result.root_key);
    }

    /// The export key is zeroized once it has unsealed a root key, so a second
    /// attempt on the same session fails rather than succeeding again.
    ///
    /// It must fail as [AuthenticationError::RootKeyDecryptionFailed]: zeroizing
    /// a `Vec` clears it as well as blanking it, so a spent export key is
    /// *empty*, and slicing 32 bytes out of it would panic instead.
    #[test]
    fn test_a_root_key_cannot_be_unsealed_twice() {
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

        let (registration_result, password_file) = register(&server_setup, PASSWORD);

        let login = log_in(&server_setup, PASSWORD, &password_file);

        let sealed_root_key = EncryptedField::from_parts(
            &registration_result.encrypted_root_key.cipher_text,
            &registration_result.encrypted_root_key.nonce,
        );

        login.unseal_root_key(&sealed_root_key).unwrap();

        assert!(matches!(
            login.unseal_root_key(&sealed_root_key),
            Err(AuthenticationError::RootKeyDecryptionFailed)
        ));
    }

    /// A root key is bound to the password it was sealed under, a session
    /// established with a different password cannot open it.
    ///
    /// This is the property that keeps the server blind. It holds the sealed
    /// blob and never the key to it, so a login it did not authenticate reveals
    /// nothing.
    #[test]
    fn test_a_root_key_cannot_be_unsealed_by_another_password() {
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

        let (registration_result, _) = register(&server_setup, PASSWORD);
        let (_, other_password_file) = register(&server_setup, OTHER_PASSWORD);

        let login = log_in(&server_setup, OTHER_PASSWORD, &other_password_file);

        let sealed_root_key = EncryptedField::from_parts(
            &registration_result.encrypted_root_key.cipher_text,
            &registration_result.encrypted_root_key.nonce,
        );

        assert!(matches!(
            login.unseal_root_key(&sealed_root_key),
            Err(AuthenticationError::RootKeyDecryptionFailed)
        ));
    }

    /// Unsealing before [Login::finish] has run fails instead of panicking:
    /// there is no export key yet, so the empty buffer takes the same path as a
    /// spent one.
    #[test]
    fn test_unsealing_before_finishing_the_login_fails() {
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

        let (registration_result, _) = register(&server_setup, PASSWORD);

        let sealed_root_key = EncryptedField::from_parts(
            &registration_result.encrypted_root_key.cipher_text,
            &registration_result.encrypted_root_key.nonce,
        );

        assert!(matches!(
            Login::new().unseal_root_key(&sealed_root_key),
            Err(AuthenticationError::RootKeyDecryptionFailed)
        ));
    }
}
