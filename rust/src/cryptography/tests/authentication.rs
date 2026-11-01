#[cfg(test)]
mod tests {
    use opaque_ke::{
        CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
        ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
    };
    use rand::rngs::OsRng;

    use crate::cryptography::{
        authentication::{
            AuthenticationError, DefaultCipherSuite,
            login::Login,
            password_change::{
                PasswordChange, PasswordChangeFinishResult, PasswordChangeStartResult,
            },
            reauth::ReAuth,
            registration::{Registration, RegistrationFinishResult},
        },
        encryption::encrypted_field::EncryptedField,
    };

    const USERNAME: &str = "duckcountgreatestuser";
    const PASSWORD: &str = "GJJ%As6Vkdz3m$Ujj$#v";
    const OTHER_PASSWORD: &str = "Cu2ScxGK0tvMA^6MBz3@";
    const NEW_PASSWORD: &str = "q8;Wd(Rk3%Zt_Hn7]Lb#";

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
        try_log_in(server_setup, password, password_file_bytes).unwrap()
    }

    /// [log_in], for a login that may be turned down: the client's finish step
    /// is where a password that does not open the password file's envelope
    /// fails.
    fn try_log_in(
        server_setup: &ServerSetup<DefaultCipherSuite>,
        password: &str,
        password_file_bytes: &[u8],
    ) -> Result<Login, AuthenticationError> {
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
            ServerLoginParameters::default(),
        )
        .unwrap();

        login.finish(&server_start.message.serialize().to_vec(), password)?;

        Ok(login)
    }

    /// The server's half of starting a password change, as
    /// `start_password_change` in DuckCount-API: a login against the stored
    /// password file and a registration of the new password, under the same
    /// identifier.
    ///
    /// Returns the login state the server finishes with, then the credential
    /// response and the registration response to hand to
    /// [PasswordChange::finish].
    fn answer_password_change(
        server_setup: &ServerSetup<DefaultCipherSuite>,
        password_file_bytes: &[u8],
        start_result: &PasswordChangeStartResult,
    ) -> (ServerLogin<DefaultCipherSuite>, Vec<u8>, Vec<u8>) {
        let password_file =
            ServerRegistration::<DefaultCipherSuite>::deserialize(password_file_bytes).unwrap();

        let server_login_start = ServerLogin::start(
            &mut OsRng,
            server_setup,
            Some(password_file),
            CredentialRequest::deserialize(&start_result.credential_request).unwrap(),
            USERNAME.as_bytes(),
            ServerLoginParameters::default(),
        )
        .unwrap();

        let server_registration_start = ServerRegistration::<DefaultCipherSuite>::start(
            server_setup,
            RegistrationRequest::deserialize(&start_result.registration_request).unwrap(),
            USERNAME.as_bytes(),
        )
        .unwrap();

        (
            server_login_start.state,
            server_login_start.message.serialize().to_vec(),
            server_registration_start.message.serialize().to_vec(),
        )
    }

    /// Runs a whole password change against an in-process server, returning
    /// what each side ends up holding: the client's finish result (which carries
    /// the root key sealed under the new password) and the server's new
    /// password file.
    ///
    /// The server half is [answer_password_change] and then what
    /// `finish_password_change` in DuckCount-API does: the login is finished,
    /// which is where the server checks the current password, before the new
    /// password file is built from the upload.
    fn change_password(
        server_setup: &ServerSetup<DefaultCipherSuite>,
        password_file_bytes: &[u8],
        current_password: &str,
        new_password: &str,
        root_key: &[u8],
    ) -> (PasswordChangeFinishResult, Vec<u8>) {
        let password_change = PasswordChange::new();

        let start_result = password_change
            .start(current_password, new_password)
            .unwrap();

        let (server_login, credential_response, registration_response) =
            answer_password_change(server_setup, password_file_bytes, &start_result);

        let finish_result = password_change
            .finish(
                credential_response,
                registration_response,
                current_password,
                new_password,
                root_key.to_vec(),
            )
            .unwrap();

        server_login
            .finish(
                CredentialFinalization::deserialize(&finish_result.credential_finalization)
                    .unwrap(),
                ServerLoginParameters::default(),
            )
            .unwrap();

        let password_file = ServerRegistration::finish(
            RegistrationUpload::<DefaultCipherSuite>::deserialize(
                &finish_result.registration_upload,
            )
            .unwrap(),
        );

        (finish_result, password_file.serialize().to_vec())
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
            &registration_result.encrypted_root_key.ciphertext,
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
            &registration_result.encrypted_root_key.ciphertext,
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
            &registration_result.encrypted_root_key.ciphertext,
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
            &registration_result.encrypted_root_key.ciphertext,
            &registration_result.encrypted_root_key.nonce,
        );

        assert!(matches!(
            Login::new().unseal_root_key(&sealed_root_key),
            Err(AuthenticationError::RootKeyDecryptionFailed)
        ));
    }

    /// The credential response is the server's to write, so one that is not
    /// one is refused rather than trusted to parse.
    #[test]
    fn test_a_reauth_refuses_a_malformed_credential_response() {
        for response in [vec![], vec![0; 319], vec![0; 320], b"{}".to_vec()] {
            let reauth = ReAuth::new();
            reauth.start(PASSWORD).unwrap();

            assert!(matches!(
                reauth.finish(&response, PASSWORD),
                Err(AuthenticationError::CredentialResponseDeserializationFailed)
            ));
        }
    }

    /// The point of a password change: the user keeps the root key they have,
    /// so the key ring it seals, and everything under that, opens as before.
    /// A login with the new password against the new password file unseals the
    /// very key registration produced.
    #[test]
    fn test_a_password_change_keeps_the_root_key() {
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

        let (registration_result, password_file) = register(&server_setup, PASSWORD);

        let (change_result, new_password_file) = change_password(
            &server_setup,
            &password_file,
            PASSWORD,
            OTHER_PASSWORD,
            &registration_result.root_key,
        );

        let login = log_in(&server_setup, OTHER_PASSWORD, &new_password_file);

        let sealed_root_key = EncryptedField::from_parts(
            &change_result.encrypted_root_key.ciphertext,
            &change_result.encrypted_root_key.nonce,
        );

        let root_key = login.unseal_root_key(&sealed_root_key).unwrap();

        assert_eq!(root_key, registration_result.root_key);
    }

    /// The new password file is a registration of the new password only, so
    /// the old one is turned down by it, on the client, as any wrong password.
    #[test]
    fn test_the_old_password_no_longer_logs_in_after_a_change() {
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

        let (registration_result, password_file) = register(&server_setup, PASSWORD);

        let (_, new_password_file) = change_password(
            &server_setup,
            &password_file,
            PASSWORD,
            OTHER_PASSWORD,
            &registration_result.root_key,
        );

        assert!(matches!(
            try_log_in(&server_setup, PASSWORD, &new_password_file),
            Err(AuthenticationError::ClientLoginFinalizationFailed(_))
        ));
    }

    /// A wrong current password fails the login half on the client, as a
    /// [Login] does, so the caller can tell it apart: the result is an error,
    /// with no credential finalization, registration upload or sealed root key
    /// to send, and the password file stays what it was.
    ///
    /// The attempt is spent all the same, both states having been consumed: the
    /// credential request was blinded from the wrong password, so a retry has
    /// to start over.
    #[test]
    fn test_a_password_change_refuses_a_wrong_current_password() {
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

        let (registration_result, password_file) = register(&server_setup, PASSWORD);

        let password_change = PasswordChange::new();

        let start_result = password_change.start(OTHER_PASSWORD, NEW_PASSWORD).unwrap();

        let (_, credential_response, registration_response) =
            answer_password_change(&server_setup, &password_file, &start_result);

        assert!(matches!(
            password_change.finish(
                credential_response.clone(),
                registration_response.clone(),
                OTHER_PASSWORD,
                NEW_PASSWORD,
                registration_result.root_key.clone(),
            ),
            Err(AuthenticationError::ClientLoginFinalizationFailed(_))
        ));

        assert!(matches!(
            password_change.finish(
                credential_response,
                registration_response,
                OTHER_PASSWORD,
                NEW_PASSWORD,
                registration_result.root_key,
            ),
            Err(AuthenticationError::FinishCalledBeforeStart)
        ));
    }

    /// Finishing before [PasswordChange::start] has run fails instead of
    /// panicking: there is no state to finish either handshake from.
    #[test]
    fn test_finishing_a_password_change_before_starting_it_fails() {
        assert!(matches!(
            PasswordChange::new().finish(vec![], vec![], PASSWORD, OTHER_PASSWORD, vec![0; 32]),
            Err(AuthenticationError::FinishCalledBeforeStart)
        ));
    }

    /// Both states are consumed by the first finish, so a session yields one
    /// pair of messages and one seal at most.
    #[test]
    fn test_a_password_change_cannot_be_finished_twice() {
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

        let (registration_result, password_file) = register(&server_setup, PASSWORD);

        let password_change = PasswordChange::new();

        let start_result = password_change.start(PASSWORD, OTHER_PASSWORD).unwrap();

        let (_, credential_response, registration_response) =
            answer_password_change(&server_setup, &password_file, &start_result);

        password_change
            .finish(
                credential_response.clone(),
                registration_response.clone(),
                PASSWORD,
                OTHER_PASSWORD,
                registration_result.root_key.clone(),
            )
            .unwrap();

        assert!(matches!(
            password_change.finish(
                credential_response,
                registration_response,
                PASSWORD,
                OTHER_PASSWORD,
                registration_result.root_key,
            ),
            Err(AuthenticationError::FinishCalledBeforeStart)
        ));
    }

    /// Even a change to the very same password leaves the old seal unopenable:
    /// the export key is derived from the password file's envelope, and a
    /// registration seals a new one every time. Only the seal the change made
    /// opens against the new password file.
    ///
    /// This is why the server writes the new seal in the same transaction as
    /// the new password file, rather than leaving the client to send it after:
    /// once the file is in, nothing opens the old seal again.
    #[test]
    fn test_a_change_to_the_same_password_still_replaces_the_seal() {
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

        let (registration_result, password_file) = register(&server_setup, PASSWORD);

        let (change_result, new_password_file) = change_password(
            &server_setup,
            &password_file,
            PASSWORD,
            PASSWORD,
            &registration_result.root_key,
        );

        let login = log_in(&server_setup, PASSWORD, &new_password_file);

        let old_seal = EncryptedField::from_parts(
            &registration_result.encrypted_root_key.ciphertext,
            &registration_result.encrypted_root_key.nonce,
        );

        assert!(matches!(
            login.unseal_root_key(&old_seal),
            Err(AuthenticationError::RootKeyDecryptionFailed)
        ));

        let new_seal = EncryptedField::from_parts(
            &change_result.encrypted_root_key.ciphertext,
            &change_result.encrypted_root_key.nonce,
        );

        assert_eq!(
            login.unseal_root_key(&new_seal).unwrap(),
            registration_result.root_key
        );
    }

    /// The new seal is under the new password only: a session the old
    /// password opened against the old password file, the export key a device
    /// held before the change, cannot open it.
    #[test]
    fn test_the_old_password_cannot_open_the_new_seal() {
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

        let (registration_result, password_file) = register(&server_setup, PASSWORD);

        let old_login = log_in(&server_setup, PASSWORD, &password_file);

        let (change_result, _) = change_password(
            &server_setup,
            &password_file,
            PASSWORD,
            OTHER_PASSWORD,
            &registration_result.root_key,
        );

        let new_seal = EncryptedField::from_parts(
            &change_result.encrypted_root_key.ciphertext,
            &change_result.encrypted_root_key.nonce,
        );

        assert!(matches!(
            old_login.unseal_root_key(&new_seal),
            Err(AuthenticationError::RootKeyDecryptionFailed)
        ));
    }

    /// Both responses are the server's to write, so one that is not one is
    /// refused rather than trusted to parse, whichever of the two it is.
    #[test]
    fn test_a_password_change_refuses_malformed_server_responses() {
        let server_setup = ServerSetup::<DefaultCipherSuite>::new(&mut OsRng);

        let (registration_result, password_file) = register(&server_setup, PASSWORD);

        for response in [vec![], vec![0; 319], vec![0; 320], b"{}".to_vec()] {
            let password_change = PasswordChange::new();

            let start_result = password_change.start(PASSWORD, OTHER_PASSWORD).unwrap();

            let (_, _, registration_response) =
                answer_password_change(&server_setup, &password_file, &start_result);

            assert!(matches!(
                password_change.finish(
                    response,
                    registration_response,
                    PASSWORD,
                    OTHER_PASSWORD,
                    registration_result.root_key.clone(),
                ),
                Err(AuthenticationError::CredentialResponseDeserializationFailed)
            ));
        }

        for response in [vec![], vec![0; 63], vec![0; 64], b"{}".to_vec()] {
            let password_change = PasswordChange::new();

            let start_result = password_change.start(PASSWORD, OTHER_PASSWORD).unwrap();

            let (_, credential_response, _) =
                answer_password_change(&server_setup, &password_file, &start_result);

            assert!(matches!(
                password_change.finish(
                    credential_response,
                    response,
                    PASSWORD,
                    OTHER_PASSWORD,
                    registration_result.root_key.clone(),
                ),
                Err(AuthenticationError::RegistrationResponseDeserializationFailed)
            ));
        }
    }
}
