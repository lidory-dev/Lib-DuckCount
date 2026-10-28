#[cfg(test)]
mod tests {
    //! The largest message of each kind the app sends, built through this
    //! library as the app builds it, against the cap the DuckCount API holds
    //! the field it travels in to.
    //!
    //! Nothing in a message's size is the user's: it grows with the members of
    //! a group, the keys a share carries and the beneficiaries of each, all of
    //! them capped, and with whatever mls-rs and the cipher suite make of
    //! those. A change to either can grow every message past what the API
    //! takes, which nothing else would show until a group of a hundred was
    //! refused, so the worst cases are built here, a hundred members at a time.

    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;
    use mls_rs::identity::SigningIdentity;
    use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
    use mls_rs::{CipherSuiteProvider, Client, CryptoProvider, ExtensionList};
    use serde_json::{Map, Value, json};
    use uuid::Uuid;

    use crate::cryptography::mls::client::MlsClient;
    use crate::cryptography::mls::config::{crypto_provider, mls_rules};
    use crate::cryptography::mls::storage::group_state::with_limits_outside_tests;
    use crate::cryptography::mls::storage::{MlsNamespace, MlsStore, MlsStoreError};
    use crate::cryptography::mls::types::InviteeKeyPackage;
    use crate::cryptography::mls::{CIPHER_SUITE, MAX_GROUP_MEMBERS};

    // The DuckCount API's caps, each the most characters the field may hold as
    // it sits in the request's JSON, Base64 or the envelope's own JSON. They
    // change with the API's (`MAX_WELCOME_LENGTH` and the others it defines
    // beside it), and this has to keep up.

    /// `welcome_message`, on `POST /groups` and `POST /groups/{uuid}/members`.
    const MAX_WELCOME_LENGTH: usize = 512 * 1024;

    /// `commit_message`, on `POST` and `DELETE /groups/{uuid}/members`.
    const MAX_COMMIT_LENGTH: usize = 640 * 1024;

    /// `profile_keys_message`, `key_message` and a group post's `ciphertext`.
    const MAX_GROUP_APPLICATION_MESSAGE_LENGTH: usize = 32 * 1024;

    /// A direct message's `ciphertext`, the envelope the app sends it in.
    const MAX_DIRECT_MESSAGE_LENGTH: usize = 256 * 1024;

    /// Each key package of `PUT /users/{uuid}/key-package`.
    const MAX_KEY_PACKAGE_LENGTH: usize = 8 * 1024;

    /// The most serialized plaintext one share of the keys to one-time
    /// expenses carries, `ExpenseKeyShare.MAX_PLAINTEXT_BYTES` in the app,
    /// which cuts a larger one into shares of at most this.
    const MAX_KEY_SHARE_PLAINTEXT: usize = 96 * 1024;

    const SECRET: &[u8] = b"&eHml-C_AFyWdylXLd50";

    /// An [`MlsStore`] kept in memory, standing in for the host's database.
    #[derive(Default)]
    struct MemoryStore {
        records: Mutex<HashMap<(u8, Vec<u8>), Vec<u8>>>,
    }

    impl MlsStore for MemoryStore {
        fn get(
            &self,
            namespace: MlsNamespace,
            key: Vec<u8>,
        ) -> Result<Option<Vec<u8>>, MlsStoreError> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .get(&(namespace.tag(), key))
                .cloned())
        }

        fn put(
            &self,
            namespace: MlsNamespace,
            key: Vec<u8>,
            value: Vec<u8>,
        ) -> Result<(), MlsStoreError> {
            self.records
                .lock()
                .unwrap()
                .insert((namespace.tag(), key), value);

            Ok(())
        }

        fn delete(&self, namespace: MlsNamespace, key: Vec<u8>) -> Result<(), MlsStoreError> {
            self.records.lock().unwrap().remove(&(namespace.tag(), key));

            Ok(())
        }

        fn keys(&self, namespace: MlsNamespace) -> Result<Vec<Vec<u8>>, MlsStoreError> {
            Ok(self
                .records
                .lock()
                .unwrap()
                .keys()
                .filter(|(tag, _)| *tag == namespace.tag())
                .map(|(_, key)| key.clone())
                .collect())
        }
    }

    /// The key packages of `count` users nobody has met, each from a plain
    /// mls-rs client running the rules of this library: opening an
    /// [`MlsClient`] derives its sealing key slowly by design, which a hundred
    /// members cannot afford.
    fn stranger_invitations(count: usize) -> Vec<InviteeKeyPackage> {
        (0..count)
            .map(|_| {
                let user_uuid = Uuid::new_v4().to_string();

                let crypto_provider = crypto_provider();
                let cipher_suite_provider =
                    crypto_provider.cipher_suite_provider(CIPHER_SUITE).unwrap();
                let (secret, public) = cipher_suite_provider.signature_key_generate().unwrap();

                let key_package = Client::builder()
                    .identity_provider(BasicIdentityProvider)
                    .crypto_provider(crypto_provider)
                    .mls_rules(mls_rules())
                    .signing_identity(
                        SigningIdentity::new(
                            BasicCredential::new(user_uuid.clone().into_bytes()).into_credential(),
                            public,
                        ),
                        secret,
                        CIPHER_SUITE,
                    )
                    .build()
                    .generate_key_package_message(
                        ExtensionList::default(),
                        ExtensionList::default(),
                        None,
                    )
                    .unwrap()
                    .to_bytes()
                    .unwrap();

                InviteeKeyPackage {
                    user_uuid,
                    key_package,
                }
            })
            .collect()
    }

    /// A key as the app encodes one, Base64 of 32 bytes.
    fn encoded_key() -> String {
        BASE64_STANDARD.encode([7u8; 32])
    }

    /// The key to the profile of each of `member_uuids`, by UUID, as the app
    /// hands them out.
    fn profile_keys(member_uuids: &[String]) -> Map<String, Value> {
        member_uuids
            .iter()
            .map(|uuid| (uuid.clone(), Value::String(encoded_key())))
            .collect()
    }

    /// What the app's Welcome to a group of `member_uuids` hands over, its
    /// `WelcomePayload`: the group's key and every member's profile key.
    fn welcome_payload(member_uuids: &[String]) -> Vec<u8> {
        json!({ "group_key": encoded_key(), "profile_keys": profile_keys(member_uuids) })
            .to_string()
            .into_bytes()
    }

    /// The application message the app's creator sends the members already in
    /// a group as he adds somebody, its `ProfileKeysMessage`: the largest the
    /// app posts in a group, the key a rotation hands over and a member's own
    /// profile key being a key each.
    fn profile_keys_message(member_uuids: &[String]) -> Vec<u8> {
        json!({ "type": "profile_keys", "profile_encryption_keys": profile_keys(member_uuids) })
            .to_string()
            .into_bytes()
    }

    /// `bytes` as the request carries them.
    fn wire_length(bytes: &[u8]) -> usize {
        BASE64_STANDARD.encode(bytes).len()
    }

    #[test]
    fn test_the_largest_message_of_each_kind_fits_the_cap_the_api_holds_it_to() {
        with_limits_outside_tests(|| {
            let creator_uuid = Uuid::new_v4().to_string();
            let creator = MlsClient::new(
                creator_uuid.clone(),
                SECRET.to_vec(),
                Arc::new(MemoryStore::default()),
            )
            .unwrap();

            // A group created with a hundred members, the most its Welcome
            // ever seats, handing over every member's profile key.
            let invitees = stranger_invitations(MAX_GROUP_MEMBERS - 1);
            let members = std::iter::once(creator_uuid.clone())
                .chain(invitees.iter().map(|invitee| invitee.user_uuid.clone()))
                .collect::<Vec<_>>();

            let creation = creator
                .create_group(
                    Some(Uuid::new_v4().to_string()),
                    invitees,
                    Some(welcome_payload(&members)),
                )
                .unwrap();

            let creation_welcome = wire_length(&creation.welcome);
            assert!(
                creation_welcome <= MAX_WELCOME_LENGTH,
                "creation Welcome: {creation_welcome}"
            );

            let full = creator.load_group(creation.mls_group_id).unwrap();

            // The largest application message, to every other member of it.
            let posted = wire_length(
                &full
                    .encrypt_application_message(profile_keys_message(&members))
                    .unwrap(),
            );
            assert!(
                posted <= MAX_GROUP_APPLICATION_MESSAGE_LENGTH,
                "profile keys message: {posted}"
            );

            // Removing one of a hundred, which encrypts the path to every
            // member staying.
            let removal = wire_length(&full.remove_members(vec![members[1].clone()]).unwrap());
            assert!(
                removal <= MAX_COMMIT_LENGTH,
                "removal of one of a hundred: {removal}"
            );

            // Adding ninety-nine to a group of the creator alone, the largest
            // Commit there is: it carries every key package it adds.
            let alone = creator
                .create_group(
                    Some(Uuid::new_v4().to_string()),
                    stranger_invitations(1),
                    None,
                )
                .unwrap();
            let alone = creator.load_group(alone.mls_group_id).unwrap();
            let only_other = alone
                .members()
                .unwrap()
                .into_iter()
                .map(|member| member.user_uuid)
                .find(|uuid| *uuid != creator_uuid)
                .unwrap();

            alone.remove_members(vec![only_other]).unwrap();
            alone.apply_pending_commit().unwrap();

            let addition = alone
                .add_members(
                    stranger_invitations(MAX_GROUP_MEMBERS - 1),
                    Some(welcome_payload(&members)),
                )
                .unwrap();

            let addition_commit = wire_length(&addition.commit);
            let addition_welcome = wire_length(&addition.welcome);
            assert!(
                addition_commit <= MAX_COMMIT_LENGTH,
                "addition Commit: {addition_commit}"
            );
            assert!(
                addition_welcome <= MAX_WELCOME_LENGTH,
                "addition Welcome: {addition_welcome}"
            );

            // A key package of each kind.
            let bundle = creator.generate_key_packages(1).unwrap();

            for key_package in std::iter::once(&bundle.last_resort_key_package)
                .chain(&bundle.one_time_key_packages)
            {
                let length = wire_length(key_package);
                assert!(length <= MAX_KEY_PACKAGE_LENGTH, "key package: {length}");
            }

            // The largest share of expense keys, sent with the Welcome to the
            // channel while its peer has not been seen in it, in the envelope
            // the app sends a direct message in, its `DirectMessageEnvelope`.
            let channel = creator
                .create_group(None, stranger_invitations(1), None)
                .unwrap();
            let share = creator
                .load_group(channel.mls_group_id.clone())
                .unwrap()
                .encrypt_application_message(vec![b'k'; MAX_KEY_SHARE_PLAINTEXT])
                .unwrap();

            let envelope = json!({
                "mls_group_id": BASE64_STANDARD.encode(&channel.mls_group_id),
                "message": BASE64_STANDARD.encode(&share),
                "welcome": BASE64_STANDARD.encode(&channel.welcome),
            })
            .to_string()
            .len();
            assert!(
                envelope <= MAX_DIRECT_MESSAGE_LENGTH,
                "key share envelope: {envelope}"
            );
        });
    }
}
