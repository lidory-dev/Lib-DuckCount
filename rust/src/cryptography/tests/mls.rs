#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use mls_rs::client_builder::MlsConfig;
    use mls_rs::extension::MlsExtension;
    use mls_rs::extension::recommended::LastResortKeyPackageExt;
    use mls_rs::group::ContentType;
    use mls_rs::identity::SigningIdentity;
    use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
    use mls_rs::time::MlsTime;
    use mls_rs::{
        CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList,
        MlsMessage,
    };
    use mls_rs_crypto_awslc::AwsLcCryptoProvider;
    use uuid::Uuid;

    use crate::cryptography::mls::client::MlsClient;
    use crate::cryptography::mls::config::{KEY_PACKAGE_LIFETIME, mls_rules};
    use crate::cryptography::mls::group::MlsGroup;
    use crate::cryptography::mls::group_id::{
        CHANNEL_NONCE_EXTENSION, channel_group_id, server_group_id,
    };
    use crate::cryptography::mls::identity::fingerprint::safety_number;
    use crate::cryptography::mls::one_time_expense::{
        OneTimeExpenseManifest, SealedValue, verify_one_time_expense,
    };
    use crate::cryptography::mls::storage::{MlsNamespace, MlsStore, MlsStoreError};
    use crate::cryptography::mls::types::{InviteeKeyPackage, ProcessedMessage};
    use crate::cryptography::mls::{CIPHER_SUITE, MAX_GROUP_MEMBERS, MlsError, max_group_members};

    const SECRET: &[u8] = b"&eHml-C_AFyWdylXLd50";

    /// Stored records, keyed by namespace tag and key.
    type Records = HashMap<(u8, Vec<u8>), Vec<u8>>;

    /// An [`MlsStore`] kept in memory, standing in for the host's database.
    ///
    /// Records are held exactly as the library hands them over, so the storage
    /// adapters (sealing included) are exercised for real rather than mocked.
    #[derive(Default)]
    struct TestStore {
        records: Mutex<Records>,
    }

    impl TestStore {
        fn new() -> Arc<Self> {
            Arc::new(Self::default())
        }

        /// Every value currently stored, for inspecting what the host can see.
        fn values(&self) -> Vec<Vec<u8>> {
            self.records.lock().unwrap().values().cloned().collect()
        }

        /// How many records `namespace` holds.
        fn count(&self, namespace: MlsNamespace) -> usize {
            self.keys(namespace).unwrap().len()
        }

        /// Everything stored, for checking that an operation stored nothing.
        fn records(&self) -> Records {
            self.records.lock().unwrap().clone()
        }
    }

    impl MlsStore for TestStore {
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

    /// One user with their own client and storage.
    struct TestUser {
        uuid: String,
        store: Arc<TestStore>,
        client: MlsClient,
    }

    impl TestUser {
        fn new() -> Self {
            let uuid = Uuid::new_v4().to_string();
            let store = TestStore::new();

            let client = MlsClient::new(uuid.clone(), SECRET.to_vec(), store.clone()).unwrap();

            TestUser {
                uuid,
                store,
                client,
            }
        }

        /// Rebuilds the client from the same storage, as a restart would.
        fn reopen(&self) -> MlsClient {
            MlsClient::new(self.uuid.clone(), SECRET.to_vec(), self.store.clone()).unwrap()
        }

        /// Produces a freshly published key package, as the server would hand
        /// one out to a peer.
        fn invitation(&self) -> InviteeKeyPackage {
            let bundle = self.client.generate_key_packages(1).unwrap();

            InviteeKeyPackage {
                user_uuid: self.uuid.clone(),
                key_package: bundle.one_time_key_packages[0].clone(),
            }
        }
    }

    /// Applies a commit that the (imaginary) server accepted.
    fn accept(group: &MlsGroup) {
        group.apply_pending_commit().unwrap();
    }

    /// The UUID of a group the DuckCount API holds, nobody's yet.
    fn new_group_uuid() -> String {
        Uuid::new_v4().to_string()
    }

    /// Creates a group owned by `creator` and joins every invitee to it, as a
    /// group the DuckCount API holds.
    ///
    /// Returns the creator's group followed by each invitee's, in order.
    fn establish_group(creator: &TestUser, invitees: &[&TestUser]) -> Vec<Arc<MlsGroup>> {
        establish_group_as(&new_group_uuid(), creator, invitees)
    }

    /// [`establish_group`], as the group the DuckCount API holds under
    /// `group_uuid`.
    fn establish_group_as(
        group_uuid: &str,
        creator: &TestUser,
        invitees: &[&TestUser],
    ) -> Vec<Arc<MlsGroup>> {
        let creation = creator
            .client
            .create_group(
                Some(group_uuid.to_string()),
                invitees.iter().map(|user| user.invitation()).collect(),
                None,
            )
            .unwrap();

        let mut groups = vec![
            creator
                .client
                .load_group(creation.mls_group_id.clone())
                .unwrap(),
        ];

        let welcome = creation.welcome;

        for user in invitees {
            let others = std::iter::once(creator)
                .chain(invitees.iter().copied())
                .filter(|other| other.uuid != user.uuid)
                .collect::<Vec<_>>();

            let joined = user
                .client
                .join_group(
                    welcome.clone(),
                    Some(group_uuid.to_string()),
                    uuids(&others),
                    true,
                )
                .unwrap();

            groups.push(user.client.load_group(joined).unwrap());
        }

        groups
    }

    /// The UUIDs of `users`, as a joiner names the members they expect.
    fn uuids(users: &[&TestUser]) -> Vec<String> {
        users.iter().map(|user| user.uuid.clone()).collect()
    }

    fn member_uuids(group: &MlsGroup) -> Vec<String> {
        let mut uuids = group
            .members()
            .unwrap()
            .into_iter()
            .map(|member| member.user_uuid)
            .collect::<Vec<_>>();

        uuids.sort();
        uuids
    }

    #[test]
    fn test_create_join_and_exchange_application_messages() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let groups = establish_group(&alice, &[&bob, &carol]);
        let (alice_group, bob_group, carol_group) = (&groups[0], &groups[1], &groups[2]);

        let mut expected = vec![alice.uuid.clone(), bob.uuid.clone(), carol.uuid.clone()];
        expected.sort();

        assert_eq!(member_uuids(alice_group), expected);
        assert_eq!(member_uuids(bob_group), expected);
        assert_eq!(member_uuids(carol_group), expected);

        assert_eq!(alice_group.epoch().unwrap(), bob_group.epoch().unwrap());
        assert_eq!(alice_group.epoch().unwrap(), carol_group.epoch().unwrap());

        // The intended payload: a per-expense encryption key broadcast to the group.
        let expense_key = b"an expense encryption key".to_vec();

        let ciphertext = alice_group
            .encrypt_application_message(expense_key.clone())
            .unwrap();

        for group in [bob_group, carol_group] {
            match group.process_incoming_message(ciphertext.clone()).unwrap() {
                ProcessedMessage::ApplicationMessage {
                    sender_user_uuid,
                    payload,
                    is_sender_pinned,
                } => {
                    assert_eq!(sender_user_uuid, alice.uuid);
                    assert_eq!(payload, expense_key);
                    assert!(is_sender_pinned);
                }
                other => panic!(
                    "expected an application message, got {:?}",
                    other_kind(&other)
                ),
            }
        }
    }

    #[test]
    fn test_add_member_advances_every_view_of_the_group() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let group_uuid = new_group_uuid();
        let groups = establish_group_as(&group_uuid, &alice, &[&bob]);
        let (alice_group, bob_group) = (&groups[0], &groups[1]);

        let epoch_before = alice_group.epoch().unwrap();

        let output = alice_group
            .add_members(vec![carol.invitation()], None)
            .unwrap();

        assert_eq!(
            alice
                .client
                .pinned_signature_key(carol.uuid.clone())
                .unwrap(),
            Some(carol.client.signature_public_key())
        );

        // The commit is pending until the server accepts it.
        assert!(alice_group.has_pending_commit().unwrap());
        assert_eq!(alice_group.epoch().unwrap(), epoch_before);

        assert!(matches!(
            bob_group.process_incoming_message(output.commit).unwrap(),
            ProcessedMessage::Commit {
                removed_self: false,
                ..
            }
        ));

        accept(alice_group);
        assert!(!alice_group.has_pending_commit().unwrap());

        let carol_group_id = carol
            .client
            .join_group(
                output.welcome.clone(),
                Some(group_uuid),
                uuids(&[&alice, &bob]),
                true,
            )
            .unwrap();
        let carol_group = carol.client.load_group(carol_group_id).unwrap();

        let mut expected = vec![alice.uuid.clone(), bob.uuid.clone(), carol.uuid.clone()];
        expected.sort();

        assert_eq!(member_uuids(alice_group), expected);
        assert_eq!(member_uuids(bob_group), expected);
        assert_eq!(member_uuids(&carol_group), expected);

        assert_eq!(alice_group.epoch().unwrap(), epoch_before + 1);
        assert_eq!(bob_group.epoch().unwrap(), epoch_before + 1);
        assert_eq!(carol_group.epoch().unwrap(), epoch_before + 1);
    }

    #[test]
    fn test_removed_member_is_told_and_loses_access() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let groups = establish_group(&alice, &[&bob, &carol]);
        let (alice_group, bob_group, carol_group) = (&groups[0], &groups[1], &groups[2]);

        let commit = alice_group
            .remove_members(vec![carol.uuid.clone()])
            .unwrap();

        // The server addresses the Remove Commit to the target as well, which is
        // how their client learns they are out.
        assert!(matches!(
            carol_group
                .process_incoming_message(commit.clone())
                .unwrap(),
            ProcessedMessage::Commit {
                removed_self: true,
                ..
            }
        ));

        assert!(matches!(
            bob_group.process_incoming_message(commit).unwrap(),
            ProcessedMessage::Commit {
                removed_self: false,
                ..
            }
        ));

        accept(alice_group);

        let mut expected = vec![alice.uuid.clone(), bob.uuid.clone()];
        expected.sort();

        assert_eq!(member_uuids(alice_group), expected);
        assert_eq!(member_uuids(bob_group), expected);

        // Traffic after the removal is unreadable to the removed member.
        let ciphertext = alice_group
            .encrypt_application_message(b"after carol left".to_vec())
            .unwrap();

        assert!(
            bob_group
                .process_incoming_message(ciphertext.clone())
                .is_ok()
        );
        assert!(carol_group.process_incoming_message(ciphertext).is_err());
    }

    #[test]
    fn test_the_one_welcome_lets_every_invitee_join_and_nobody_else() {
        let alice = TestUser::new();
        let invitees = (0..4).map(|_| TestUser::new()).collect::<Vec<_>>();

        // Dave published key packages too, but was not invited.
        let dave = TestUser::new();
        dave.invitation();

        let group_uuid = new_group_uuid();

        let creation = alice
            .client
            .create_group(
                Some(group_uuid.clone()),
                invitees.iter().map(TestUser::invitation).collect(),
                None,
            )
            .unwrap();

        let welcome = creation.welcome;

        // The server hands the same bytes to every invitee, so each has to be
        // able to open them.
        for user in &invitees {
            let others = std::iter::once(&alice)
                .chain(&invitees)
                .filter(|other| other.uuid != user.uuid)
                .collect::<Vec<_>>();

            let joined = user
                .client
                .join_group(
                    welcome.clone(),
                    Some(group_uuid.clone()),
                    uuids(&others),
                    true,
                )
                .unwrap();

            assert_eq!(joined, creation.mls_group_id);
        }

        // And for nobody else: it carries no secret for any key package of
        // Dave's, should it reach him.
        let everybody = std::iter::once(&alice).chain(&invitees).collect::<Vec<_>>();

        let error = dave
            .client
            .join_group(welcome, Some(group_uuid), uuids(&everybody), true)
            .expect_err("a Welcome must not open for somebody it was not written for");

        assert!(matches!(error, MlsError::ProtocolFailed(_)));
        assert_eq!(dave.store.count(MlsNamespace::GroupState), 0);
        assert_eq!(dave.store.count(MlsNamespace::IdentityPin), 0);
    }

    #[test]
    fn test_a_welcome_payload_reaches_every_invitee_from_its_author() {
        // The payload rides a GroupInfo extension of the private-use range,
        // which no member lists among its capabilities: mls-rs carries it all
        // the same.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let group_key = b"thirty-two bytes of a group key!".to_vec();
        let group_uuid = new_group_uuid();

        let creation = alice
            .client
            .create_group(
                Some(group_uuid.clone()),
                vec![bob.invitation(), carol.invitation()],
                Some(group_key.clone()),
            )
            .unwrap();

        let welcome = creation.welcome;

        // Encrypted to the invitees, so the server relaying it never sees it.
        assert!(
            !welcome
                .windows(group_key.len())
                .any(|window| window == group_key)
        );

        for (user, other) in [(&bob, &carol), (&carol, &bob)] {
            let inspection = user
                .client
                .inspect_welcome(welcome.clone(), Some(group_uuid.clone()))
                .unwrap();

            assert_eq!(inspection.welcome_payload, Some(group_key.clone()));
            assert_eq!(inspection.committer_user_uuid, alice.uuid);

            user.client
                .join_group(
                    welcome.clone(),
                    Some(group_uuid.clone()),
                    uuids(&[&alice, other]),
                    true,
                )
                .unwrap();
        }
    }

    #[test]
    fn test_a_welcome_given_no_payload_carries_none() {
        // What a contact request sends: a group shared with one peer, and
        // nothing beside it.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let creation = alice
            .client
            .create_group(None, vec![bob.invitation()], None)
            .unwrap();

        let inspection = bob.client.inspect_welcome(creation.welcome, None).unwrap();

        assert_eq!(inspection.welcome_payload, None);
        assert_eq!(inspection.committer_user_uuid, alice.uuid);
    }

    #[test]
    fn test_a_member_added_later_gets_the_payload_of_the_welcome_adding_them() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let group_uuid = new_group_uuid();

        let creation = alice
            .client
            .create_group(
                Some(group_uuid.clone()),
                vec![bob.invitation()],
                Some(b"for bob".to_vec()),
            )
            .unwrap();

        let bob_group_id = bob
            .client
            .join_group(
                creation.welcome,
                Some(group_uuid.clone()),
                uuids(&[&alice]),
                true,
            )
            .unwrap();

        let alice_group = alice.client.load_group(creation.mls_group_id).unwrap();
        let bob_group = bob.client.load_group(bob_group_id).unwrap();

        // Bob, not the creator, commits Carol in, handing her something else.
        let output = bob_group
            .add_members(vec![carol.invitation()], Some(b"for carol".to_vec()))
            .unwrap();

        alice_group.process_incoming_message(output.commit).unwrap();
        accept(&bob_group);

        let inspection = carol
            .client
            .inspect_welcome(output.welcome.clone(), Some(group_uuid.clone()))
            .unwrap();

        assert_eq!(inspection.committer_user_uuid, bob.uuid);
        assert_eq!(inspection.welcome_payload, Some(b"for carol".to_vec()));

        carol
            .client
            .join_group(
                output.welcome,
                Some(group_uuid),
                uuids(&[&alice, &bob]),
                true,
            )
            .unwrap();
    }

    /// Joins `inviter`'s new group with `joiner` as a contact request is
    /// opened: expecting the inviter, and pinning nobody.
    fn open_request(inviter: &TestUser, joiner: &TestUser) -> (Arc<MlsGroup>, Arc<MlsGroup>) {
        let creation = inviter
            .client
            .create_group(None, vec![joiner.invitation()], None)
            .unwrap();

        let group_id = joiner
            .client
            .join_group(creation.welcome, None, uuids(&[inviter]), false)
            .unwrap();

        (
            inviter.client.load_group(creation.mls_group_id).unwrap(),
            joiner.client.load_group(group_id).unwrap(),
        )
    }

    #[test]
    fn test_a_joined_group_pins_its_members_only_when_asked() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let (_, bob_group) = open_request(&alice, &bob);

        assert!(
            bob.client
                .pinned_signature_key(alice.uuid.clone())
                .unwrap()
                .is_none(),
            "a request opened and then refused must leave no pin behind"
        );

        bob_group.pin_members(uuids(&[&alice])).unwrap();

        assert_eq!(
            bob.client.pinned_signature_key(alice.uuid.clone()).unwrap(),
            Some(alice.client.signature_public_key())
        );
    }

    #[test]
    fn test_pinning_members_refuses_a_key_pinned_differently_since_the_join() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let impostor = TestUser::new();

        let (_, bob_group) = open_request(&alice, &bob);

        bob.client
            .pin_identity(alice.uuid.clone(), impostor.client.signature_public_key())
            .unwrap();

        assert!(matches!(
            bob_group.pin_members(uuids(&[&alice])).unwrap_err(),
            MlsError::IdentityKeyMismatch(uuid) if uuid == alice.uuid
        ));
    }

    #[test]
    fn test_verifying_members_pins_nobody() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let (_, bob_group) = open_request(&alice, &bob);

        bob_group.verify_members(uuids(&[&alice])).unwrap();

        assert!(
            bob.client
                .pinned_signature_key(alice.uuid.clone())
                .unwrap()
                .is_none(),
            "an acceptance that is never taken must leave no pin behind"
        );

        // Once pinned, the same key still passes.
        bob_group.pin_members(uuids(&[&alice])).unwrap();
        bob_group.verify_members(uuids(&[&alice])).unwrap();
    }

    #[test]
    fn test_verifying_members_refuses_a_key_pinned_differently_since_the_join() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let impostor = TestUser::new();

        let (_, bob_group) = open_request(&alice, &bob);

        bob.client
            .pin_identity(alice.uuid.clone(), impostor.client.signature_public_key())
            .unwrap();

        assert!(matches!(
            bob_group.verify_members(uuids(&[&alice])).unwrap_err(),
            MlsError::IdentityKeyMismatch(uuid) if uuid == alice.uuid
        ));

        // The pin that was there stays as it was.
        assert_eq!(
            bob.client.pinned_signature_key(alice.uuid.clone()).unwrap(),
            Some(impostor.client.signature_public_key())
        );
    }

    /// Whether `receiver` reads a message from `sender` as signed with the key
    /// pinned for them.
    fn reads_as_pinned(sender: &MlsGroup, receiver: &MlsGroup) -> bool {
        let message = sender
            .encrypt_application_message(b"hello".to_vec())
            .unwrap();

        receiver
            .read_application_message(message)
            .unwrap()
            .is_sender_pinned
    }

    #[test]
    fn test_a_request_is_read_as_unpinned_until_its_sender_is_pinned() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let (alice_group, bob_group) = open_request(&alice, &bob);

        assert!(!reads_as_pinned(&alice_group, &bob_group));

        bob_group.pin_members(uuids(&[&alice])).unwrap();

        assert!(reads_as_pinned(&alice_group, &bob_group));

        // The answer, read by the requester, who pinned Bob when inviting him.
        assert!(reads_as_pinned(&bob_group, &alice_group));
    }

    #[test]
    fn test_a_member_committed_in_before_their_pin_is_read_as_unpinned() {
        // Mallory commits in a leaf claiming to be Quentin before Victor has
        // met him. Once Victor pins the real Quentin, that leaf is still not
        // him.
        let mallory = TestUser::new();
        let victor = TestUser::new();
        let quentin = TestUser::new();

        let group_uuid = new_group_uuid();
        let groups = establish_group_as(&group_uuid, &mallory, &[&victor]);
        let (mallory_group, victor_group) = (&groups[0], &groups[1]);

        let store = TestStore::new();
        let posing_as_quentin = TestUser {
            uuid: quentin.uuid.clone(),
            client: MlsClient::new(quentin.uuid.clone(), SECRET.to_vec(), store.clone()).unwrap(),
            store,
        };

        let output = mallory_group
            .add_members(vec![posing_as_quentin.invitation()], None)
            .unwrap();

        victor_group
            .process_incoming_message(output.commit)
            .unwrap();
        accept(mallory_group);

        let fake_group_id = posing_as_quentin
            .client
            .join_group(
                output.welcome.clone(),
                Some(group_uuid),
                uuids(&[&mallory, &victor]),
                false,
            )
            .unwrap();
        let fake_group = posing_as_quentin.client.load_group(fake_group_id).unwrap();

        victor
            .client
            .pin_identity(quentin.uuid.clone(), quentin.client.signature_public_key())
            .unwrap();

        assert!(!reads_as_pinned(&fake_group, victor_group));
        assert!(reads_as_pinned(mallory_group, victor_group));
    }

    #[test]
    fn test_members_committed_in_after_the_join_are_never_pinned() {
        // Mallory's request is opened, then she commits in a leaf claiming to
        // be Quentin, with a key she made up, before Victor accepts.
        let mallory = TestUser::new();
        let victor = TestUser::new();
        let quentin = TestUser::new();

        let (mallory_group, victor_group) = open_request(&mallory, &victor);

        let store = TestStore::new();
        let posing_as_quentin = TestUser {
            uuid: quentin.uuid.clone(),
            client: MlsClient::new(quentin.uuid.clone(), SECRET.to_vec(), store.clone()).unwrap(),
            store,
        };

        let output = mallory_group
            .add_members(vec![posing_as_quentin.invitation()], None)
            .unwrap();

        victor_group
            .process_incoming_message(output.commit)
            .unwrap();

        assert!(matches!(
            victor_group.pin_members(uuids(&[&mallory])).unwrap_err(),
            MlsError::UnexpectedMembers
        ));

        assert!(matches!(
            victor_group.verify_members(uuids(&[&mallory])).unwrap_err(),
            MlsError::UnexpectedMembers
        ));

        for member in [&mallory, &quentin] {
            assert!(
                victor
                    .client
                    .pinned_signature_key(member.uuid.clone())
                    .unwrap()
                    .is_none(),
                "nobody is pinned from a roster the host did not expect"
            );
        }
    }

    #[test]
    fn test_an_application_message_is_read_with_its_sender() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let (alice_group, bob_group) = open_request(&alice, &bob);

        let message = alice_group
            .encrypt_application_message(b"a card".to_vec())
            .unwrap();

        let read = bob_group.read_application_message(message).unwrap();

        assert_eq!(read.sender_user_uuid, alice.uuid);
        assert_eq!(read.payload, b"a card".to_vec());

        // Bob opened the request without pinning anybody.
        assert!(!read.is_sender_pinned);
    }

    #[test]
    fn test_reading_an_application_message_refuses_a_commit_without_applying_it() {
        // Mallory's request is opened, then she commits Carol in, sending the
        // Commit where Victor only expects messages from her.
        let mallory = TestUser::new();
        let victor = TestUser::new();
        let carol = TestUser::new();

        let (mallory_group, victor_group) = open_request(&mallory, &victor);
        let epoch = victor_group.epoch().unwrap();

        let commit = mallory_group
            .add_members(vec![carol.invitation()], None)
            .unwrap()
            .commit;

        let error = victor_group
            .read_application_message(commit.clone())
            .expect_err("a Commit must be refused");

        assert!(matches!(error, MlsError::InvalidMessage));

        // Nothing was applied or stored: the group Victor loads again holds
        // the two of them, in the epoch he joined, which the Commit still fits.
        let reloaded = victor
            .client
            .load_group(victor_group.mls_group_id().unwrap())
            .unwrap();

        let mut expected = uuids(&[&mallory, &victor]);
        expected.sort();

        assert_eq!(reloaded.epoch().unwrap(), epoch);
        assert_eq!(member_uuids(&reloaded), expected);

        assert!(matches!(
            reloaded.process_incoming_message(commit).unwrap(),
            ProcessedMessage::Commit { .. }
        ));
    }

    #[test]
    fn test_reading_an_application_message_refuses_a_proposal_without_keeping_it() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let (alice_group, bob_group) = open_request(&alice, &bob);

        let proposal = alice_group.propose_self_remove().unwrap();

        let error = bob_group
            .read_application_message(proposal.clone())
            .expect_err("a Proposal must be refused");

        assert!(matches!(error, MlsError::InvalidMessage));

        // Nothing is pending, so Bob still sends.
        bob_group
            .encrypt_application_message(b"still here".to_vec())
            .unwrap();

        // Kept, the same Proposal would stop him until somebody committed it.
        bob_group.process_incoming_message(proposal).unwrap();

        assert!(
            bob_group
                .encrypt_application_message(b"stuck".to_vec())
                .is_err()
        );
    }

    #[test]
    fn test_a_message_that_would_grow_the_group_past_its_limit_is_refused() {
        // Mallory skips as many generations as she likes, message after
        // message, and Victor keeps a key for every one of them.
        let mallory = TestUser::new();
        let victor = TestUser::new();

        let (mallory_group, victor_group) = open_request(&mallory, &victor);
        let group_id = victor_group.mls_group_id().unwrap();

        let stored = || {
            victor
                .store
                .get(MlsNamespace::GroupState, group_id.clone())
                .unwrap()
                .unwrap()
        };

        let mut overtaken = Vec::new();
        let mut refusal = None;

        for _ in 0..10 {
            let batch = (0..1000)
                .map(|_| {
                    mallory_group
                        .encrypt_application_message(b"skipped".to_vec())
                        .unwrap()
                })
                .collect::<Vec<_>>();

            // The first of each batch is overtaken by its last, and read later.
            overtaken.push(batch[0].clone());

            let before = stored();

            if let Err(error) = victor_group.read_application_message(batch[999].clone()) {
                refusal = Some((error, before));
                break;
            }
        }

        let (error, before) = refusal.expect("the group must stop growing");

        assert!(matches!(error, MlsError::GroupStateTooLarge));
        assert!(overtaken.len() > 1, "a batch has to be taken in first");

        // Nothing was stored.
        assert_eq!(stored(), before);

        // Nor kept in memory: a message overtaken before is still read, which a
        // group grown past its limit could not store.
        let read = victor_group
            .read_application_message(overtaken[0].clone())
            .unwrap();

        assert_eq!(read.payload, b"skipped".to_vec());

        // And Victor still sends.
        let message = victor_group
            .encrypt_application_message(b"still here".to_vec())
            .unwrap();

        mallory_group.read_application_message(message).unwrap();
    }

    /// `message`, a PrivateMessage sent to the group `group_id`, with the
    /// content type its header names changed from `from` to `to`.
    fn relabelled(
        mut message: Vec<u8>,
        group_id: &[u8],
        from: ContentType,
        to: ContentType,
    ) -> Vec<u8> {
        // The version and the wire format, two bytes each, then the group id
        // behind its variable-length size, then the eight-byte epoch.
        let size_length = if group_id.len() < 64 { 1 } else { 2 };
        let offset = 2 + 2 + size_length + group_id.len() + 8;

        assert_eq!(
            message[offset], from as u8,
            "the header is not laid out as expected"
        );

        message[offset] = to as u8;
        message
    }

    #[test]
    fn test_a_commit_labelled_as_an_application_message_is_not_read() {
        // The content type travels in the clear, so whoever relays a Commit,
        // the server included, can relabel it to get it past the check. The
        // label is authenticated with the message, which then fails to open.
        let mallory = TestUser::new();
        let victor = TestUser::new();
        let carol = TestUser::new();

        let (mallory_group, victor_group) = open_request(&mallory, &victor);
        let epoch = victor_group.epoch().unwrap();

        let commit = mallory_group
            .add_members(vec![carol.invitation()], None)
            .unwrap()
            .commit;

        let relabelled = relabelled(
            commit,
            &victor_group.mls_group_id().unwrap(),
            ContentType::Commit,
            ContentType::Application,
        );

        let error = victor_group
            .read_application_message(relabelled)
            .expect_err("a relabelled Commit must not be read");

        assert!(matches!(error, MlsError::ProtocolFailed(_)));

        let reloaded = victor
            .client
            .load_group(victor_group.mls_group_id().unwrap())
            .unwrap();

        let mut expected = uuids(&[&mallory, &victor]);
        expected.sort();

        assert_eq!(reloaded.epoch().unwrap(), epoch);
        assert_eq!(member_uuids(&reloaded), expected);
    }

    #[test]
    fn test_a_welcome_with_unexpected_members_is_refused_and_leaves_nothing() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let group_uuid = new_group_uuid();

        let creation = alice
            .client
            .create_group(
                Some(group_uuid.clone()),
                vec![bob.invitation(), carol.invitation()],
                None,
            )
            .unwrap();

        let welcome = creation.welcome.clone();

        // Bob was told this is a group with Alice alone.
        let error = bob
            .client
            .join_group(
                welcome.clone(),
                Some(group_uuid.clone()),
                uuids(&[&alice]),
                true,
            )
            .expect_err("a group holding somebody unexpected must be refused");

        assert!(matches!(error, MlsError::UnexpectedMembers));

        assert!(matches!(
            bob.client
                .load_group(creation.mls_group_id.clone())
                .unwrap_err(),
            MlsError::GroupNotFound
        ));

        for member in [&alice, &carol] {
            assert!(
                bob.client
                    .pinned_signature_key(member.uuid.clone())
                    .unwrap()
                    .is_none(),
                "a refused Welcome pins nobody"
            );
        }

        // Nothing was spent either: the same Welcome still opens once the
        // expectation is right.
        assert!(
            bob.client
                .join_group(welcome, Some(group_uuid), uuids(&[&alice, &carol]), true)
                .is_ok()
        );
    }

    #[test]
    fn test_a_member_claiming_somebody_else_is_refused_and_not_pinned() {
        // Mallory writes a Welcome in which her own leaf claims to be Xavier,
        // and sends it to Victor. The server authenticated the sender as
        // Mallory, so that is who Victor expects.
        let mallory = TestUser::new();
        let xavier = TestUser::new();
        let victor = TestUser::new();

        let posing_as_xavier =
            MlsClient::new(xavier.uuid.clone(), SECRET.to_vec(), TestStore::new()).unwrap();

        let creation = posing_as_xavier
            .create_group(None, vec![victor.invitation()], None)
            .unwrap();

        let error = victor
            .client
            .join_group(creation.welcome.clone(), None, uuids(&[&mallory]), true)
            .expect_err("a leaf claiming somebody other than the sender must be refused");

        assert!(matches!(error, MlsError::UnexpectedMembers));

        assert!(
            victor
                .client
                .pinned_signature_key(xavier.uuid.clone())
                .unwrap()
                .is_none(),
            "the key Mallory made up for Xavier is not remembered as his"
        );

        // So the real Xavier is still recognised when he shows up.
        establish_group(&xavier, &[&victor]);

        assert_eq!(
            victor
                .client
                .pinned_signature_key(xavier.uuid.clone())
                .unwrap(),
            Some(xavier.client.signature_public_key())
        );
    }

    #[test]
    fn test_a_welcome_from_an_impostor_of_a_pinned_member_is_refused() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        // Alice meets Bob, pinning his signature key.
        establish_group(&alice, &[&bob]);

        let posing_as_bob =
            MlsClient::new(bob.uuid.clone(), SECRET.to_vec(), TestStore::new()).unwrap();

        let creation = posing_as_bob
            .create_group(None, vec![alice.invitation()], None)
            .unwrap();

        let error = alice
            .client
            .join_group(creation.welcome.clone(), None, uuids(&[&bob]), false)
            .expect_err("a Welcome signed with a key other than Bob's pinned one must be refused");

        assert!(matches!(error, MlsError::IdentityKeyMismatch(uuid) if uuid == bob.uuid));
    }

    #[test]
    fn test_a_message_sent_in_the_clear_is_refused() {
        // A proposal to add somebody, sent from outside the group: the one message mls-rs
        // takes from a non-member, signed by nothing but the key package it carries, and
        // needing only the group id and epoch, which travel in the clear. Taken in, it
        // would sit pending and leave the group unable to send anything until committed.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);

        let crypto_provider = crate::cryptography::mls::config::crypto_provider();
        let cipher_suite_provider = crypto_provider.cipher_suite_provider(CIPHER_SUITE).unwrap();
        let (secret, public) = cipher_suite_provider.signature_key_generate().unwrap();

        let outsider = Client::builder()
            .identity_provider(BasicIdentityProvider)
            .crypto_provider(crypto_provider)
            .signing_identity(
                SigningIdentity::new(
                    BasicCredential::new(Uuid::new_v4().to_string().into_bytes()).into_credential(),
                    public,
                ),
                secret,
                CIPHER_SUITE,
            )
            .build();

        let proposal = outsider
            .external_add_proposal(
                &groups[0].group_info(),
                None,
                Vec::new(),
                ExtensionList::default(),
                ExtensionList::default(),
                None,
            )
            .unwrap();

        let error = groups[1]
            .process_incoming_message(proposal.to_bytes().unwrap())
            .expect_err("a message sent in the clear must be refused");

        assert!(matches!(error, MlsError::InvalidMessage));

        let error = groups[1]
            .read_application_message(proposal.to_bytes().unwrap())
            .expect_err("a message sent in the clear must be refused");

        assert!(matches!(error, MlsError::InvalidMessage));

        // Nothing was taken in, so the group still sends.
        let message = groups[1]
            .encrypt_application_message(b"still here".to_vec())
            .unwrap();

        groups[0].process_incoming_message(message).unwrap();
    }

    /// A Welcome for `joiner` into the group `group_id`, its GroupInfo carrying
    /// `extensions`, made by a plain mls-rs client rather than an
    /// [`MlsClient`], which would have derived the id, and the UUID of the one
    /// who made it.
    fn foreign_welcome(
        joiner: &TestUser,
        group_id: Vec<u8>,
        extensions: ExtensionList,
    ) -> (Vec<u8>, String) {
        let creator_uuid = Uuid::new_v4().to_string();

        let mut group = plain_client(creator_uuid.clone())
            .create_group_with_id(
                group_id,
                ExtensionList::default(),
                ExtensionList::default(),
                None,
            )
            .unwrap();

        let key_package = MlsMessage::from_bytes(&joiner.invitation().key_package).unwrap();

        let commit = group
            .commit_builder()
            .set_group_info_ext(extensions)
            .add_member(key_package)
            .unwrap()
            .build()
            .unwrap();

        (commit.welcome_messages[0].to_bytes().unwrap(), creator_uuid)
    }

    /// The GroupInfo extensions of a Welcome to the channel whose creator drew
    /// `nonce`.
    fn carrying_nonce(nonce: &[u8]) -> ExtensionList {
        [Extension::new(CHANNEL_NONCE_EXTENSION, nonce.to_vec())]
            .into_iter()
            .collect()
    }

    #[test]
    fn test_a_welcome_to_a_group_id_not_derived_is_refused_before_anything_is_stored() {
        // MLS leaves the id to whoever creates the group. One this library did
        // not derive could be anybody's: another group's, which every member of
        // that one reads, or one as long as its author likes, and it would be
        // the key of a stored record, and of the record of its deletion.
        let nonce = rand::random::<[u8; 32]>();

        // The same client's Welcome joins once its id is derived, as a channel's.
        let bob = TestUser::new();
        let (welcome, creator) =
            foreign_welcome(&bob, channel_group_id(&nonce), carrying_nonce(&nonce));
        bob.client
            .join_group(welcome, None, vec![creator], true)
            .unwrap();

        let refused = [
            // Drawn at random, as MLS leaves it.
            (
                rand::random::<[u8; 32]>().to_vec(),
                ExtensionList::default(),
            ),
            // Of another length.
            (vec![7u8; 16], ExtensionList::default()),
            (vec![7u8; 4096], ExtensionList::default()),
            // Carrying a nonce it was not derived from.
            (
                channel_group_id(&nonce),
                carrying_nonce(&rand::random::<[u8; 32]>()),
            ),
            // The id of a group the API holds, which a channel never has, even
            // one whose nonce is that group's UUID: only the domain each is
            // derived under keeps the two apart.
            {
                let group_uuid = new_group_uuid();

                (
                    server_group_id(&group_uuid),
                    carrying_nonce(group_uuid.as_bytes()),
                )
            },
        ];

        for (group_id, extensions) in refused {
            let bob = TestUser::new();
            let (welcome, creator) = foreign_welcome(&bob, group_id, extensions);
            let before = bob.store.records();

            let error = bob
                .client
                .join_group(welcome, None, vec![creator], true)
                .expect_err("a group id not derived must be refused");

            // Nothing stored, nobody pinned, and no key package spent.
            assert!(matches!(error, MlsError::UnexpectedGroupId));
            assert_eq!(bob.store.records(), before);
        }
    }

    #[test]
    fn test_a_welcome_is_joined_only_as_the_group_its_id_was_derived_for() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let other_group_uuid = new_group_uuid();
        let group_uuid = new_group_uuid();

        let creation = alice
            .client
            .create_group(
                Some(group_uuid.clone()),
                vec![bob.invitation(), carol.invitation()],
                None,
            )
            .unwrap();

        assert_eq!(creation.mls_group_id, server_group_id(&group_uuid));

        let welcome = creation.welcome;
        let before = bob.store.records();

        // Listed under another group, or opened as a channel.
        for expected_group_uuid in [Some(other_group_uuid.clone()), None] {
            assert!(matches!(
                bob.client
                    .inspect_welcome(welcome.clone(), expected_group_uuid.clone())
                    .unwrap_err(),
                MlsError::UnexpectedGroupId
            ));

            assert!(matches!(
                bob.client
                    .join_group(
                        welcome.clone(),
                        expected_group_uuid,
                        uuids(&[&alice, &carol]),
                        true,
                    )
                    .unwrap_err(),
                MlsError::UnexpectedGroupId
            ));
        }

        assert_eq!(bob.store.records(), before);

        bob.client
            .join_group(welcome, Some(group_uuid), uuids(&[&alice, &carol]), true)
            .unwrap();

        // Nor is a channel's Welcome joined as a group's.
        let channel = alice
            .client
            .create_group(None, vec![carol.invitation()], None)
            .unwrap()
            .welcome;

        assert!(matches!(
            carol
                .client
                .join_group(
                    channel.clone(),
                    Some(other_group_uuid),
                    uuids(&[&alice]),
                    true,
                )
                .unwrap_err(),
            MlsError::UnexpectedGroupId
        ));

        carol
            .client
            .join_group(channel, None, uuids(&[&alice]), true)
            .unwrap();
    }

    #[test]
    fn test_a_contact_request_given_a_group_s_id_is_refused_and_the_group_still_joined() {
        // Carol, invited to Alice's group with Bob, reads its id, and sends Bob
        // a request of her own under it before he joins. Joined, it would leave
        // Alice's group refused on his device as already joined, for good.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let group_uuid = new_group_uuid();

        let creation = alice
            .client
            .create_group(
                Some(group_uuid.clone()),
                vec![bob.invitation(), carol.invitation()],
                None,
            )
            .unwrap();

        // The one way this library lets her aim at that id.
        let request = carol
            .client
            .create_group(Some(group_uuid.clone()), vec![bob.invitation()], None)
            .unwrap();

        assert_eq!(request.mls_group_id, creation.mls_group_id);

        let before = bob.store.records();

        // Opened as a request is, expecting its sender alone.
        let error = bob
            .client
            .join_group(request.welcome, None, uuids(&[&carol]), false)
            .expect_err("a request under a group's id must be refused");

        assert!(matches!(error, MlsError::UnexpectedGroupId));
        assert_eq!(bob.store.records(), before);

        let joined = bob
            .client
            .join_group(
                creation.welcome,
                Some(group_uuid),
                uuids(&[&alice, &carol]),
                false,
            )
            .unwrap();

        assert_eq!(joined, creation.mls_group_id);
    }

    /// A plain mls-rs client for `user_uuid`, running the rules of this library
    /// and keeping everything in memory.
    ///
    /// Opening an [`MlsClient`] derives its sealing key from the secret, slowly
    /// by design, which a test that needs a hundred members cannot afford a
    /// hundred times.
    fn plain_client(user_uuid: String) -> Client<impl MlsConfig> {
        let crypto_provider = crate::cryptography::mls::config::crypto_provider();
        let cipher_suite_provider = crypto_provider.cipher_suite_provider(CIPHER_SUITE).unwrap();
        let (secret, public) = cipher_suite_provider.signature_key_generate().unwrap();

        Client::builder()
            .identity_provider(BasicIdentityProvider)
            .crypto_provider(crypto_provider)
            .mls_rules(mls_rules())
            .signing_identity(
                SigningIdentity::new(
                    BasicCredential::new(user_uuid.into_bytes()).into_credential(),
                    public,
                ),
                secret,
                CIPHER_SUITE,
            )
            .build()
    }

    /// The key packages of `count` users nobody has met, as the server would
    /// hand them out.
    fn stranger_invitations(count: usize) -> Vec<InviteeKeyPackage> {
        (0..count)
            .map(|_| {
                let user_uuid = Uuid::new_v4().to_string();

                let key_package = plain_client(user_uuid.clone())
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

    /// A Welcome for `joiner` into a group of `member_count` members, which an
    /// [`MlsClient`] refuses to write past the cap, the UUID the API holds the
    /// group under, and the UUIDs of everybody in it but `joiner`.
    fn welcome_to_a_group_of(
        member_count: usize,
        joiner: &TestUser,
    ) -> (Vec<u8>, String, Vec<String>) {
        let creator_uuid = Uuid::new_v4().to_string();
        let group_uuid = new_group_uuid();

        let mut group = plain_client(creator_uuid.clone())
            .create_group_with_id(
                server_group_id(&group_uuid),
                ExtensionList::default(),
                ExtensionList::default(),
                None,
            )
            .unwrap();

        // The creator, the joiner, and strangers for the rest.
        let strangers = stranger_invitations(member_count - 2);

        let mut commit_builder = group.commit_builder();

        for invitation in strangers.iter().chain([&joiner.invitation()]) {
            commit_builder = commit_builder
                .add_member(MlsMessage::from_bytes(&invitation.key_package).unwrap())
                .unwrap();
        }

        let welcome = commit_builder.build().unwrap().welcome_messages.remove(0);

        let others = std::iter::once(creator_uuid)
            .chain(strangers.into_iter().map(|stranger| stranger.user_uuid))
            .collect();

        (welcome.to_bytes().unwrap(), group_uuid, others)
    }

    #[test]
    fn test_max_group_members_is_the_cap_the_api_enforces() {
        // The API holds its own copy of the cap: the two must move together.
        assert_eq!(max_group_members(), 100);
    }

    #[test]
    fn test_creating_a_group_past_the_member_cap_is_refused_before_anything_is_done() {
        let alice = TestUser::new();
        let before = alice.store.records();

        // A hundred invitees, and Alice makes a hundred and one.
        let error = alice
            .client
            .create_group(
                Some(new_group_uuid()),
                stranger_invitations(MAX_GROUP_MEMBERS),
                Some(b"a group key".to_vec()),
            )
            .expect_err("a group past the cap must be refused");

        assert!(matches!(error, MlsError::TooManyMembers));

        // Nothing was stored, and nobody pinned.
        assert_eq!(alice.store.records(), before);

        // Counted before any key package is even read.
        let unreadable = (0..MAX_GROUP_MEMBERS)
            .map(|_| InviteeKeyPackage {
                user_uuid: Uuid::new_v4().to_string(),
                key_package: b"not a key package".to_vec(),
            })
            .collect();

        assert!(matches!(
            alice
                .client
                .create_group(Some(new_group_uuid()), unreadable, None)
                .unwrap_err(),
            MlsError::TooManyMembers
        ));

        // One fewer makes exactly the cap, which is built, and stopped only
        // when stored: a test lets a group store 64 KB, a fifth of what a
        // hundred members take.
        assert!(matches!(
            alice
                .client
                .create_group(
                    Some(new_group_uuid()),
                    stranger_invitations(MAX_GROUP_MEMBERS - 1),
                    None,
                )
                .unwrap_err(),
            MlsError::GroupStateTooLarge
        ));
    }

    #[test]
    fn test_creating_a_group_of_nobody_is_refused_before_anything_is_done() {
        let alice = TestUser::new();
        let before = alice.store.records();

        let error = alice
            .client
            .create_group(
                Some(new_group_uuid()),
                Vec::new(),
                Some(b"a group key".to_vec()),
            )
            .expect_err("a group of its creator alone must be refused");

        assert!(matches!(error, MlsError::ProtocolFailed(_)));
        assert_eq!(alice.store.records(), before);
    }

    #[test]
    fn test_adding_members_past_the_cap_is_refused_before_anything_is_built() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);
        let before = alice.store.records();

        // Alice and Bob, and ninety-nine more, make a hundred and one.
        let error = groups[0]
            .add_members(stranger_invitations(MAX_GROUP_MEMBERS - 1), None)
            .expect_err("a group grown past the cap must be refused");

        assert!(matches!(error, MlsError::TooManyMembers));

        // Nothing was stored, and nobody pinned.
        assert_eq!(alice.store.records(), before);
        assert!(!groups[0].has_pending_commit().unwrap());

        // Nor built: a Commit left pending in memory would refuse the next one
        // outright. Up to exactly the cap, it is built, and stopped only when
        // stored, as a test lets a group store 64 KB.
        assert!(matches!(
            groups[0]
                .add_members(stranger_invitations(MAX_GROUP_MEMBERS - 2), None)
                .unwrap_err(),
            MlsError::GroupStateTooLarge
        ));
    }

    #[test]
    fn test_adding_nobody_is_refused_before_anything_is_built() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);
        let before = alice.store.records();

        let error = groups[0]
            .add_members(Vec::new(), None)
            .expect_err("adding nobody must be refused");

        assert!(matches!(error, MlsError::ProtocolFailed(_)));

        // Nothing was stored, nor built: the group still commits.
        assert_eq!(alice.store.records(), before);
        assert!(!groups[0].has_pending_commit().unwrap());

        groups[0].update().unwrap();
    }

    #[test]
    fn test_adding_members_while_a_member_proposes_adding_somebody_is_refused() {
        // Mallory, a member, proposes adding a stranger. Alice's next Commit
        // would carry that proposal along with her invitees, adding somebody
        // she never counted, and her Welcome would open for them as well.
        let alice = TestUser::new();
        let carol = TestUser::new();

        let mallory_uuid = Uuid::new_v4().to_string();
        let mallory_client = plain_client(mallory_uuid.clone());

        let mallory_key_package = mallory_client
            .generate_key_package_message(ExtensionList::default(), ExtensionList::default(), None)
            .unwrap();

        let creation = alice
            .client
            .create_group(
                Some(new_group_uuid()),
                vec![InviteeKeyPackage {
                    user_uuid: mallory_uuid,
                    key_package: mallory_key_package.to_bytes().unwrap(),
                }],
                None,
            )
            .unwrap();

        let alice_group = alice.client.load_group(creation.mls_group_id).unwrap();

        let welcome = MlsMessage::from_bytes(&creation.welcome).unwrap();
        let (mut mallory_group, _) = mallory_client.join_group(None, &welcome, None).unwrap();

        let stranger = stranger_invitations(1).remove(0);

        let proposal = mallory_group
            .propose_add(
                MlsMessage::from_bytes(&stranger.key_package).unwrap(),
                Vec::new(),
            )
            .unwrap();

        assert!(matches!(
            alice_group
                .process_incoming_message(proposal.to_bytes().unwrap())
                .unwrap(),
            ProcessedMessage::Proposal { .. }
        ));

        let before = alice.store.records();

        let error = alice_group
            .add_members(vec![carol.invitation()], None)
            .expect_err("a Commit adding somebody besides the invitees must be refused");

        assert!(matches!(error, MlsError::UnexpectedMembers));

        // Nothing was stored, nobody pinned, and nothing built.
        assert_eq!(alice.store.records(), before);
        assert!(!alice_group.has_pending_commit().unwrap());
    }

    #[test]
    fn test_a_welcome_to_a_group_past_the_member_cap_is_refused_before_anything_is_stored() {
        let bob = TestUser::new();

        let (welcome, group_uuid, others) = welcome_to_a_group_of(MAX_GROUP_MEMBERS + 1, &bob);
        let before = bob.store.records();

        // Expecting every one of them, and trusting them all.
        let error = bob
            .client
            .join_group(welcome, Some(group_uuid), others, true)
            .expect_err("a group past the cap must be refused");

        assert!(matches!(error, MlsError::TooManyMembers));

        // Nothing was stored, nobody pinned, and no key package spent.
        assert_eq!(bob.store.records(), before);

        // A group of exactly the cap is let in, and stopped only when stored,
        // as a test lets a group store 64 KB.
        let (welcome, group_uuid, others) = welcome_to_a_group_of(MAX_GROUP_MEMBERS, &bob);

        assert!(matches!(
            bob.client
                .join_group(welcome, Some(group_uuid), others, true)
                .unwrap_err(),
            MlsError::GroupStateTooLarge
        ));
    }

    #[test]
    fn test_a_welcome_is_never_joined_twice() {
        // A last-resort key package survives the joins it serves, so a Welcome
        // sealed to one can be delivered again, by a retry or by a server
        // replaying it. Joining it twice would rewind the group.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let last_resort = InviteeKeyPackage {
            user_uuid: bob.uuid.clone(),
            key_package: bob
                .client
                .generate_key_packages(0)
                .unwrap()
                .last_resort_key_package,
        };

        let creation = alice
            .client
            .create_group(None, vec![last_resort], None)
            .unwrap();
        let welcome = creation.welcome.clone();

        let group_id = bob
            .client
            .join_group(welcome.clone(), None, uuids(&[&alice]), true)
            .unwrap();

        let alice_group = alice.client.load_group(group_id.clone()).unwrap();

        let first = alice_group
            .encrypt_application_message(b"first".to_vec())
            .unwrap();

        bob.client
            .load_group(group_id.clone())
            .unwrap()
            .process_incoming_message(first.clone())
            .unwrap();

        let error = bob
            .client
            .join_group(welcome.clone(), None, uuids(&[&alice]), true)
            .expect_err("a Welcome for a group already held must be refused");

        assert!(matches!(error, MlsError::GroupAlreadyJoined));

        // Bob's group was left where it was: the message it already read stays
        // spent, and the next one opens.
        let bob_group = bob.client.load_group(group_id.clone()).unwrap();

        assert!(bob_group.process_incoming_message(first.clone()).is_err());

        let second = alice_group
            .encrypt_application_message(b"second".to_vec())
            .unwrap();

        assert!(bob_group.process_incoming_message(second).is_ok());

        // Deleting the group does not make its Welcome a way back in, which
        // would let the first message be read a second time.
        drop(bob_group);
        bob.client.delete_group(group_id).unwrap();

        let error = bob
            .client
            .join_group(welcome, None, uuids(&[&alice]), true)
            .expect_err("a Welcome for a deleted group must be refused");

        assert!(matches!(error, MlsError::GroupAlreadyJoined));
    }

    #[test]
    fn test_inspecting_a_welcome_names_its_committer_the_other_members_and_its_payload() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let group_key = b"thirty-two bytes of a group key!".to_vec();
        let group_uuid = new_group_uuid();

        let creation = alice
            .client
            .create_group(
                Some(group_uuid.clone()),
                vec![bob.invitation(), carol.invitation()],
                Some(group_key.clone()),
            )
            .unwrap();

        let inspection = bob
            .client
            .inspect_welcome(creation.welcome, Some(group_uuid))
            .unwrap();

        let mut others = uuids(&[&alice, &carol]);
        others.sort();

        assert_eq!(inspection.committer_user_uuid, alice.uuid);
        assert_eq!(inspection.member_uuids, others);
        assert_eq!(inspection.welcome_payload, Some(group_key));
    }

    #[test]
    fn test_inspecting_a_welcome_stores_nothing_and_spends_nothing() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let group_uuid = new_group_uuid();

        // Sealed to a one-time key package, which a join spends.
        let creation = alice
            .client
            .create_group(
                Some(group_uuid.clone()),
                vec![bob.invitation()],
                Some(b"a group key".to_vec()),
            )
            .unwrap();

        let welcome = creation.welcome;
        let before = bob.store.records();

        let inspection = bob
            .client
            .inspect_welcome(welcome.clone(), Some(group_uuid.clone()))
            .unwrap();

        // Nothing stored, nobody pinned, and the key package still held.
        assert_eq!(bob.store.records(), before);

        // So the Welcome reads the same again, and joins afterwards.
        let again = bob
            .client
            .inspect_welcome(welcome.clone(), Some(group_uuid.clone()))
            .unwrap();

        assert_eq!(again.committer_user_uuid, inspection.committer_user_uuid);
        assert_eq!(again.member_uuids, inspection.member_uuids);

        let joined = bob
            .client
            .join_group(welcome, Some(group_uuid), inspection.member_uuids, true)
            .unwrap();

        assert_eq!(joined, creation.mls_group_id);

        let message = alice
            .client
            .load_group(creation.mls_group_id)
            .unwrap()
            .encrypt_application_message(b"joined".to_vec())
            .unwrap();

        assert!(
            bob.client
                .load_group(joined)
                .unwrap()
                .process_incoming_message(message)
                .is_ok()
        );
    }

    #[test]
    fn test_inspecting_a_welcome_to_a_group_past_the_member_cap_is_refused_and_stores_nothing() {
        let bob = TestUser::new();

        let (welcome, group_uuid, _) = welcome_to_a_group_of(MAX_GROUP_MEMBERS + 1, &bob);
        let before = bob.store.records();

        assert!(matches!(
            bob.client
                .inspect_welcome(welcome, Some(group_uuid))
                .unwrap_err(),
            MlsError::TooManyMembers
        ));

        assert_eq!(bob.store.records(), before);

        // A group of exactly the cap is read, every member but Bob listed:
        // nothing is stored, so the 64 KB a test lets a group store does not
        // stop it as it stops the join.
        let (welcome, group_uuid, mut others) = welcome_to_a_group_of(MAX_GROUP_MEMBERS, &bob);
        let before = bob.store.records();

        others.sort();

        assert_eq!(
            bob.client
                .inspect_welcome(welcome, Some(group_uuid))
                .unwrap()
                .member_uuids,
            others
        );
        assert_eq!(bob.store.records(), before);
    }

    #[test]
    fn test_inspecting_a_welcome_already_joined_is_refused_even_once_the_group_is_deleted() {
        // A last-resort key package survives the join, so the Welcome still
        // opens: only the record of the group refuses it.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let last_resort = InviteeKeyPackage {
            user_uuid: bob.uuid.clone(),
            key_package: bob
                .client
                .generate_key_packages(0)
                .unwrap()
                .last_resort_key_package,
        };

        let group_uuid = new_group_uuid();

        let creation = alice
            .client
            .create_group(Some(group_uuid.clone()), vec![last_resort], None)
            .unwrap();
        let welcome = creation.welcome;

        let group_id = bob
            .client
            .join_group(
                welcome.clone(),
                Some(group_uuid.clone()),
                uuids(&[&alice]),
                true,
            )
            .unwrap();

        let before = bob.store.records();

        assert!(matches!(
            bob.client
                .inspect_welcome(welcome.clone(), Some(group_uuid.clone()))
                .unwrap_err(),
            MlsError::GroupAlreadyJoined
        ));

        assert_eq!(bob.store.records(), before);

        bob.client.delete_group(group_id).unwrap();

        let before = bob.store.records();

        assert!(matches!(
            bob.client
                .inspect_welcome(welcome, Some(group_uuid))
                .unwrap_err(),
            MlsError::GroupAlreadyJoined
        ));

        assert_eq!(bob.store.records(), before);
    }

    #[test]
    fn test_inspecting_a_welcome_from_an_impostor_of_a_pinned_member_is_refused() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        // Alice meets Bob, pinning his signature key.
        establish_group(&alice, &[&bob]);

        let posing_as_bob =
            MlsClient::new(bob.uuid.clone(), SECRET.to_vec(), TestStore::new()).unwrap();

        let group_uuid = new_group_uuid();

        let creation = posing_as_bob
            .create_group(
                Some(group_uuid.clone()),
                vec![alice.invitation()],
                Some(b"a group key".to_vec()),
            )
            .unwrap();

        let before = alice.store.records();

        let error = alice
            .client
            .inspect_welcome(creation.welcome, Some(group_uuid))
            .expect_err("a Welcome signed with a key other than Bob's pinned one must be refused");

        assert!(matches!(error, MlsError::IdentityKeyMismatch(uuid) if uuid == bob.uuid));
        assert_eq!(alice.store.records(), before);
    }

    #[test]
    fn test_inspecting_an_unreadable_welcome_or_one_to_a_group_id_not_derived_is_refused() {
        let bob = TestUser::new();
        let before = bob.store.records();

        assert!(matches!(
            bob.client
                .inspect_welcome(b"not a Welcome".to_vec(), None)
                .unwrap_err(),
            MlsError::InvalidMessage
        ));

        assert_eq!(bob.store.records(), before);

        let (welcome, _) = foreign_welcome(&bob, vec![7u8; 16], ExtensionList::default());
        let before = bob.store.records();

        assert!(matches!(
            bob.client.inspect_welcome(welcome, None).unwrap_err(),
            MlsError::UnexpectedGroupId
        ));

        assert_eq!(bob.store.records(), before);
    }

    #[test]
    fn test_joining_with_the_inspected_members_succeeds_where_the_server_list_has_moved_on() {
        // Alice creates a group with Bob, Carol and Dave, and Dave deletes his
        // account before Carol joins: the server lists the group without him,
        // while the Welcome's tree, which nobody committed his removal from,
        // still holds him.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let dave = TestUser::new();

        let group_uuid = new_group_uuid();

        let creation = alice
            .client
            .create_group(
                Some(group_uuid.clone()),
                vec![bob.invitation(), carol.invitation(), dave.invitation()],
                None,
            )
            .unwrap();

        let welcome = creation.welcome;

        let server_list = uuids(&[&alice, &bob]);

        assert!(matches!(
            carol
                .client
                .join_group(
                    welcome.clone(),
                    Some(group_uuid.clone()),
                    server_list,
                    false
                )
                .unwrap_err(),
            MlsError::UnexpectedMembers
        ));

        let inspection = carol
            .client
            .inspect_welcome(welcome.clone(), Some(group_uuid.clone()))
            .unwrap();

        let mut tree = uuids(&[&alice, &bob, &dave]);
        tree.sort();

        assert_eq!(inspection.member_uuids, tree);

        let joined = carol
            .client
            .join_group(welcome, Some(group_uuid), inspection.member_uuids, false)
            .unwrap();

        let carol_group = carol.client.load_group(joined).unwrap();

        let mut everybody = uuids(&[&alice, &bob, &carol, &dave]);
        everybody.sort();

        assert_eq!(member_uuids(&carol_group), everybody);

        let message = alice
            .client
            .load_group(creation.mls_group_id)
            .unwrap()
            .encrypt_application_message(b"still here".to_vec())
            .unwrap();

        assert!(carol_group.process_incoming_message(message).is_ok());
    }

    #[test]
    fn test_a_client_signs_expenses_with_the_key_its_peers_pin() {
        let alice = TestUser::new();

        let manifest = OneTimeExpenseManifest {
            revision: 0,
            title: SealedValue {
                nonce: b"nonce".to_vec(),
                ciphertext: b"title".to_vec(),
            },
            description: SealedValue {
                nonce: b"nonce".to_vec(),
                ciphertext: b"description".to_vec(),
            },
            amount: SealedValue {
                nonce: b"nonce".to_vec(),
                ciphertext: b"amount".to_vec(),
            },
            currency: SealedValue {
                nonce: b"nonce".to_vec(),
                ciphertext: b"currency".to_vec(),
            },
            timestamp: SealedValue {
                nonce: b"nonce".to_vec(),
                ciphertext: b"timestamp".to_vec(),
            },
            beneficiaries: Vec::new(),
        };

        let signature = alice
            .client
            .sign_one_time_expense(manifest.clone())
            .unwrap();

        assert!(verify_one_time_expense(
            alice.uuid.clone(),
            alice.client.signature_public_key(),
            manifest,
            signature,
        ));
    }

    #[test]
    fn test_only_the_last_resort_key_package_is_marked_as_such() {
        let alice = TestUser::new();

        let bundle = alice.client.generate_key_packages(3).unwrap();

        assert!(has_last_resort_extension(&bundle.last_resort_key_package));

        assert_eq!(bundle.one_time_key_packages.len(), 3);

        for one_time in &bundle.one_time_key_packages {
            assert!(!has_last_resort_extension(one_time));
        }
    }

    /// Seconds since the Unix epoch, as the expiry of a key package is kept.
    fn now() -> u64 {
        MlsTime::now().seconds_since_epoch()
    }

    #[test]
    fn test_pruning_deletes_key_packages_only_once_they_have_expired() {
        let bob = TestUser::new();

        bob.client.generate_key_packages(3).unwrap();

        // The last-resort key package and the three one-time ones.
        assert_eq!(bob.store.count(MlsNamespace::KeyPackage), 4);

        let expiry = now() + KEY_PACKAGE_LIFETIME.as_secs();

        let pruned = bob
            .client
            .prune_key_packages_expired_before(expiry - 60 * 60)
            .unwrap();

        assert_eq!(pruned, 0);
        assert_eq!(bob.store.count(MlsNamespace::KeyPackage), 4);

        let pruned = bob
            .client
            .prune_key_packages_expired_before(expiry + 60 * 60)
            .unwrap();

        assert_eq!(pruned, 4);
        assert_eq!(bob.store.count(MlsNamespace::KeyPackage), 0);
    }

    #[test]
    fn test_a_welcome_to_a_pruned_key_package_cannot_be_joined() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let invitation = bob.invitation();

        bob.client
            .prune_key_packages_expired_before(now() + KEY_PACKAGE_LIFETIME.as_secs() + 60 * 60)
            .unwrap();

        let creation = alice
            .client
            .create_group(None, vec![invitation], None)
            .unwrap();

        bob.client
            .join_group(creation.welcome.clone(), None, uuids(&[&alice]), true)
            .expect_err("the secrets the Welcome was sealed to are gone");
    }

    #[test]
    fn test_pruning_leaves_groups_pins_and_the_signer_alone() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);

        bob.client.generate_key_packages(2).unwrap();

        bob.client
            .prune_key_packages_expired_before(u64::MAX)
            .unwrap();

        assert_eq!(bob.store.count(MlsNamespace::KeyPackage), 0);

        // The group, the pin of Alice, and Bob's own signature key all survive.
        let message = groups[0]
            .encrypt_application_message(b"still here".to_vec())
            .unwrap();

        bob.reopen()
            .load_group(groups[1].mls_group_id().unwrap())
            .unwrap()
            .process_incoming_message(message)
            .unwrap();

        assert!(
            bob.client
                .pinned_signature_key(alice.uuid.clone())
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn test_pruning_leaves_a_record_it_cannot_open_where_it_is() {
        let bob = TestUser::new();

        bob.client.generate_key_packages(1).unwrap();

        bob.store
            .put(MlsNamespace::KeyPackage, b"tampered".to_vec(), vec![0; 64])
            .unwrap();

        let pruned = bob
            .client
            .prune_key_packages_expired_before(u64::MAX)
            .unwrap();

        assert_eq!(pruned, 2);
        assert_eq!(bob.store.count(MlsNamespace::KeyPackage), 1);
    }

    /// How many groups `user` keeps a record of having deleted.
    fn deleted_group_records(user: &TestUser) -> usize {
        user.store
            .keys(MlsNamespace::Metadata)
            .unwrap()
            .iter()
            .filter(|key| key.starts_with(b"deleted-group/"))
            .count()
    }

    #[test]
    fn test_the_record_of_a_deleted_group_goes_with_the_key_packages_held_then() {
        // Joined through the last-resort key package, which survives the join.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let last_resort = InviteeKeyPackage {
            user_uuid: bob.uuid.clone(),
            key_package: bob
                .client
                .generate_key_packages(0)
                .unwrap()
                .last_resort_key_package,
        };

        let creation = alice
            .client
            .create_group(None, vec![last_resort], None)
            .unwrap();
        let welcome = creation.welcome.clone();

        let group_id = bob
            .client
            .join_group(welcome.clone(), None, uuids(&[&alice]), true)
            .unwrap();

        bob.client.delete_group(group_id).unwrap();

        assert_eq!(deleted_group_records(&bob), 1);

        // While that key package is held the Welcome still opens, and the record
        // is what refuses it.
        bob.client
            .prune_key_packages_expired_before(now() + KEY_PACKAGE_LIFETIME.as_secs() - 60)
            .unwrap();

        assert_eq!(deleted_group_records(&bob), 1);
        assert!(matches!(
            bob.client
                .join_group(welcome.clone(), None, uuids(&[&alice]), true)
                .unwrap_err(),
            MlsError::GroupAlreadyJoined
        ));

        // Pruned with it, the record goes, and the Welcome no longer opens at all.
        bob.client
            .prune_key_packages_expired_before(now() + KEY_PACKAGE_LIFETIME.as_secs() + 60)
            .unwrap();

        assert_eq!(bob.store.count(MlsNamespace::KeyPackage), 0);
        assert_eq!(deleted_group_records(&bob), 0);
        assert!(
            bob.client
                .join_group(welcome, None, uuids(&[&alice]), true)
                .is_err()
        );
        assert_eq!(bob.store.count(MlsNamespace::GroupState), 0);
    }

    #[test]
    fn test_key_packages_generated_after_a_deletion_do_not_keep_its_record() {
        // Taken from the key packages held at the deletion, not from the clock:
        // those going is what lets it go, and newer ones do not keep it.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);

        bob.client
            .delete_group(groups[1].mls_group_id().unwrap())
            .unwrap();

        let record = bob
            .store
            .keys(MlsNamespace::Metadata)
            .unwrap()
            .into_iter()
            .find(|key| key.starts_with(b"deleted-group/"))
            .unwrap();

        let openable_until = u64::from_be_bytes(
            bob.store
                .get(MlsNamespace::Metadata, record)
                .unwrap()
                .unwrap()
                .try_into()
                .unwrap(),
        );

        assert!(openable_until >= now() + KEY_PACKAGE_LIFETIME.as_secs() - 60);

        // Generated after the deletion, so expiring after what the record holds.
        std::thread::sleep(std::time::Duration::from_secs(2));
        bob.client.generate_key_packages(1).unwrap();

        bob.client
            .prune_key_packages_expired_before(openable_until)
            .unwrap();
        assert_eq!(deleted_group_records(&bob), 1);

        bob.client
            .prune_key_packages_expired_before(openable_until + 1)
            .unwrap();
        assert_eq!(deleted_group_records(&bob), 0);
        assert_eq!(bob.store.count(MlsNamespace::KeyPackage), 2);
    }

    #[test]
    fn test_pruning_now_keeps_freshly_generated_key_packages() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let invitation = bob.invitation();

        assert_eq!(bob.client.prune_key_packages().unwrap(), 0);

        let creation = alice
            .client
            .create_group(None, vec![invitation], None)
            .unwrap();

        bob.client
            .join_group(creation.welcome.clone(), None, uuids(&[&alice]), true)
            .unwrap();
    }

    #[test]
    fn test_pins_can_be_handed_out_and_put_back() {
        // A log-out empties the host store, so the pins a client built up go with it.
        // What the host kept has to be enough to put them back, or a client coming
        // back trusts whichever key package the server serves next for each peer.
        let alice = TestUser::new();
        let bob = TestUser::new();

        establish_group(&alice, &[&bob]);

        let pinned = alice
            .client
            .pinned_signature_key(bob.uuid.clone())
            .unwrap()
            .expect("meeting bob pinned him");

        assert_eq!(pinned, bob.client.signature_public_key());

        // Alice on a new device: her own signature key restored, and nothing else.
        let restored = MlsClient::restore(
            alice.uuid.clone(),
            SECRET.to_vec(),
            TestStore::new(),
            alice.client.signature_private_key(),
            alice.client.signature_public_key(),
        )
        .unwrap();

        assert!(
            restored
                .pinned_signature_key(bob.uuid.clone())
                .unwrap()
                .is_none(),
            "a restored client starts with no pins"
        );

        restored
            .pin_identity(bob.uuid.clone(), pinned.clone())
            .unwrap();

        assert_eq!(
            restored.pinned_signature_key(bob.uuid.clone()).unwrap(),
            Some(pinned)
        );
    }

    #[test]
    fn test_a_restored_pin_that_disagrees_is_refused() {
        // Putting pins back exists to keep noticing a substitution, so a backup that
        // disagrees with what this client already holds is the very event to report,
        // not one to quietly take the backup's word for.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let impostor = TestUser::new();

        establish_group(&alice, &[&bob]);

        let error = alice
            .client
            .pin_identity(bob.uuid.clone(), impostor.client.signature_public_key())
            .unwrap_err();

        assert!(matches!(error, MlsError::IdentityKeyMismatch(uuid) if uuid == bob.uuid));

        assert_eq!(
            alice.client.pinned_signature_key(bob.uuid.clone()).unwrap(),
            Some(bob.client.signature_public_key()),
            "the pin that was already there is left alone"
        );
    }

    #[test]
    fn test_a_substituted_signature_key_is_rejected() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        // Alice meets Bob, pinning his signature key.
        establish_group(&alice, &[&bob]);

        assert!(
            alice
                .client
                .pinned_signature_key(bob.uuid.clone())
                .unwrap()
                .is_some()
        );

        // Somebody else now claims Bob's UUID with a different signature key,
        // what a malicious server substituting a key package would look like.
        let impostor_store = TestStore::new();
        let impostor = MlsClient::new(bob.uuid.clone(), SECRET.to_vec(), impostor_store).unwrap();

        assert_ne!(
            impostor.signature_public_key(),
            bob.client.signature_public_key()
        );

        let impostor_key_package = InviteeKeyPackage {
            user_uuid: bob.uuid.clone(),
            key_package: impostor
                .generate_key_packages(1)
                .unwrap()
                .one_time_key_packages
                .remove(0),
        };

        let error = alice
            .client
            .create_group(None, vec![impostor_key_package], None)
            .expect_err("a substituted signature key must be refused");

        assert!(matches!(error, MlsError::IdentityKeyMismatch(uuid) if uuid == bob.uuid));

        // Once the user has verified the new key out of band, clearing the pin
        // lets the new key through.
        alice.client.clear_identity_pin(bob.uuid.clone()).unwrap();

        let replacement = InviteeKeyPackage {
            user_uuid: bob.uuid.clone(),
            key_package: impostor
                .generate_key_packages(1)
                .unwrap()
                .one_time_key_packages
                .remove(0),
        };

        assert!(
            alice
                .client
                .create_group(None, vec![replacement], None)
                .is_ok()
        );
    }

    #[test]
    fn test_a_key_package_for_the_wrong_user_is_rejected() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        // The server answers "give me Bob's key package" with Carol's.
        let mislabelled = InviteeKeyPackage {
            user_uuid: bob.uuid.clone(),
            key_package: carol.invitation().key_package,
        };

        let error = alice
            .client
            .create_group(None, vec![mislabelled], None)
            .expect_err("a key package for another user must be refused");

        assert!(matches!(
            error,
            MlsError::UnusableKeyPackages(ref named) if *named == [bob.uuid.clone()]
        ));
    }

    #[test]
    fn test_every_invitee_whose_key_package_cannot_be_used_is_named_and_nothing_is_done() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        // The server answers "give me Carol's key package" with Bob's.
        let mislabelled = InviteeKeyPackage {
            user_uuid: carol.uuid.clone(),
            key_package: bob.invitation().key_package,
        };

        let classical = classical_invitation();
        let expired = expired_invitation();

        let unusable = [
            classical.user_uuid.clone(),
            mislabelled.user_uuid.clone(),
            expired.user_uuid.clone(),
        ];

        let before = alice.store.records();

        let error = alice
            .client
            .create_group(
                Some(new_group_uuid()),
                vec![classical, bob.invitation(), mislabelled, expired],
                None,
            )
            .expect_err("key packages nobody can be added with must be refused");

        // All of them at once, in the order given, Bob's own aside: the
        // expired one too, which mls-rs would only refuse once the Commit is
        // built, naming nobody.
        assert!(matches!(
            error,
            MlsError::UnusableKeyPackages(ref named) if *named == unusable
        ));

        // Nothing was stored, and nobody pinned.
        assert_eq!(alice.store.records(), before);
    }

    #[test]
    fn test_both_users_see_the_same_safety_number() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        establish_group(&alice, &[&bob]);

        let as_alice_sees_it = alice
            .client
            .safety_number(bob.uuid.clone())
            .unwrap()
            .expect("meeting bob pinned him");

        assert_eq!(
            bob.client.safety_number(alice.uuid.clone()).unwrap(),
            Some(as_alice_sees_it.clone())
        );

        assert_eq!(
            as_alice_sees_it,
            safety_number(
                &alice.uuid,
                &alice.client.signature_public_key(),
                &bob.uuid,
                &bob.client.signature_public_key(),
            )
        );
    }

    #[test]
    fn test_there_is_no_safety_number_with_somebody_never_pinned() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        assert_eq!(alice.client.safety_number(bob.uuid.clone()).unwrap(), None);
    }

    #[test]
    fn test_a_safety_number_is_built_from_the_pinned_key() {
        // What a man in the middle looks like: the server served Alice a key of
        // its own for Bob, and that is the one she pinned, while Bob pinned
        // Alice's real one.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let impostor = TestUser::new();

        alice
            .client
            .pin_identity(bob.uuid.clone(), impostor.client.signature_public_key())
            .unwrap();
        bob.client
            .pin_identity(alice.uuid.clone(), alice.client.signature_public_key())
            .unwrap();

        let as_alice_sees_it = alice.client.safety_number(bob.uuid.clone()).unwrap();
        let as_bob_sees_it = bob.client.safety_number(alice.uuid.clone()).unwrap();

        assert_eq!(
            as_alice_sees_it,
            Some(safety_number(
                &alice.uuid,
                &alice.client.signature_public_key(),
                &bob.uuid,
                &impostor.client.signature_public_key(),
            ))
        );
        assert_ne!(as_alice_sees_it, as_bob_sees_it);

        // Once Alice pins Bob's real key instead, the two agree.
        alice.client.clear_identity_pin(bob.uuid.clone()).unwrap();
        alice
            .client
            .pin_identity(bob.uuid.clone(), bob.client.signature_public_key())
            .unwrap();

        assert_eq!(
            alice.client.safety_number(bob.uuid.clone()).unwrap(),
            as_bob_sees_it
        );
    }

    #[test]
    fn test_a_member_s_fingerprint_is_their_half_of_the_safety_number() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);

        let mut members = groups[0].members().unwrap();
        members.sort_by(|first, second| first.user_uuid.cmp(&second.user_uuid));

        assert_eq!(
            alice.client.safety_number(bob.uuid.clone()).unwrap(),
            Some(format!(
                "{} {}",
                members[0].fingerprint, members[1].fingerprint
            ))
        );
    }

    #[test]
    fn test_state_survives_a_restart() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);
        let group_id = groups[0].mls_group_id().unwrap();

        let ciphertext = groups[0]
            .encrypt_application_message(b"before the restart".to_vec())
            .unwrap();

        // Bob restarts: new client, same storage.
        drop(groups);

        let bob_client = bob.reopen();
        let bob_group = bob_client.load_group(group_id).unwrap();

        match bob_group.process_incoming_message(ciphertext).unwrap() {
            ProcessedMessage::ApplicationMessage { payload, .. } => {
                assert_eq!(payload, b"before the restart");
            }
            other => panic!(
                "expected an application message, got {:?}",
                other_kind(&other)
            ),
        }

        // The identity survived too, so peers still recognise him.
        assert_eq!(
            bob_client.signature_public_key(),
            bob.client.signature_public_key()
        );
    }

    #[test]
    fn test_stored_records_are_sealed() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        establish_group(&alice, &[&bob]);

        // The user's own UUID is the most recognisable plaintext in the state;
        // nothing the host holds may contain it.
        let uuid_bytes = alice.uuid.as_bytes();

        let unsealed = alice
            .store
            .values()
            .into_iter()
            .filter(|value| {
                value
                    .windows(uuid_bytes.len())
                    .any(|window| window == uuid_bytes)
            })
            .count();

        assert_eq!(unsealed, 0, "stored records must not contain plaintext");

        // And a different secret cannot open them.
        let error = MlsClient::new(
            alice.uuid.clone(),
            b"a different secret".to_vec(),
            alice.store.clone(),
        )
        .expect_err("the wrong secret must not open stored state");

        assert!(matches!(error, MlsError::StorageIntegrityFailed));
    }

    #[test]
    fn test_a_record_moved_to_another_slot_does_not_open() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        establish_group(&alice, &[&bob, &carol]);

        // Swap the two identity pins Alice holds. Both are well-formed records
        // sealed with her own key; only the slot they sit in has changed.
        let bob_pin = alice
            .store
            .get(MlsNamespace::IdentityPin, bob.uuid.as_bytes().to_vec())
            .unwrap()
            .unwrap();

        alice
            .store
            .put(
                MlsNamespace::IdentityPin,
                carol.uuid.as_bytes().to_vec(),
                bob_pin,
            )
            .unwrap();

        let error = alice
            .client
            .pinned_signature_key(carol.uuid.clone())
            .expect_err("a record moved between slots must not open");

        assert!(matches!(error, MlsError::StorageIntegrityFailed));
    }

    #[test]
    fn test_concurrent_commits_converge_on_server_order() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);
        let (alice_group, bob_group) = (&groups[0], &groups[1]);

        let epoch_before = alice_group.epoch().unwrap();

        // Both members commit in the same epoch, neither having seen the other.
        let alice_commit = alice_group.update().unwrap();
        let bob_commit = bob_group.update().unwrap();

        // The server happens to store Bob's first, so Bob's wins for everyone.
        assert!(matches!(
            alice_group.process_incoming_message(bob_commit).unwrap(),
            ProcessedMessage::Commit { .. }
        ));

        // Applying the winning commit discards Alice's, which simply never
        // happened; she has to reissue it if she still wants it.
        assert!(!alice_group.has_pending_commit().unwrap());

        accept(bob_group);

        assert_eq!(alice_group.epoch().unwrap(), epoch_before + 1);
        assert_eq!(bob_group.epoch().unwrap(), epoch_before + 1);

        // Bob rejects Alice's now-stale commit rather than forking.
        assert!(bob_group.process_incoming_message(alice_commit).is_err());

        // The group is still usable by both.
        let ciphertext = bob_group
            .encrypt_application_message(b"still working".to_vec())
            .unwrap();

        assert!(matches!(
            alice_group.process_incoming_message(ciphertext).unwrap(),
            ProcessedMessage::ApplicationMessage { .. }
        ));
    }

    #[test]
    fn test_a_rejected_commit_can_be_rolled_back_and_reissued() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let group_uuid = new_group_uuid();
        let groups = establish_group_as(&group_uuid, &alice, &[&bob]);
        let alice_group = &groups[0];

        let epoch_before = alice_group.epoch().unwrap();

        alice_group
            .add_members(vec![carol.invitation()], None)
            .unwrap();
        assert!(alice_group.has_pending_commit().unwrap());

        // The server rejected it.
        alice_group.clear_pending_commit().unwrap();

        assert!(!alice_group.has_pending_commit().unwrap());
        assert_eq!(alice_group.epoch().unwrap(), epoch_before);

        // And the change can be made again.
        let output = alice_group
            .add_members(vec![carol.invitation()], None)
            .unwrap();
        accept(alice_group);

        assert_eq!(alice_group.epoch().unwrap(), epoch_before + 1);
        assert!(
            carol
                .client
                .join_group(
                    output.welcome.clone(),
                    Some(group_uuid),
                    uuids(&[&alice, &bob]),
                    true,
                )
                .is_ok()
        );
    }

    #[test]
    fn test_a_pending_commit_survives_a_restart() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);
        let group_id = groups[0].mls_group_id().unwrap();

        groups[0]
            .add_members(vec![carol.invitation()], None)
            .unwrap();

        // The app dies between sending the commit and learning its fate.
        drop(groups);

        let alice_client = alice.reopen();
        let alice_group = alice_client.load_group(group_id).unwrap();

        assert!(
            alice_group.has_pending_commit().unwrap(),
            "an unresolved commit must still be visible after a restart"
        );

        alice_group.apply_pending_commit().unwrap();

        assert!(member_uuids(&alice_group).contains(&carol.uuid));
    }

    #[test]
    fn test_self_removal_is_a_proposal_another_member_commits() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let groups = establish_group(&alice, &[&bob, &carol]);
        let (alice_group, bob_group, carol_group) = (&groups[0], &groups[1], &groups[2]);

        // Carol is deleting her account.
        let proposal = carol_group.propose_self_remove().unwrap();

        // Proposing changes nothing on its own: she is still a member.
        assert!(member_uuids(carol_group).contains(&carol.uuid));

        assert!(matches!(
            alice_group
                .process_incoming_message(proposal.clone())
                .unwrap(),
            ProcessedMessage::Proposal { .. }
        ));

        bob_group.process_incoming_message(proposal).unwrap();

        // A remaining member commits it, and only then is Carol gone.
        let commit = alice_group.update().unwrap();
        accept(alice_group);

        bob_group.process_incoming_message(commit).unwrap();

        let mut expected = vec![alice.uuid.clone(), bob.uuid.clone()];
        expected.sort();

        assert_eq!(member_uuids(alice_group), expected);
        assert_eq!(member_uuids(bob_group), expected);
    }

    #[test]
    fn test_a_classical_cipher_suite_is_refused() {
        let alice = TestUser::new();

        let classical = classical_invitation();
        let user_uuid = classical.user_uuid.clone();

        let error = alice
            .client
            .create_group(None, vec![classical], None)
            .expect_err("a classical cipher suite must be refused");

        assert!(matches!(
            error,
            MlsError::UnusableKeyPackages(ref named) if *named == [user_uuid]
        ));
    }

    #[test]
    fn test_deleting_a_group_removes_its_stored_state() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);
        let group_id = groups[0].mls_group_id().unwrap();

        drop(groups);

        alice.client.delete_group(group_id.clone()).unwrap();

        assert!(matches!(
            alice.client.load_group(group_id).unwrap_err(),
            MlsError::GroupNotFound
        ));

        assert!(
            alice
                .store
                .keys(MlsNamespace::GroupEpoch)
                .unwrap()
                .is_empty()
        );
    }

    /// Whether a serialised key package carries the last-resort extension.
    fn has_last_resort_extension(key_package: &[u8]) -> bool {
        MlsMessage::from_bytes(key_package)
            .unwrap()
            .as_key_package()
            .unwrap()
            .extensions
            .has_extension(LastResortKeyPackageExt::extension_type())
    }

    /// A key package from a client running a classical cipher suite.
    fn classical_invitation() -> InviteeKeyPackage {
        const CLASSICAL: CipherSuite = CipherSuite::CURVE25519_AES128;

        let user_uuid = Uuid::new_v4().to_string();

        let crypto_provider = AwsLcCryptoProvider::new();

        let cipher_suite_provider = crypto_provider.cipher_suite_provider(CLASSICAL).unwrap();
        let (secret, public) = cipher_suite_provider.signature_key_generate().unwrap();

        let signing_identity = SigningIdentity::new(
            BasicCredential::new(user_uuid.as_bytes().to_vec()).into_credential(),
            public,
        );

        let client = Client::builder()
            .identity_provider(BasicIdentityProvider)
            .crypto_provider(crypto_provider)
            .signing_identity(signing_identity, secret, CLASSICAL)
            .build();

        assert_ne!(CLASSICAL, CIPHER_SUITE);

        InviteeKeyPackage {
            user_uuid,
            key_package: client
                .generate_key_package_message(
                    ExtensionList::default(),
                    ExtensionList::default(),
                    None,
                )
                .unwrap()
                .to_bytes()
                .unwrap(),
        }
    }

    /// A key package of somebody nobody has met, generated as of two years ago,
    /// longer ago than any key package lives, so expired.
    fn expired_invitation() -> InviteeKeyPackage {
        let user_uuid = Uuid::new_v4().to_string();

        let key_package = plain_client(user_uuid.clone())
            .generate_key_package_message(
                ExtensionList::default(),
                ExtensionList::default(),
                Some(MlsTime::from(now() - 2 * 365 * 24 * 60 * 60)),
            )
            .unwrap()
            .to_bytes()
            .unwrap();

        InviteeKeyPackage {
            user_uuid,
            key_package,
        }
    }

    /// A short label for a processed message, for assertion failures.
    fn other_kind(message: &ProcessedMessage) -> &'static str {
        match message {
            ProcessedMessage::ApplicationMessage { .. } => "application message",
            ProcessedMessage::Commit { .. } => "commit",
            ProcessedMessage::Proposal { .. } => "proposal",
            ProcessedMessage::Ignored => "ignored",
        }
    }
}
