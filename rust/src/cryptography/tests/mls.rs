#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    use mls_rs::extension::MlsExtension;
    use mls_rs::extension::recommended::LastResortKeyPackageExt;
    use mls_rs::identity::SigningIdentity;
    use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
    use mls_rs::time::MlsTime;
    use mls_rs::{
        CipherSuite, CipherSuiteProvider, Client, CryptoProvider, ExtensionList, MlsMessage,
    };
    use mls_rs_crypto_awslc::AwsLcCryptoProvider;
    use uuid::Uuid;

    use crate::cryptography::mls::client::MlsClient;
    use crate::cryptography::mls::config::KEY_PACKAGE_LIFETIME;
    use crate::cryptography::mls::group::MlsGroup;
    use crate::cryptography::mls::one_time_expense::{
        OneTimeExpenseManifest, SealedValue, verify_one_time_expense,
    };
    use crate::cryptography::mls::storage::{MlsNamespace, MlsStore, MlsStoreError};
    use crate::cryptography::mls::types::{InviteeKeyPackage, ProcessedMessage};
    use crate::cryptography::mls::{CIPHER_SUITE, MlsError};

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

    /// Creates a group owned by `creator` and joins every invitee to it.
    ///
    /// Returns the creator's group followed by each invitee's, in order.
    fn establish_group(creator: &TestUser, invitees: &[&TestUser]) -> Vec<Arc<MlsGroup>> {
        let creation = creator
            .client
            .create_group(invitees.iter().map(|user| user.invitation()).collect())
            .unwrap();

        let mut groups = vec![
            creator
                .client
                .load_group(creation.mls_group_id.clone())
                .unwrap(),
        ];

        for user in invitees {
            let welcome = creation
                .welcomes
                .iter()
                .find(|welcome| welcome.user_uuid == user.uuid)
                .expect("every invitee gets a welcome");

            let others = std::iter::once(creator)
                .chain(invitees.iter().copied())
                .filter(|other| other.uuid != user.uuid)
                .collect::<Vec<_>>();

            let group_id = user
                .client
                .join_group(welcome.welcome.clone(), uuids(&others), true)
                .unwrap();

            groups.push(user.client.load_group(group_id).unwrap());
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

        let groups = establish_group(&alice, &[&bob]);
        let (alice_group, bob_group) = (&groups[0], &groups[1]);

        let epoch_before = alice_group.epoch().unwrap();

        let output = alice_group.add_members(vec![carol.invitation()]).unwrap();

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
                output.welcomes[0].welcome.clone(),
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
    fn test_each_invitee_gets_their_own_welcome() {
        let alice = TestUser::new();
        let invitees = (0..4).map(|_| TestUser::new()).collect::<Vec<_>>();

        let creation = alice
            .client
            .create_group(invitees.iter().map(TestUser::invitation).collect())
            .unwrap();

        assert_eq!(creation.welcomes.len(), invitees.len());

        // Each Welcome must be usable by the member it is addressed to, and by
        // nobody else, that is what makes the mapping meaningful rather than a
        // convenient ordering.
        for (index, user) in invitees.iter().enumerate() {
            let welcome = creation
                .welcomes
                .iter()
                .find(|welcome| welcome.user_uuid == user.uuid)
                .expect("every invitee gets a welcome");

            let others = std::iter::once(&alice)
                .chain(&invitees)
                .filter(|other| other.uuid != user.uuid)
                .collect::<Vec<_>>();

            let someone_else = &creation.welcomes[(index + 1) % creation.welcomes.len()];

            if someone_else.user_uuid != user.uuid {
                assert!(
                    user.client
                        .join_group(someone_else.welcome.clone(), uuids(&others), true)
                        .is_err()
                );
            }

            assert!(
                user.client
                    .join_group(welcome.welcome.clone(), uuids(&others), true)
                    .is_ok()
            );
        }
    }

    /// Joins `inviter`'s new group with `joiner` as a contact request is
    /// opened: expecting the inviter, and pinning nobody.
    fn open_request(inviter: &TestUser, joiner: &TestUser) -> (Arc<MlsGroup>, Arc<MlsGroup>) {
        let creation = inviter
            .client
            .create_group(vec![joiner.invitation()])
            .unwrap();

        let group_id = joiner
            .client
            .join_group(
                creation.welcomes[0].welcome.clone(),
                uuids(&[inviter]),
                false,
            )
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

    /// Whether `receiver` reads a message from `sender` as signed with the key
    /// pinned for them.
    fn reads_as_pinned(sender: &MlsGroup, receiver: &MlsGroup) -> bool {
        let message = sender
            .encrypt_application_message(b"hello".to_vec())
            .unwrap();

        match receiver.process_incoming_message(message).unwrap() {
            ProcessedMessage::ApplicationMessage {
                is_sender_pinned, ..
            } => is_sender_pinned,
            other => panic!(
                "expected an application message, got {:?}",
                other_kind(&other)
            ),
        }
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

        let groups = establish_group(&mallory, &[&victor]);
        let (mallory_group, victor_group) = (&groups[0], &groups[1]);

        let store = TestStore::new();
        let posing_as_quentin = TestUser {
            uuid: quentin.uuid.clone(),
            client: MlsClient::new(quentin.uuid.clone(), SECRET.to_vec(), store.clone()).unwrap(),
            store,
        };

        let output = mallory_group
            .add_members(vec![posing_as_quentin.invitation()])
            .unwrap();

        victor_group
            .process_incoming_message(output.commit)
            .unwrap();
        accept(mallory_group);

        let fake_group_id = posing_as_quentin
            .client
            .join_group(
                output.welcomes[0].welcome.clone(),
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
            .add_members(vec![posing_as_quentin.invitation()])
            .unwrap();

        victor_group
            .process_incoming_message(output.commit)
            .unwrap();

        assert!(matches!(
            victor_group.pin_members(uuids(&[&mallory])).unwrap_err(),
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
    fn test_a_welcome_with_unexpected_members_is_refused_and_leaves_nothing() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let creation = alice
            .client
            .create_group(vec![bob.invitation(), carol.invitation()])
            .unwrap();

        let welcome = creation
            .welcomes
            .iter()
            .find(|welcome| welcome.user_uuid == bob.uuid)
            .unwrap();

        // Bob was told this is a group with Alice alone.
        let error = bob
            .client
            .join_group(welcome.welcome.clone(), uuids(&[&alice]), true)
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
                .join_group(welcome.welcome.clone(), uuids(&[&alice, &carol]), true)
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
            .create_group(vec![victor.invitation()])
            .unwrap();

        let error = victor
            .client
            .join_group(
                creation.welcomes[0].welcome.clone(),
                uuids(&[&mallory]),
                true,
            )
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
            .create_group(vec![alice.invitation()])
            .unwrap();

        let error = alice
            .client
            .join_group(creation.welcomes[0].welcome.clone(), uuids(&[&bob]), false)
            .expect_err("a Welcome signed with a key other than Bob's pinned one must be refused");

        assert!(matches!(error, MlsError::IdentityKeyMismatch(uuid) if uuid == bob.uuid));
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

        let creation = alice.client.create_group(vec![last_resort]).unwrap();
        let welcome = creation.welcomes[0].welcome.clone();

        let group_id = bob
            .client
            .join_group(welcome.clone(), uuids(&[&alice]), true)
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
            .join_group(welcome.clone(), uuids(&[&alice]), true)
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
            .join_group(welcome, uuids(&[&alice]), true)
            .expect_err("a Welcome for a deleted group must be refused");

        assert!(matches!(error, MlsError::GroupAlreadyJoined));
    }

    #[test]
    fn test_a_client_signs_expenses_with_the_key_its_peers_pin() {
        let alice = TestUser::new();

        let manifest = OneTimeExpenseManifest {
            revision: 0,
            is_settlement: false,
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

        let creation = alice.client.create_group(vec![invitation]).unwrap();

        bob.client
            .join_group(creation.welcomes[0].welcome.clone(), uuids(&[&alice]), true)
            .expect_err("the secrets the Welcome was sealed to are gone");
    }

    #[test]
    fn test_pruning_leaves_everything_but_key_packages_alone() {
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
                .pinned_fingerprint(alice.uuid.clone())
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

    #[test]
    fn test_pruning_now_keeps_freshly_generated_key_packages() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let invitation = bob.invitation();

        assert_eq!(bob.client.prune_key_packages().unwrap(), 0);

        let creation = alice.client.create_group(vec![invitation]).unwrap();

        bob.client
            .join_group(creation.welcomes[0].welcome.clone(), uuids(&[&alice]), true)
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
                .pinned_fingerprint(bob.uuid.clone())
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
            .create_group(vec![impostor_key_package])
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

        assert!(alice.client.create_group(vec![replacement]).is_ok());
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
            .create_group(vec![mislabelled])
            .expect_err("a key package for another user must be refused");

        assert!(matches!(error, MlsError::InvalidCredential));
    }

    #[test]
    fn test_fingerprints_are_stable_and_agree_between_clients() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);

        let bob_as_alice_sees_him = groups[0]
            .members()
            .unwrap()
            .into_iter()
            .find(|member| member.user_uuid == bob.uuid)
            .unwrap()
            .fingerprint;

        assert_eq!(bob_as_alice_sees_him, bob.client.fingerprint());

        assert_eq!(
            alice.client.pinned_fingerprint(bob.uuid.clone()).unwrap(),
            Some(bob.client.fingerprint())
        );

        assert_ne!(alice.client.fingerprint(), bob.client.fingerprint());
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
            .pinned_fingerprint(carol.uuid.clone())
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

        let groups = establish_group(&alice, &[&bob]);
        let alice_group = &groups[0];

        let epoch_before = alice_group.epoch().unwrap();

        alice_group.add_members(vec![carol.invitation()]).unwrap();
        assert!(alice_group.has_pending_commit().unwrap());

        // The server rejected it.
        alice_group.clear_pending_commit().unwrap();

        assert!(!alice_group.has_pending_commit().unwrap());
        assert_eq!(alice_group.epoch().unwrap(), epoch_before);

        // And the change can be made again.
        let output = alice_group.add_members(vec![carol.invitation()]).unwrap();
        accept(alice_group);

        assert_eq!(alice_group.epoch().unwrap(), epoch_before + 1);
        assert!(
            carol
                .client
                .join_group(
                    output.welcomes[0].welcome.clone(),
                    uuids(&[&alice, &bob]),
                    true
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

        groups[0].add_members(vec![carol.invitation()]).unwrap();

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

        let error = alice
            .client
            .create_group(vec![classical_invitation()])
            .expect_err("a classical cipher suite must be refused");

        assert!(matches!(error, MlsError::InvalidKeyPackage));
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
