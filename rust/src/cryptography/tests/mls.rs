#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    use mls_rs::client_builder::MlsConfig;
    use mls_rs::extension::MlsExtension;
    use mls_rs::extension::recommended::LastResortKeyPackageExt;
    use mls_rs::group::ContentType;
    use mls_rs::identity::SigningIdentity;
    use mls_rs::identity::basic::{BasicCredential, BasicIdentityProvider};
    use mls_rs::storage_provider::in_memory::InMemoryGroupStateStorage;
    use mls_rs::time::MlsTime;
    use mls_rs::{
        CipherSuite, CipherSuiteProvider, Client, CryptoProvider, Extension, ExtensionList, Group,
        MlsMessage,
    };
    use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
    use mls_rs_crypto_awslc::AwsLcCryptoProvider;
    use uuid::Uuid;
    use zeroize::Zeroizing;

    use crate::cryptography::mls::client::MlsClient;
    use crate::cryptography::mls::config::{KEY_PACKAGE_LIFETIME, mls_rules};
    use crate::cryptography::mls::group::MlsGroup;
    use crate::cryptography::mls::group_expense::{
        GroupExpenseBeneficiary, GroupExpenseDeletion, GroupExpenseVersion, verify_group_expense,
        verify_group_expense_deletion,
    };
    use crate::cryptography::mls::group_id::{
        CHANNEL_NONCE_EXTENSION, channel_group_id, server_group_id,
    };
    use crate::cryptography::mls::group_information::{GroupInformation, verify_group_information};
    use crate::cryptography::mls::identity::fingerprint::safety_number;
    use crate::cryptography::mls::one_time_expense::{
        OneTimeExpenseManifest, SealedValue, verify_one_time_expense,
    };
    use crate::cryptography::mls::storage::group_state::{
        max_group_state_len, max_group_state_len_at_rest, max_group_state_len_at_rest_in_tests,
        max_group_state_len_in_tests, with_limits_outside_tests,
    };
    use crate::cryptography::mls::storage::{MlsNamespace, MlsStore, MlsStoreError};
    use crate::cryptography::mls::types::{CommitPolicy, InviteeKeyPackage, ProcessedMessage};
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

    /// The commit policy of a group `creator` created, which nobody has
    /// departed.
    fn created_by(creator: &TestUser) -> Option<CommitPolicy> {
        commit_policy(&creator.uuid, &[])
    }

    /// The commit policy of a group `creator_uuid` created, which
    /// `departed_uuids` have departed.
    fn commit_policy(creator_uuid: &str, departed_uuids: &[&str]) -> Option<CommitPolicy> {
        Some(CommitPolicy {
            creator_uuid: creator_uuid.to_string(),
            departed_uuids: departed_uuids.iter().map(ToString::to_string).collect(),
        })
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

    /// How large the state `user` stores for the group `group_id` is, before
    /// sealing.
    fn stored_state_len(user: &TestUser, group_id: &[u8]) -> usize {
        let sealed = user
            .store
            .get(MlsNamespace::GroupState, group_id.to_vec())
            .unwrap()
            .unwrap();

        // Sealing adds a 12-byte nonce and a 16-byte tag.
        sealed.len() - 12 - 16
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
            match group
                .process_incoming_message(ciphertext.clone(), None)
                .unwrap()
            {
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
            bob_group
                .process_incoming_message(output.commit, None)
                .unwrap(),
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
                .process_incoming_message(commit.clone(), None)
                .unwrap(),
            ProcessedMessage::Commit {
                removed_self: true,
                ..
            }
        ));

        assert!(matches!(
            bob_group.process_incoming_message(commit, None).unwrap(),
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
                .process_incoming_message(ciphertext.clone(), None)
                .is_ok()
        );
        assert!(
            carol_group
                .process_incoming_message(ciphertext, None)
                .is_err()
        );
    }

    #[test]
    fn test_a_commit_names_its_committer_and_the_epoch_each_member_is_in() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let groups = establish_group(&alice, &[&bob, &carol]);
        let (alice_group, bob_group, carol_group) = (&groups[0], &groups[1], &groups[2]);

        let epoch_before = alice_group.epoch().unwrap();

        let removal = alice_group
            .remove_members(vec![carol.uuid.clone()])
            .unwrap();

        // Bob moves on to the next epoch, and Carol, removed, stays in the one
        // she was in.
        for (group, epoch, removed) in [
            (bob_group, epoch_before + 1, false),
            (carol_group, epoch_before, true),
        ] {
            match group
                .process_incoming_message(removal.clone(), None)
                .unwrap()
            {
                ProcessedMessage::Commit {
                    committer_user_uuid,
                    epoch: epoch_now,
                    removed_self,
                } => {
                    assert_eq!(committer_user_uuid, Some(alice.uuid.clone()));
                    assert_eq!(epoch_now, epoch);
                    assert_eq!(group.epoch().unwrap(), epoch);
                    assert_eq!(removed_self, removed);
                }
                other => panic!("expected a commit, got {:?}", other_kind(&other)),
            }
        }
    }

    #[test]
    fn test_removing_nobody_is_refused_before_anything_is_built() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);
        let before = alice.store.records();

        let error = groups[0]
            .remove_members(Vec::new())
            .expect_err("removing nobody must be refused");

        assert!(matches!(error, MlsError::ProtocolFailed(_)));

        // Nothing was stored, nor built: the group still commits.
        assert_eq!(alice.store.records(), before);
        assert!(!groups[0].has_pending_commit().unwrap());

        groups[0].update().unwrap();
    }

    #[test]
    fn test_members_holding_to_the_commit_policy_follow_the_creators_removals_and_additions() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let dave = TestUser::new();

        let group_uuid = new_group_uuid();
        let groups = establish_group_as(&group_uuid, &alice, &[&bob, &carol]);
        let (alice_group, bob_group, carol_group) = (&groups[0], &groups[1], &groups[2]);

        let policy = created_by(&alice);

        let removal = alice_group
            .remove_members(vec![carol.uuid.clone()])
            .unwrap();

        for (group, removed) in [(carol_group, true), (bob_group, false)] {
            assert!(matches!(
                group
                    .process_incoming_message(removal.clone(), policy.clone())
                    .unwrap(),
                ProcessedMessage::Commit { removed_self, .. } if removed_self == removed
            ));
        }

        accept(alice_group);

        let addition = alice_group
            .add_members(vec![dave.invitation()], None)
            .unwrap();

        assert!(matches!(
            bob_group
                .process_incoming_message(addition.commit, policy.clone())
                .unwrap(),
            ProcessedMessage::Commit {
                removed_self: false,
                ..
            }
        ));

        accept(alice_group);

        let dave_group_id = dave
            .client
            .join_group(
                addition.welcome,
                Some(group_uuid),
                uuids(&[&alice, &bob]),
                true,
            )
            .unwrap();
        let dave_group = dave.client.load_group(dave_group_id).unwrap();

        let mut expected = uuids(&[&alice, &bob, &dave]);
        expected.sort();

        assert_eq!(member_uuids(alice_group), expected);
        assert_eq!(member_uuids(bob_group), expected);
        assert_eq!(member_uuids(&dave_group), expected);

        // Whoever sends to the group, it is read as before.
        let message = dave_group
            .encrypt_application_message(b"hello".to_vec())
            .unwrap();

        for group in [alice_group, bob_group] {
            assert!(matches!(
                group
                    .process_incoming_message(message.clone(), policy.clone())
                    .unwrap(),
                ProcessedMessage::ApplicationMessage { sender_user_uuid, .. }
                    if sender_user_uuid == dave.uuid
            ));
        }
    }

    #[test]
    fn test_members_holding_to_the_commit_policy_apply_the_creators_update() {
        // Alice, the creator, replaces a Commit nobody could apply with nobody
        // left to remove: an update, which the server lists with no departed
        // members.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let group_uuid = new_group_uuid();
        let groups = establish_group_as(&group_uuid, &alice, &[&bob, &carol]);
        let (alice_group, bob_group, carol_group) = (&groups[0], &groups[1], &groups[2]);

        let epoch = alice_group.epoch().unwrap();
        let mut expected = uuids(&[&alice, &bob, &carol]);
        expected.sort();

        let update = alice_group.update().unwrap();
        let next_key = alice_group
            .content_key_after_pending_commit(group_uuid.clone())
            .unwrap();

        for group in [bob_group, carol_group] {
            assert!(matches!(
                group
                    .process_incoming_message(update.clone(), created_by(&alice))
                    .unwrap(),
                ProcessedMessage::Commit { committer_user_uuid, removed_self: false, .. }
                    if committer_user_uuid == Some(alice.uuid.clone())
            ));
        }

        accept(alice_group);

        // One epoch further, under a key every member derives, and nobody
        // added or removed.
        for group in [alice_group, bob_group, carol_group] {
            assert_eq!(group.epoch().unwrap(), epoch + 1);
            assert_eq!(group.content_key(group_uuid.clone()).unwrap(), next_key);
            assert_eq!(member_uuids(group), expected);
        }
    }

    #[test]
    fn test_an_addition_by_anybody_but_the_creator_is_refused_and_nothing_stored() {
        // Bob, a member, commits a stranger in, while Alice, the creator, has
        // his removal pending. Dave has left, which lets Bob remove him, and
        // nothing more.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let dave = TestUser::new();

        let groups = establish_group(&alice, &[&bob, &carol, &dave]);
        let (alice_group, bob_group, carol_group) = (&groups[0], &groups[1], &groups[2]);

        let policy = commit_policy(&alice.uuid, &[&dave.uuid]);
        let epoch = alice_group.epoch().unwrap();

        let intrusion = bob_group
            .add_members(stranger_invitations(1), None)
            .unwrap()
            .commit;

        let removal = alice_group.remove_members(vec![bob.uuid.clone()]).unwrap();

        for (user, group) in [(&alice, alice_group), (&carol, carol_group)] {
            let before = user.store.records();

            let error = group
                .process_incoming_message(intrusion.clone(), policy.clone())
                .expect_err("an addition from anybody but the creator must be refused");

            assert!(matches!(error, MlsError::UnauthorizedChange));

            // Nothing was stored, nor kept in memory.
            assert_eq!(user.store.records(), before);
            assert_eq!(group.epoch().unwrap(), epoch);
            assert_eq!(group.members().unwrap().len(), 4);
        }

        // Alice's removal is still pending, as it would not be had Bob's Commit
        // been applied, and it is the one Carol follows.
        assert!(alice_group.has_pending_commit().unwrap());

        assert!(matches!(
            carol_group
                .process_incoming_message(removal, policy)
                .unwrap(),
            ProcessedMessage::Commit { .. }
        ));

        accept(alice_group);

        let mut expected = uuids(&[&alice, &carol, &dave]);
        expected.sort();

        assert_eq!(member_uuids(alice_group), expected);
        assert_eq!(member_uuids(carol_group), expected);
    }

    #[test]
    fn test_a_proposal_is_refused_from_any_member_where_a_commit_policy_is_held() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let groups = establish_group(&alice, &[&bob, &carol]);
        let (alice_group, bob_group, carol_group) = (&groups[0], &groups[1], &groups[2]);

        // Carol, leaving, proposes her own removal, which the creator refuses
        // like everybody else, even with her departed.
        let policy = commit_policy(&alice.uuid, &[&carol.uuid]);
        let leaving = carol_group.propose_self_remove().unwrap();

        assert!(matches!(
            alice_group
                .process_incoming_message(leaving.clone(), policy.clone())
                .unwrap_err(),
            MlsError::UnauthorizedChange
        ));

        // A proposal of the creator's own goes the same way.
        let creators = alice_group.propose_self_remove().unwrap();

        let before = bob.store.records();

        for proposal in [leaving, creators] {
            assert!(matches!(
                bob_group
                    .process_incoming_message(proposal, policy.clone())
                    .unwrap_err(),
                MlsError::UnauthorizedChange
            ));
        }

        // Nothing was stored, nor kept: Bob still sends, which a proposal kept
        // would stop until somebody committed it.
        assert_eq!(bob.store.records(), before);

        bob_group
            .encrypt_application_message(b"still here".to_vec())
            .unwrap();
    }

    #[test]
    fn test_a_commit_the_policy_does_not_allow_is_refused_before_what_it_carries_is_checked() {
        // Bob, a member, commits Dave in under a key of his own making. Alice,
        // the creator, has Dave's real key pinned, Carol none.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let dave = TestUser::new();

        establish_group(&alice, &[&dave]);

        let groups = establish_group(&alice, &[&bob, &carol]);
        let (alice_group, bob_group, carol_group) = (&groups[0], &groups[1], &groups[2]);

        let forged_dave = InviteeKeyPackage {
            user_uuid: dave.uuid.clone(),
            key_package: plain_client(dave.uuid.clone())
                .generate_key_package_message(
                    ExtensionList::default(),
                    ExtensionList::default(),
                    None,
                )
                .unwrap()
                .to_bytes()
                .unwrap(),
        };

        let intrusion = bob_group
            .add_members(vec![forged_dave], None)
            .unwrap()
            .commit;

        // Both refuse it for who committed it, Alice without telling of a key
        // Dave never changed.
        for (user, group) in [(&alice, alice_group), (&carol, carol_group)] {
            let before = user.store.records();

            assert!(matches!(
                group
                    .process_incoming_message(intrusion.clone(), created_by(&alice))
                    .unwrap_err(),
                MlsError::UnauthorizedChange
            ));

            assert_eq!(user.store.records(), before);
        }
    }

    #[test]
    fn test_a_removal_of_departed_members_by_any_member_is_applied() {
        // Carol and Dave have left, and Bob, a member, commits their removal
        // while Alice, the creator, is away.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let dave = TestUser::new();
        let erin = TestUser::new();

        let groups = establish_group(&alice, &[&bob, &carol, &dave, &erin]);
        let (alice_group, bob_group, erin_group) = (&groups[0], &groups[1], &groups[4]);

        // The server stored it with both, in whatever order, a member named
        // twice counting once.
        let policy = commit_policy(&alice.uuid, &[&dave.uuid, &carol.uuid, &dave.uuid]);
        let epoch = alice_group.epoch().unwrap();

        let removal = bob_group
            .remove_members(vec![carol.uuid.clone(), dave.uuid.clone()])
            .unwrap();

        // Each member who reads it is told who removed them.
        for group in [alice_group, erin_group] {
            match group
                .process_incoming_message(removal.clone(), policy.clone())
                .unwrap()
            {
                ProcessedMessage::Commit {
                    committer_user_uuid,
                    removed_self,
                    ..
                } => {
                    assert_eq!(committer_user_uuid, Some(bob.uuid.clone()));
                    assert!(!removed_self);
                }
                other => panic!("expected a commit, got {:?}", other_kind(&other)),
            }
        }

        accept(bob_group);

        let mut expected = uuids(&[&alice, &bob, &erin]);
        expected.sort();

        for group in [alice_group, bob_group, erin_group] {
            assert_eq!(member_uuids(group), expected);
            assert_eq!(group.epoch().unwrap(), epoch + 1);
        }

        // Alice still changes the group as she likes once she is back, her
        // Commit stored with nobody departed.
        let removal = alice_group.remove_members(vec![erin.uuid.clone()]).unwrap();

        assert!(matches!(
            bob_group
                .process_incoming_message(removal, created_by(&alice))
                .unwrap(),
            ProcessedMessage::Commit { committer_user_uuid, .. }
                if committer_user_uuid == Some(alice.uuid.clone())
        ));
    }

    #[test]
    fn test_a_removal_of_fewer_departed_members_than_the_server_stored_it_with_is_refused() {
        // Carol and Dave have left, and Bob, a member, names them both to the
        // server but removes Carol alone, which would leave Dave's leaf in
        // the tree once the server counts him as removed.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let dave = TestUser::new();
        let erin = TestUser::new();

        let groups = establish_group(&alice, &[&bob, &carol, &dave, &erin]);
        let (alice_group, bob_group, erin_group) = (&groups[0], &groups[1], &groups[4]);

        let stored_with = commit_policy(&alice.uuid, &[&carol.uuid, &dave.uuid]);
        let epoch = alice_group.epoch().unwrap();

        let removal = bob_group.remove_members(vec![carol.uuid.clone()]).unwrap();

        let mut expected = uuids(&[&alice, &bob, &carol, &dave, &erin]);
        expected.sort();

        for (user, group) in [(&alice, alice_group), (&erin, erin_group)] {
            let before = user.store.records();

            assert!(matches!(
                group
                    .process_incoming_message(removal.clone(), stored_with.clone())
                    .unwrap_err(),
                MlsError::UnauthorizedChange
            ));

            // Nothing was stored, nor kept in memory: the group loaded again
            // is the one there was.
            assert_eq!(user.store.records(), before);
            assert_eq!(group.epoch().unwrap(), epoch);
            assert_eq!(member_uuids(group), expected);

            let reloaded = user
                .client
                .load_group(group.mls_group_id().unwrap())
                .unwrap();

            assert_eq!(reloaded.epoch().unwrap(), epoch);
            assert_eq!(member_uuids(&reloaded), expected);

            // Stored with Carol alone, the same Commit is applied.
            assert!(matches!(
                reloaded
                    .process_incoming_message(
                        removal.clone(),
                        commit_policy(&alice.uuid, &[&carol.uuid])
                    )
                    .unwrap(),
                ProcessedMessage::Commit { committer_user_uuid, .. }
                    if committer_user_uuid == Some(bob.uuid.clone())
            ));

            assert_eq!(reloaded.epoch().unwrap(), epoch + 1);
            assert!(!member_uuids(&reloaded).contains(&carol.uuid));
        }
    }

    #[test]
    fn test_a_member_but_the_creator_may_remove_nobody_but_departed_members() {
        // Carol has left, and Bob, a member, tries what only Alice, the
        // creator, may do.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let dave = TestUser::new();

        let groups = establish_group(&alice, &[&bob, &carol, &dave]);
        let (alice_group, bob_group, dave_group) = (&groups[0], &groups[1], &groups[3]);

        let policy = commit_policy(&alice.uuid, &[&carol.uuid]);
        let epoch = alice_group.epoch().unwrap();

        let attempts = [
            (
                "a removal of a member still in the group",
                vec![dave.uuid.clone()],
            ),
            (
                "a removal of a departed member and one still in the group",
                vec![carol.uuid.clone(), dave.uuid.clone()],
            ),
            ("a removal of the creator", vec![alice.uuid.clone()]),
            ("an update removing nobody", Vec::new()),
        ]
        .map(|(attempt, removed)| {
            let commit = if removed.is_empty() {
                bob_group.update().unwrap()
            } else {
                bob_group.remove_members(removed).unwrap()
            };

            bob_group.clear_pending_commit().unwrap();

            (attempt, commit)
        });

        for (user, group) in [(&alice, alice_group), (&dave, dave_group)] {
            let before = user.store.records();

            for (attempt, commit) in &attempts {
                assert!(
                    matches!(
                        group
                            .process_incoming_message(commit.clone(), policy.clone())
                            .unwrap_err(),
                        MlsError::UnauthorizedChange
                    ),
                    "{attempt} must be refused"
                );
            }

            // Nothing was stored, nor kept in memory.
            assert_eq!(user.store.records(), before);
            assert_eq!(group.epoch().unwrap(), epoch);
            assert_eq!(group.members().unwrap().len(), 4);
        }
    }

    #[test]
    fn test_a_removal_of_departed_members_carrying_anything_more_is_refused_by_every_member() {
        // Mallory, a member playing a plain mls-rs client, removes a stranger
        // who has left, slipping something more into each Commit. Alice, the
        // creator, has her pinned, Bob nobody.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let mut group = establish_group_with_mallory(&alice, &bob, 1, false);

        let departed = group.stranger_uuids[0].clone();
        let policy = commit_policy(&alice.uuid, &[&departed]);
        let epoch = group.alice_group.epoch().unwrap();

        let departed_index = group
            .mallory_group
            .member_with_identity(departed.as_bytes())
            .unwrap()
            .index;

        let mallory = &mut group.mallory_group;

        let addition = mallory
            .commit_builder()
            .remove_member(departed_index)
            .unwrap()
            .add_member(MlsMessage::from_bytes(&stranger_invitations(1)[0].key_package).unwrap())
            .unwrap()
            .build()
            .unwrap();
        mallory.clear_pending_commit();

        let extensions = mallory.context().extensions.clone();
        let context_change = mallory
            .commit_builder()
            .remove_member(departed_index)
            .unwrap()
            .set_group_context_ext(extensions)
            .unwrap()
            .build()
            .unwrap();
        mallory.clear_pending_commit();

        for (user, member_group) in [(&alice, &group.alice_group), (&bob, &group.bob_group)] {
            let before = user.store.records();

            for (attempt, commit) in [
                ("an addition", &addition),
                ("a change to the group context", &context_change),
            ] {
                assert!(
                    matches!(
                        member_group
                            .process_incoming_message(
                                commit.commit_message.to_bytes().unwrap(),
                                policy.clone()
                            )
                            .unwrap_err(),
                        MlsError::UnauthorizedChange
                    ),
                    "a removal carrying {attempt} must be refused"
                );
            }

            assert_eq!(user.store.records(), before);
            assert_eq!(member_group.epoch().unwrap(), epoch);
        }

        // A removal whose update path gives Mallory's leaf a signature key of
        // her own making, under her name or under that of the member it
        // removes, is refused with the same error by both, whatever each has
        // pinned: Alice, who seated them, has keys pinned for Mallory and the
        // departed member, and Bob none for either. Refused by the pins, it
        // would be an `IdentityKeyMismatch` on Alice's device, which waits on
        // it, and a `ProtocolFailed` on Bob's, which refuses it for good, and
        // Alice would never replace it.
        let crypto_provider = crate::cryptography::mls::config::crypto_provider();
        let cipher_suite_provider = crypto_provider.cipher_suite_provider(CIPHER_SUITE).unwrap();

        let leaf_changes = [
            ("her key", group.mallory_uuid.clone()),
            ("her leaf to the departed member", departed.clone()),
        ]
        .map(|(change, user_uuid)| {
            let (secret, public) = cipher_suite_provider.signature_key_generate().unwrap();
            let credential = BasicCredential::new(user_uuid.into_bytes()).into_credential();

            let mallory = &mut group.mallory_group;

            let commit = mallory
                .commit_builder()
                .remove_member(departed_index)
                .unwrap()
                .set_new_signing_identity(secret, SigningIdentity::new(credential, public))
                .build()
                .unwrap()
                .commit_message
                .to_bytes()
                .unwrap();
            mallory.clear_pending_commit();

            (change, commit)
        });

        for (user, member_group) in [(&alice, &group.alice_group), (&bob, &group.bob_group)] {
            let before = user.store.records();

            for (change, commit) in &leaf_changes {
                assert!(
                    matches!(
                        member_group
                            .process_incoming_message(commit.clone(), policy.clone())
                            .unwrap_err(),
                        MlsError::UnauthorizedChange
                    ),
                    "a removal changing {change} must be refused alike"
                );
            }

            assert_eq!(user.store.records(), before);
            assert_eq!(member_group.epoch().unwrap(), epoch);
        }

        // The removal and nothing more, its update path holding the key
        // Mallory's leaf had, is applied by both.
        let removal = group
            .mallory_group
            .commit_builder()
            .remove_member(departed_index)
            .unwrap()
            .build()
            .unwrap()
            .commit_message
            .to_bytes()
            .unwrap();

        for member_group in [&group.alice_group, &group.bob_group] {
            assert!(matches!(
                member_group
                    .process_incoming_message(removal.clone(), policy.clone())
                    .unwrap(),
                ProcessedMessage::Commit { committer_user_uuid, .. }
                    if committer_user_uuid == Some(group.mallory_uuid.clone())
            ));
            assert!(!member_uuids(member_group).contains(&departed));
        }
    }

    #[test]
    fn test_creating_a_group_leaves_it_at_epoch_1() {
        // The DuckCount API starts every group at generation 1, the epoch its
        // creation leaves it in, whose content key its information is sealed
        // under.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        for group in establish_group(&alice, &[&bob, &carol]) {
            assert_eq!(group.epoch().unwrap(), 1);
        }
    }

    #[test]
    fn test_the_content_key_is_what_the_mls_exporter_derives_under_its_label_and_the_group_uuid() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let group = establish_group_with_mallory(&alice, &bob, 0, true);

        let exported = group
            .mallory_group
            .export_secret(
                b"DuckCount 1.0 Group content key",
                group.group_uuid.as_bytes(),
                32,
            )
            .unwrap();

        for member_group in [&group.alice_group, &group.bob_group] {
            assert_eq!(
                member_group.content_key(group.group_uuid.clone()).unwrap(),
                exported.as_bytes()
            );
        }
    }

    #[test]
    fn test_content_keys_agree_across_members_change_with_every_epoch_and_escape_a_removed_member()
    {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let dave = TestUser::new();

        let group_uuid = new_group_uuid();
        let groups = establish_group_as(&group_uuid, &alice, &[&bob, &carol]);
        let (alice_group, bob_group, carol_group) = (&groups[0], &groups[1], &groups[2]);

        let content_key = |group: &MlsGroup| group.content_key(group_uuid.clone()).unwrap();

        // Every member derives the one key of the epoch the group was created
        // in, under its UUID and no other.
        let created = content_key(alice_group);

        assert_eq!(created.len(), 32);
        assert_eq!(content_key(bob_group), created);
        assert_eq!(content_key(carol_group), created);
        assert_ne!(alice_group.content_key(new_group_uuid()).unwrap(), created);

        // Alice removes Carol: a new key, which Carol, left in the epoch the
        // removal ended, never derives.
        let removal = alice_group
            .remove_members(vec![carol.uuid.clone()])
            .unwrap();

        for group in [bob_group, carol_group] {
            group
                .process_incoming_message(removal.clone(), created_by(&alice))
                .unwrap();
        }

        accept(alice_group);

        let removed = content_key(alice_group);

        assert_ne!(removed, created);
        assert_eq!(content_key(bob_group), removed);
        assert_eq!(content_key(carol_group), created);

        // Alice adds Dave: a new key again, which Dave derives from his
        // Welcome.
        let addition = alice_group
            .add_members(vec![dave.invitation()], None)
            .unwrap();

        bob_group
            .process_incoming_message(addition.commit, created_by(&alice))
            .unwrap();

        accept(alice_group);

        let dave_group_id = dave
            .client
            .join_group(
                addition.welcome,
                Some(group_uuid.clone()),
                uuids(&[&alice, &bob]),
                true,
            )
            .unwrap();
        let dave_group = dave.client.load_group(dave_group_id).unwrap();

        let added = content_key(alice_group);

        assert_ne!(added, created);
        assert_ne!(added, removed);
        assert_eq!(content_key(bob_group), added);
        assert_eq!(content_key(&dave_group), added);
    }

    #[test]
    fn test_the_content_key_after_a_pending_commit_is_its_epochs_and_nothing_is_stored() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let dave = TestUser::new();

        let group_uuid = new_group_uuid();
        let groups = establish_group_as(&group_uuid, &alice, &[&bob, &carol]);
        let (alice_group, bob_group) = (&groups[0], &groups[1]);
        let group_id = alice_group.mls_group_id().unwrap();

        // With nothing pending, there is no epoch to derive it for.
        assert!(matches!(
            alice_group
                .content_key_after_pending_commit(group_uuid.clone())
                .unwrap_err(),
            MlsError::ProtocolFailed(_)
        ));

        let current = alice_group.content_key(group_uuid.clone()).unwrap();
        let epoch = alice_group.epoch().unwrap();

        let removal = alice_group
            .remove_members(vec![carol.uuid.clone()])
            .unwrap();

        let before = alice.store.records();

        let next = alice_group
            .content_key_after_pending_commit(group_uuid.clone())
            .unwrap();

        // Derived from a copy: nothing was stored, and the group is still in
        // its epoch with the Commit pending, as it is once loaded again.
        assert_ne!(next, current);
        assert_eq!(alice.store.records(), before);
        assert_eq!(alice_group.epoch().unwrap(), epoch);
        assert_eq!(
            alice_group.content_key(group_uuid.clone()).unwrap(),
            current
        );
        assert!(alice_group.has_pending_commit().unwrap());

        let reloaded = alice.reopen().load_group(group_id).unwrap();

        assert_eq!(reloaded.epoch().unwrap(), epoch);
        assert!(reloaded.has_pending_commit().unwrap());

        // The key the Commit's epoch has once it is applied, for every member.
        bob_group
            .process_incoming_message(removal, created_by(&alice))
            .unwrap();

        accept(alice_group);

        assert_eq!(alice_group.content_key(group_uuid.clone()).unwrap(), next);
        assert_eq!(bob_group.content_key(group_uuid.clone()).unwrap(), next);

        // So for an addition, whose Welcome opens that epoch.
        let addition = alice_group
            .add_members(vec![dave.invitation()], None)
            .unwrap();

        let next = alice_group
            .content_key_after_pending_commit(group_uuid.clone())
            .unwrap();

        accept(alice_group);

        let dave_group_id = dave
            .client
            .join_group(
                addition.welcome,
                Some(group_uuid.clone()),
                uuids(&[&alice, &bob]),
                true,
            )
            .unwrap();
        let dave_group = dave.client.load_group(dave_group_id).unwrap();

        assert_eq!(alice_group.content_key(group_uuid.clone()).unwrap(), next);
        assert_eq!(dave_group.content_key(group_uuid).unwrap(), next);
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

        alice_group
            .process_incoming_message(output.commit, None)
            .unwrap();
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

    /// Creates a group the DuckCount API holds, owned by `creator`, holding
    /// `joiner` and `others`, and joins `joiner` to it as a host joins a group
    /// it was added to: pinning nobody.
    ///
    /// Returns the creator's group and the joiner's.
    fn join_group_pinning_nobody(
        creator: &TestUser,
        joiner: &TestUser,
        others: &[&TestUser],
    ) -> (Arc<MlsGroup>, Arc<MlsGroup>) {
        let group_uuid = new_group_uuid();

        let creation = creator
            .client
            .create_group(
                Some(group_uuid.clone()),
                std::iter::once(joiner)
                    .chain(others.iter().copied())
                    .map(|user| user.invitation())
                    .collect(),
                None,
            )
            .unwrap();

        let members = std::iter::once(creator)
            .chain(others.iter().copied())
            .collect::<Vec<_>>();

        let group_id = joiner
            .client
            .join_group(creation.welcome, Some(group_uuid), uuids(&members), false)
            .unwrap();

        (
            creator.client.load_group(creation.mls_group_id).unwrap(),
            joiner.client.load_group(group_id).unwrap(),
        )
    }

    /// A key package of a client of somebody else's making claiming to be
    /// `user`, as a server substituting one would serve for them.
    fn substituted_invitation(user: &TestUser) -> InviteeKeyPackage {
        let impostor =
            MlsClient::new(user.uuid.clone(), SECRET.to_vec(), TestStore::new()).unwrap();

        assert_ne!(
            impostor.signature_public_key(),
            user.client.signature_public_key()
        );

        InviteeKeyPackage {
            user_uuid: user.uuid.clone(),
            key_package: impostor
                .generate_key_packages(1)
                .unwrap()
                .one_time_key_packages
                .remove(0),
        }
    }

    #[test]
    fn test_pinning_a_member_pins_the_key_they_hold_in_the_group_and_nobody_else() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let dave = TestUser::new();

        let (_, bob_group) = join_group_pinning_nobody(&alice, &bob, &[&carol, &dave]);

        bob_group.pin_member(carol.uuid.clone()).unwrap();

        assert_eq!(
            bob.client.pinned_signature_key(carol.uuid.clone()).unwrap(),
            Some(carol.client.signature_public_key())
        );

        for member in [&alice, &dave] {
            assert!(
                bob.client
                    .pinned_signature_key(member.uuid.clone())
                    .unwrap()
                    .is_none(),
                "only the member named is pinned"
            );
        }

        // Once pinned, the same key still passes.
        bob_group.pin_member(carol.uuid.clone()).unwrap();
    }

    #[test]
    fn test_a_member_the_creator_added_since_the_join_is_pinned_from_the_group() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let dave = TestUser::new();

        let (alice_group, bob_group) = join_group_pinning_nobody(&alice, &bob, &[&carol]);

        let addition = alice_group
            .add_members(vec![dave.invitation()], None)
            .unwrap();

        bob_group
            .process_incoming_message(addition.commit, created_by(&alice))
            .unwrap();
        accept(&alice_group);

        bob_group.pin_member(dave.uuid.clone()).unwrap();

        assert_eq!(
            bob.client.pinned_signature_key(dave.uuid.clone()).unwrap(),
            Some(dave.client.signature_public_key())
        );
    }

    #[test]
    fn test_a_contact_request_to_a_member_pinned_from_the_group_is_made_from_their_key_package() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let (_, bob_group) = join_group_pinning_nobody(&alice, &bob, &[&carol]);

        bob_group.pin_member(carol.uuid.clone()).unwrap();

        let request = bob
            .client
            .create_group(None, vec![carol.invitation()], None)
            .unwrap();

        // And Carol opens it as any other request.
        carol
            .client
            .join_group(request.welcome, None, uuids(&[&bob]), false)
            .unwrap();

        assert_eq!(
            bob.client.pinned_signature_key(carol.uuid.clone()).unwrap(),
            Some(carol.client.signature_public_key())
        );
    }

    #[test]
    fn test_a_contact_request_to_a_member_pinned_from_the_group_refuses_anybody_else_s_key_package()
    {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let (_, bob_group) = join_group_pinning_nobody(&alice, &bob, &[&carol]);

        bob_group.pin_member(carol.uuid.clone()).unwrap();

        let error = bob
            .client
            .create_group(None, vec![substituted_invitation(&carol)], None)
            .expect_err("a key package not of the key Carol holds in the group must be refused");

        assert!(matches!(error, MlsError::IdentityKeyMismatch(uuid) if uuid == carol.uuid));

        assert_eq!(
            bob.client.pinned_signature_key(carol.uuid.clone()).unwrap(),
            Some(carol.client.signature_public_key()),
            "the key from the group stays pinned"
        );
    }

    #[test]
    fn test_pinning_somebody_outside_the_group_as_a_member_is_refused_and_pins_nobody() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let stranger = TestUser::new();

        let (_, bob_group) = join_group_pinning_nobody(&alice, &bob, &[&carol]);

        assert!(matches!(
            bob_group.pin_member(stranger.uuid.clone()).unwrap_err(),
            MlsError::UnexpectedMembers
        ));

        for user in [&stranger, &alice, &carol] {
            assert!(
                bob.client
                    .pinned_signature_key(user.uuid.clone())
                    .unwrap()
                    .is_none(),
                "nobody is pinned for a member the group does not hold"
            );
        }
    }

    #[test]
    fn test_pinning_this_user_as_a_member_is_refused_and_pins_nobody() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let (_, bob_group) = join_group_pinning_nobody(&alice, &bob, &[&carol]);

        assert!(matches!(
            bob_group.pin_member(bob.uuid.clone()).unwrap_err(),
            MlsError::UnexpectedMembers
        ));

        for user in [&bob, &alice, &carol] {
            assert!(
                bob.client
                    .pinned_signature_key(user.uuid.clone())
                    .unwrap()
                    .is_none(),
                "this user is not one of the members to pin"
            );
        }
    }

    #[test]
    fn test_pinning_a_member_refuses_a_key_pinned_differently_since_the_join() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let impostor = TestUser::new();

        let (_, bob_group) = join_group_pinning_nobody(&alice, &bob, &[&carol]);

        bob.client
            .pin_identity(carol.uuid.clone(), impostor.client.signature_public_key())
            .unwrap();

        assert!(matches!(
            bob_group.pin_member(carol.uuid.clone()).unwrap_err(),
            MlsError::IdentityKeyMismatch(uuid) if uuid == carol.uuid
        ));

        // The pin that was there stays as it was.
        assert_eq!(
            bob.client.pinned_signature_key(carol.uuid.clone()).unwrap(),
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
            .process_incoming_message(output.commit, None)
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
            .process_incoming_message(output.commit, None)
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
            reloaded.process_incoming_message(commit, None).unwrap(),
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
        bob_group.process_incoming_message(proposal, None).unwrap();

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

    /// The last of `count` application messages `sender` encrypts, which
    /// overtakes all the others: read, it leaves its reader a key for each.
    fn last_of_messages(sender: &MlsGroup, count: usize) -> Vec<u8> {
        let mut last = Vec::new();

        for _ in 0..count {
            last = sender
                .encrypt_application_message(b"skipped".to_vec())
                .unwrap();
        }

        last
    }

    #[test]
    fn test_a_group_holding_a_pending_commit_may_store_no_more_than_at_rest() {
        // Victor has an update pending as Mallory's skipping messages come in:
        // what he stores meanwhile, the update included, is held to what the
        // group may store at rest, the room kept for a Commit being his
        // update's.
        let mallory = TestUser::new();
        let victor = TestUser::new();

        let (mallory_group, victor_group) = open_request(&mallory, &victor);
        let group_id = victor_group.mls_group_id().unwrap();

        victor_group.update().unwrap();

        let mut refusal = None;

        // A hundred at a time, some 3 KB of keys each, so that what he stores
        // comes as close as it may to what he may store.
        for _ in 0..40 {
            let last = last_of_messages(&mallory_group, 100);
            let before = stored_state_len(&victor, &group_id);

            if let Err(error) = victor_group.read_application_message(last) {
                refusal = Some((error, before));
                break;
            }
        }

        let (error, before) = refusal.expect("the group must stop growing");

        assert!(matches!(error, MlsError::GroupStateTooLarge));

        // Everything stored up to the refusal, its update pending, was within
        // what a group of two may store at rest.
        assert!(before <= max_group_state_len_at_rest_in_tests(2));
        assert!(victor_group.has_pending_commit().unwrap());
    }

    #[test]
    fn test_a_message_refused_beside_a_pending_addition_is_read_once_it_is_applied_or_discarded() {
        // Alice and Bob add eight: the addition pending, the group of two they
        // are has no room left to read or send anything beside it.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);
        let (alice_group, bob_group) = (&groups[0], &groups[1]);
        let policy = created_by(&alice);

        for discarded in [true, false] {
            let message = bob_group
                .encrypt_application_message(b"hello".to_vec())
                .unwrap();

            alice_group
                .add_members(stranger_invitations(8), None)
                .unwrap();

            let before = alice.store.records();

            assert!(matches!(
                alice_group
                    .process_incoming_message(message.clone(), policy.clone())
                    .unwrap_err(),
                MlsError::GroupStateTooLarge
            ));
            assert!(matches!(
                alice_group
                    .encrypt_application_message(b"hello".to_vec())
                    .unwrap_err(),
                MlsError::GroupStateTooLarge
            ));

            assert_eq!(alice.store.records(), before);

            // Read once the addition is discarded, or applied, in the epoch
            // it ends.
            if discarded {
                alice_group.clear_pending_commit().unwrap();
            } else {
                accept(alice_group);
            }

            assert!(matches!(
                alice_group
                    .process_incoming_message(message, policy.clone())
                    .unwrap(),
                ProcessedMessage::ApplicationMessage { .. }
            ));

            alice_group
                .encrypt_application_message(b"hello".to_vec())
                .unwrap();
        }
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
    fn test_a_removal_of_departed_members_labelled_as_an_application_message_is_not_applied() {
        // `POST /groups/{uuid}/messages` keeps Commits out by the label it
        // reads, so Bob, a member, relabels his removal of Carol, who has
        // left, to have it stored there. Members read it as what it is
        // labelled, and it fails to open.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();
        let dave = TestUser::new();

        let groups = establish_group(&alice, &[&bob, &carol, &dave]);
        let (alice_group, bob_group, dave_group) = (&groups[0], &groups[1], &groups[3]);

        let policy = commit_policy(&alice.uuid, &[&carol.uuid]);
        let epoch = alice_group.epoch().unwrap();

        let removal = bob_group.remove_members(vec![carol.uuid.clone()]).unwrap();

        let relabelled = relabelled(
            removal.clone(),
            &alice_group.mls_group_id().unwrap(),
            ContentType::Commit,
            ContentType::Application,
        );

        for (user, group) in [(&alice, alice_group), (&dave, dave_group)] {
            let before = user.store.records();

            assert!(matches!(
                group
                    .process_incoming_message(relabelled.clone(), policy.clone())
                    .unwrap_err(),
                MlsError::ProtocolFailed(_)
            ));

            assert_eq!(user.store.records(), before);
            assert_eq!(group.epoch().unwrap(), epoch);
            assert_eq!(group.members().unwrap().len(), 4);

            // Refused for its label alone: as Bob sent it, it is applied.
            assert!(matches!(
                group
                    .process_incoming_message(removal.clone(), policy.clone())
                    .unwrap(),
                ProcessedMessage::Commit { .. }
            ));
        }
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
            .process_incoming_message(proposal.to_bytes().unwrap(), None)
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

        groups[0].process_incoming_message(message, None).unwrap();
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
        plain_client_storing_in(user_uuid, InMemoryGroupStateStorage::new())
    }

    /// [`plain_client`], storing its groups in `group_states`.
    fn plain_client_storing_in(
        user_uuid: String,
        group_states: impl GroupStateStorage + Clone + 'static,
    ) -> Client<impl MlsConfig> {
        let crypto_provider = crate::cryptography::mls::config::crypto_provider();
        let cipher_suite_provider = crypto_provider.cipher_suite_provider(CIPHER_SUITE).unwrap();
        let (secret, public) = cipher_suite_provider.signature_key_generate().unwrap();

        Client::builder()
            .group_state_storage(group_states)
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
        // when stored: a test lets a group of a hundred store some 260 KB,
        // short of the 300 KB they take.
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
        // outright. Up to exactly the cap, it is built and stored.
        groups[0]
            .add_members(stranger_invitations(MAX_GROUP_MEMBERS - 2), None)
            .unwrap();

        assert!(groups[0].has_pending_commit().unwrap());
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
                .process_incoming_message(proposal.to_bytes().unwrap(), None)
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
        // as a test lets a group of a hundred store some 260 KB.
        let (welcome, group_uuid, others) = welcome_to_a_group_of(MAX_GROUP_MEMBERS, &bob);

        assert!(matches!(
            bob.client
                .join_group(welcome, Some(group_uuid), others, true)
                .unwrap_err(),
            MlsError::GroupStateTooLarge
        ));
    }

    #[test]
    fn test_a_group_may_store_more_for_each_member_past_two_up_to_the_cap() {
        // A group of two, as a direct channel or a contact request is, may
        // store what it always could, and so may one left with a single member.
        assert_eq!(max_group_state_len(2), 512 * 1024);
        assert_eq!(max_group_state_len(1), 512 * 1024);

        assert_eq!(max_group_state_len(3), (512 + 12) * 1024);
        assert_eq!(max_group_state_len(MAX_GROUP_MEMBERS), 1_728_512);

        // A group somebody committed past the cap may store no more.
        assert_eq!(max_group_state_len(MAX_GROUP_MEMBERS + 1), 1_728_512);

        // At rest, less the room kept for the Commit it builds next.
        assert_eq!(max_group_state_len_at_rest(2), (512 - 27) * 1024);
        assert_eq!(max_group_state_len_at_rest(1), (512 - 27) * 1024);

        assert_eq!(max_group_state_len_at_rest(3), (512 + 12 - 36) * 1024);
        assert_eq!(max_group_state_len_at_rest(MAX_GROUP_MEMBERS), 797_696);
        assert_eq!(max_group_state_len_at_rest(MAX_GROUP_MEMBERS + 1), 797_696);
    }

    /// A [`GroupStateStorage`] keeping nothing, but how large the largest
    /// record it was handed is: what a group stores, measured past what a test
    /// lets it store.
    #[derive(Clone, Default)]
    struct LargestRecord(Arc<Mutex<usize>>);

    impl LargestRecord {
        /// How large the largest record handed over since the last call is.
        fn take(&self) -> usize {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    impl GroupStateStorage for LargestRecord {
        type Error = Infallible;

        fn state(&self, _group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Infallible> {
            Ok(None)
        }

        fn epoch(
            &self,
            _group_id: &[u8],
            _epoch_id: u64,
        ) -> Result<Option<Zeroizing<Vec<u8>>>, Infallible> {
            Ok(None)
        }

        fn write(
            &mut self,
            state: GroupState,
            epoch_inserts: Vec<EpochRecord>,
            epoch_updates: Vec<EpochRecord>,
        ) -> Result<(), Infallible> {
            let largest = epoch_inserts
                .iter()
                .chain(&epoch_updates)
                .map(|epoch| epoch.data.len())
                .fold(state.data.len(), usize::max);

            let mut recorded = self.0.lock().unwrap();
            *recorded = (*recorded).max(largest);

            Ok(())
        }

        fn max_epoch_id(&self, _group_id: &[u8]) -> Result<Option<u64>, Infallible> {
            Ok(None)
        }
    }

    #[test]
    fn test_a_group_of_a_hundred_may_hold_a_pending_addition_or_removal() {
        // Measured on a plain mls-rs creator running the rules of this library,
        // as a test lets a group of a hundred store less than it takes: how
        // much a pending Commit adds to the group at rest, which a group stored
        // at rest as full as it may be has to have room for.
        let largest = LargestRecord::default();
        let creator = plain_client_storing_in(Uuid::new_v4().to_string(), largest.clone());

        let mut group = creator
            .create_group_with_id(
                server_group_id(&new_group_uuid()),
                ExtensionList::default(),
                ExtensionList::default(),
                None,
            )
            .unwrap();

        // Ninety-nine members, the creator included.
        let mut commit_builder = group.commit_builder();

        for invitation in stranger_invitations(MAX_GROUP_MEMBERS - 2) {
            commit_builder = commit_builder
                .add_member(MlsMessage::from_bytes(&invitation.key_package).unwrap())
                .unwrap();
        }

        commit_builder.build().unwrap();
        group.apply_pending_commit().unwrap();
        group.write_to_storage().unwrap();

        let at_rest_of_ninety_nine = largest.take();

        // A hundredth pending.
        let hundredth = stranger_invitations(1).remove(0);

        group
            .commit_builder()
            .add_member(MlsMessage::from_bytes(&hundredth.key_package).unwrap())
            .unwrap()
            .build()
            .unwrap();
        group.write_to_storage().unwrap();

        let pending_addition = largest.take();

        group.apply_pending_commit().unwrap();
        group.write_to_storage().unwrap();

        let at_rest_of_a_hundred = largest.take();

        assert!(at_rest_of_a_hundred <= max_group_state_len_at_rest(MAX_GROUP_MEMBERS));

        // Then their removal.
        let hundredth_index = group
            .member_with_identity(hundredth.user_uuid.as_bytes())
            .unwrap()
            .index;

        group
            .commit_builder()
            .remove_member(hundredth_index)
            .unwrap()
            .build()
            .unwrap();
        group.write_to_storage().unwrap();

        let pending_removal = largest.take();

        for (at_rest, pending, at_rest_before) in [
            (
                at_rest_of_ninety_nine,
                pending_addition,
                MAX_GROUP_MEMBERS - 1,
            ),
            (at_rest_of_a_hundred, pending_removal, MAX_GROUP_MEMBERS),
        ] {
            // Past what a group of two may store.
            assert!(pending > max_group_state_len(2));

            // Within what a hundred may, from a group as full at rest as it
            // may be.
            assert!(
                max_group_state_len_at_rest(at_rest_before) + (pending - at_rest)
                    <= max_group_state_len(MAX_GROUP_MEMBERS)
            );
        }
    }

    /// Creates a group of `alice`, `bob`, and `stranger_count` members
    /// nobody has met, who never join, and joins Bob to it.
    ///
    /// Returns Alice's group and Bob's.
    fn establish_group_with_strangers(
        alice: &TestUser,
        bob: &TestUser,
        stranger_count: usize,
    ) -> (Arc<MlsGroup>, Arc<MlsGroup>) {
        let group_uuid = new_group_uuid();
        let strangers = stranger_invitations(stranger_count);

        let others = std::iter::once(alice.uuid.clone())
            .chain(strangers.iter().map(|stranger| stranger.user_uuid.clone()))
            .collect();

        let creation = alice
            .client
            .create_group(
                Some(group_uuid.clone()),
                strangers.into_iter().chain([bob.invitation()]).collect(),
                None,
            )
            .unwrap();

        let joined = bob
            .client
            .join_group(creation.welcome, Some(group_uuid), others, true)
            .unwrap();

        (
            alice.client.load_group(creation.mls_group_id).unwrap(),
            bob.client.load_group(joined).unwrap(),
        )
    }

    #[test]
    fn test_creating_and_joining_a_group_may_store_what_its_members_may() {
        // Twenty-two members store past what a group of two may.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let (alice_group, bob_group) = establish_group_with_strangers(&alice, &bob, 20);

        for (user, group) in [(&alice, &alice_group), (&bob, &bob_group)] {
            let stored = stored_state_len(user, &group.mls_group_id().unwrap());

            assert!(stored > max_group_state_len_at_rest_in_tests(2));
            assert!(stored <= max_group_state_len_at_rest_in_tests(22));
        }
    }

    #[test]
    fn test_an_addition_is_stored_as_the_group_it_makes_pending_and_applied() {
        // Alice and Bob add twenty, which a group of two could not store,
        // pending or at rest.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);
        let group_id = groups[0].mls_group_id().unwrap();

        let addition = groups[0]
            .add_members(stranger_invitations(20), None)
            .unwrap();

        let pending = stored_state_len(&alice, &group_id);

        assert!(pending > max_group_state_len_in_tests(2));
        assert!(pending <= max_group_state_len_in_tests(22));

        // Applied by Alice, and by Bob as he reads it.
        accept(&groups[0]);

        groups[1]
            .process_incoming_message(addition.commit, created_by(&alice))
            .unwrap();

        for user in [&alice, &bob] {
            let stored = stored_state_len(user, &group_id);

            assert!(stored > max_group_state_len_at_rest_in_tests(2));
            assert!(stored <= max_group_state_len_at_rest_in_tests(22));
        }
    }

    #[test]
    fn test_a_pending_removal_is_stored_as_the_group_it_removes_members_from() {
        // Alice removes twenty of twenty-two, which the group of two it leaves
        // could not store pending.
        let alice = TestUser::new();
        let strangers = stranger_invitations(21);
        let removed = strangers[..20]
            .iter()
            .map(|stranger| stranger.user_uuid.clone())
            .collect();

        let creation = alice
            .client
            .create_group(Some(new_group_uuid()), strangers, None)
            .unwrap();

        alice
            .client
            .load_group(creation.mls_group_id.clone())
            .unwrap()
            .remove_members(removed)
            .unwrap();

        let stored = stored_state_len(&alice, &creation.mls_group_id);

        assert!(stored > max_group_state_len_in_tests(2));
        assert!(stored <= max_group_state_len_in_tests(22));
    }

    #[test]
    fn test_a_message_read_may_grow_a_group_to_what_its_members_may_store() {
        // Bob, in a group of ten, reads the last of a thousand messages from
        // Alice, keeping a key for each of the others, which it overtook.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let (alice_group, bob_group) = establish_group_with_strangers(&alice, &bob, 8);

        bob_group
            .process_incoming_message(last_of_messages(&alice_group, 1000), created_by(&alice))
            .unwrap();

        let stored = stored_state_len(&bob, &bob_group.mls_group_id().unwrap());

        assert!(stored > max_group_state_len_at_rest_in_tests(2));
        assert!(stored <= max_group_state_len_at_rest_in_tests(10));
    }

    /// A group Alice created, see [`establish_group_with_mallory`].
    struct WithMallory<C: MlsConfig> {
        group_uuid: String,
        alice_group: Arc<MlsGroup>,
        bob_group: Arc<MlsGroup>,
        mallory_uuid: String,
        mallory_group: Group<C>,
        stranger_uuids: Vec<String>,
    }

    /// Creates a group of `alice`, `bob`, Mallory, a member playing a plain
    /// mls-rs client, and `stranger_count` members nobody has met, who never
    /// join, and joins Bob and Mallory to it, Bob pinning everybody if
    /// `bob_pins_members` says so, and nobody otherwise.
    fn establish_group_with_mallory(
        alice: &TestUser,
        bob: &TestUser,
        stranger_count: usize,
        bob_pins_members: bool,
    ) -> WithMallory<impl MlsConfig> {
        let group_uuid = new_group_uuid();

        let mallory_uuid = Uuid::new_v4().to_string();
        let mallory_client = plain_client(mallory_uuid.clone());

        let mallory_invitation = InviteeKeyPackage {
            user_uuid: mallory_uuid.clone(),
            key_package: mallory_client
                .generate_key_package_message(
                    ExtensionList::default(),
                    ExtensionList::default(),
                    None,
                )
                .unwrap()
                .to_bytes()
                .unwrap(),
        };

        let strangers = stranger_invitations(stranger_count);
        let stranger_uuids = strangers
            .iter()
            .map(|stranger| stranger.user_uuid.clone())
            .collect::<Vec<_>>();

        let creation = alice
            .client
            .create_group(
                Some(group_uuid.clone()),
                strangers
                    .into_iter()
                    .chain([bob.invitation(), mallory_invitation])
                    .collect(),
                None,
            )
            .unwrap();

        let others = std::iter::once(alice.uuid.clone())
            .chain(stranger_uuids.iter().cloned())
            .chain([mallory_uuid.clone()])
            .collect();

        let joined = bob
            .client
            .join_group(
                creation.welcome.clone(),
                Some(group_uuid.clone()),
                others,
                bob_pins_members,
            )
            .unwrap();

        let welcome = MlsMessage::from_bytes(&creation.welcome).unwrap();
        let (mallory_group, _) = mallory_client.join_group(None, &welcome, None).unwrap();

        WithMallory {
            group_uuid,
            alice_group: alice.client.load_group(creation.mls_group_id).unwrap(),
            bob_group: bob.client.load_group(joined).unwrap(),
            mallory_uuid,
            mallory_group,
            stranger_uuids,
        }
    }

    /// Has `mallory` send message after message, each the last of as many as
    /// `reader`, `user`'s group, has room left to keep a key for, and `reader`
    /// read each, until it refuses one: the group is then as full as `limit`,
    /// what it may store, lets it be.
    fn flood(
        mallory: &mut Group<impl MlsConfig>,
        reader: &MlsGroup,
        user: &TestUser,
        creator_uuid: &str,
        limit: usize,
    ) {
        let group_id = reader.mls_group_id().unwrap();

        loop {
            // A key skipped takes some 34 bytes, and a message read skipping
            // none none at all.
            let room = limit.saturating_sub(stored_state_len(user, &group_id));
            let count = (room / 36).clamp(2, 1000);

            let mut last = None;

            for _ in 0..count {
                last = Some(
                    mallory
                        .encrypt_application_message(b"skipped", Vec::new())
                        .unwrap(),
                );
            }

            if let Err(error) = reader.process_incoming_message(
                last.unwrap().to_bytes().unwrap(),
                commit_policy(creator_uuid, &[]),
            ) {
                assert!(matches!(error, MlsError::GroupStateTooLarge));

                return;
            }
        }
    }

    #[test]
    fn test_a_creator_flooded_with_skipped_keys_can_still_add_members_and_remove_the_flooder() {
        // Mallory, a member, has Alice, the creator, keep a key for every
        // message she skips, until Alice may take in no more.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let mut group = establish_group_with_mallory(&alice, &bob, 5, true);
        let group_id = group.alice_group.mls_group_id().unwrap();
        let policy = created_by(&alice);

        flood(
            &mut group.mallory_group,
            &group.alice_group,
            &alice,
            &alice.uuid,
            max_group_state_len_at_rest_in_tests(8),
        );

        assert!(
            stored_state_len(&alice, &group_id) > max_group_state_len_at_rest_in_tests(8) - 1024
        );

        // She still adds somebody, and removes Mallory.
        group
            .alice_group
            .add_members(stranger_invitations(1), None)
            .unwrap();
        group.alice_group.clear_pending_commit().unwrap();

        let removal = group
            .alice_group
            .remove_members(vec![group.mallory_uuid.clone()])
            .unwrap();
        accept(&group.alice_group);

        group
            .bob_group
            .process_incoming_message(removal, policy.clone())
            .unwrap();

        // The keys Mallory had her keep stay with the epoch they were taken
        // in, and Alice sends again.
        let message = group
            .alice_group
            .encrypt_application_message(b"still here".to_vec())
            .unwrap();

        assert!(matches!(
            group
                .bob_group
                .process_incoming_message(message, policy)
                .unwrap(),
            ProcessedMessage::ApplicationMessage { .. }
        ));
    }

    #[test]
    fn test_a_member_as_full_as_it_may_be_follows_a_removal_leaving_a_much_smaller_group() {
        // Mallory has Bob, in a group of a hundred, keep a key for every
        // message she skips, until he may take in no more, and Alice removes
        // everybody but the three of them. The record of the epoch her removal
        // ends holds what Bob took in, more than a group of three may store,
        // which only what a group may store outside tests reaches.
        with_limits_outside_tests(|| {
            let alice = TestUser::new();
            let bob = TestUser::new();

            let mut group = establish_group_with_mallory(&alice, &bob, MAX_GROUP_MEMBERS - 3, true);
            let policy = created_by(&alice);

            flood(
                &mut group.mallory_group,
                &group.bob_group,
                &bob,
                &alice.uuid,
                max_group_state_len_at_rest(MAX_GROUP_MEMBERS),
            );

            let removal = group
                .alice_group
                .remove_members(group.stranger_uuids.clone())
                .unwrap();
            accept(&group.alice_group);

            group
                .bob_group
                .process_incoming_message(removal, policy.clone())
                .unwrap();

            assert_eq!(group.bob_group.members().unwrap().len(), 3);

            let largest_record = bob
                .store
                .records()
                .into_iter()
                .filter(|((tag, _), _)| *tag == MlsNamespace::GroupEpoch.tag())
                .map(|(_, sealed)| sealed.len() - 12 - 16)
                .max()
                .unwrap();

            assert!(largest_record > max_group_state_len_at_rest(3));

            // Bob is in the epoch Alice is in.
            let message = group
                .alice_group
                .encrypt_application_message(b"fewer of us".to_vec())
                .unwrap();

            assert!(matches!(
                group
                    .bob_group
                    .process_incoming_message(message, policy)
                    .unwrap(),
                ProcessedMessage::ApplicationMessage { .. }
            ));
        });
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
            .process_incoming_message(first.clone(), None)
            .unwrap();

        let error = bob
            .client
            .join_group(welcome.clone(), None, uuids(&[&alice]), true)
            .expect_err("a Welcome for a group already held must be refused");

        assert!(matches!(error, MlsError::GroupAlreadyJoined));

        // Bob's group was left where it was: the message it already read stays
        // spent, and the next one opens.
        let bob_group = bob.client.load_group(group_id.clone()).unwrap();

        assert!(
            bob_group
                .process_incoming_message(first.clone(), None)
                .is_err()
        );

        let second = alice_group
            .encrypt_application_message(b"second".to_vec())
            .unwrap();

        assert!(bob_group.process_incoming_message(second, None).is_ok());

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
                .process_incoming_message(message, None)
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
        // nothing is stored, so the 260 KB a test lets a group of a hundred
        // store does not stop it as it stops the join.
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
    fn test_a_member_added_back_joins_at_the_later_epoch_while_the_old_welcome_stays_refused() {
        // Carol joined through her last-resort key package, which survives the
        // join, so the Welcome she joined from still opens: only the record of
        // the group refuses it.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let last_resort = InviteeKeyPackage {
            user_uuid: carol.uuid.clone(),
            key_package: carol
                .client
                .generate_key_packages(0)
                .unwrap()
                .last_resort_key_package,
        };

        let group_uuid = new_group_uuid();

        let creation = alice
            .client
            .create_group(
                Some(group_uuid.clone()),
                vec![bob.invitation(), last_resort],
                None,
            )
            .unwrap();

        let first_welcome = creation.welcome;

        let alice_group = alice
            .client
            .load_group(creation.mls_group_id.clone())
            .unwrap();

        let joined = [(&bob, &carol), (&carol, &bob)].map(|(user, other)| {
            let group_id = user
                .client
                .join_group(
                    first_welcome.clone(),
                    Some(group_uuid.clone()),
                    uuids(&[&alice, other]),
                    true,
                )
                .unwrap();

            user.client.load_group(group_id).unwrap()
        });

        let policy = created_by(&alice);

        // Alice removes Carol, and adds her back.
        let removal = alice_group
            .remove_members(vec![carol.uuid.clone()])
            .unwrap();

        for group in &joined {
            group
                .process_incoming_message(removal.clone(), policy.clone())
                .unwrap();
        }

        accept(&alice_group);

        let addition = alice_group
            .add_members(vec![carol.invitation()], None)
            .unwrap();

        joined[0]
            .process_incoming_message(addition.commit, policy.clone())
            .unwrap();

        accept(&alice_group);

        // While Carol still holds the group, neither Welcome is joined.
        for welcome in [&first_welcome, &addition.welcome] {
            assert!(matches!(
                carol
                    .client
                    .inspect_welcome(welcome.clone(), Some(group_uuid.clone()))
                    .unwrap_err(),
                MlsError::GroupAlreadyJoined
            ));
        }

        // Once she drops it, as a removed member does, the Welcome she first
        // joined from is still refused, and the later one adding her back is
        // not.
        carol.client.delete_group(creation.mls_group_id).unwrap();

        assert!(matches!(
            carol
                .client
                .inspect_welcome(first_welcome.clone(), Some(group_uuid.clone()))
                .unwrap_err(),
            MlsError::GroupAlreadyJoined
        ));
        assert!(matches!(
            carol
                .client
                .join_group(
                    first_welcome.clone(),
                    Some(group_uuid.clone()),
                    uuids(&[&alice, &bob]),
                    true,
                )
                .unwrap_err(),
            MlsError::GroupAlreadyJoined
        ));

        let inspection = carol
            .client
            .inspect_welcome(addition.welcome.clone(), Some(group_uuid.clone()))
            .unwrap();

        assert_eq!(inspection.committer_user_uuid, alice.uuid);

        let rejoined = carol
            .client
            .join_group(
                addition.welcome,
                Some(group_uuid.clone()),
                inspection.member_uuids,
                true,
            )
            .unwrap();

        let carol_group = carol.client.load_group(rejoined).unwrap();

        // In the epoch everybody else is in, and reading them again.
        assert_eq!(carol_group.epoch().unwrap(), alice_group.epoch().unwrap());

        let message = alice_group
            .encrypt_application_message(b"welcome back".to_vec())
            .unwrap();

        assert!(matches!(
            carol_group
                .process_incoming_message(message, policy)
                .unwrap(),
            ProcessedMessage::ApplicationMessage { .. }
        ));

        // The first Welcome is refused once more, as one to a group she holds.
        assert!(matches!(
            carol
                .client
                .inspect_welcome(first_welcome, Some(group_uuid))
                .unwrap_err(),
            MlsError::GroupAlreadyJoined
        ));
    }

    #[test]
    fn test_the_record_of_a_deleted_group_refuses_every_welcome_once_it_cannot_be_read() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let group_uuid = new_group_uuid();
        let groups = establish_group_as(&group_uuid, &alice, &[&bob]);
        let (alice_group, bob_group) = (&groups[0], &groups[1]);
        let group_id = alice_group.mls_group_id().unwrap();

        // Alice removes Bob, who drops the group, and adds him back.
        let removal = alice_group.remove_members(vec![bob.uuid.clone()]).unwrap();

        bob_group
            .process_incoming_message(removal, created_by(&alice))
            .unwrap();
        bob.client.delete_group(group_id.clone()).unwrap();

        accept(alice_group);

        let addition = alice_group
            .add_members(vec![bob.invitation()], None)
            .unwrap();

        bob.client
            .inspect_welcome(addition.welcome.clone(), Some(group_uuid.clone()))
            .unwrap();

        // Once the record no longer says which epoch the group was at, the
        // Welcome adding him back is refused like the one he joined from.
        let key = [b"deleted-group/".as_slice(), &group_id].concat();

        bob.store
            .put(MlsNamespace::Metadata, key, b"unreadable".to_vec())
            .unwrap();

        assert!(matches!(
            bob.client
                .inspect_welcome(addition.welcome, Some(group_uuid))
                .unwrap_err(),
            MlsError::GroupAlreadyJoined
        ));
    }

    #[test]
    fn test_deleting_a_group_deleted_already_leaves_the_record_of_its_deletion_as_it_was() {
        // As a host deleting it again does, not knowing its first try stored
        // everything.
        let alice = TestUser::new();
        let bob = TestUser::new();

        let groups = establish_group(&alice, &[&bob]);
        let group_id = groups[1].mls_group_id().unwrap();

        bob.client.delete_group(group_id.clone()).unwrap();

        let before = bob.store.records();

        bob.client.delete_group(group_id).unwrap();

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

        assert!(carol_group.process_incoming_message(message, None).is_ok());
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
    fn test_a_client_signs_group_information_with_the_key_its_peers_pin() {
        let alice = TestUser::new();

        let information = GroupInformation {
            group_uuid: new_group_uuid(),
            revision: 1,
            title: "Flatmates".to_string(),
            description: "Rent and groceries".to_string(),
            currency_uuid: Uuid::new_v4().to_string(),
        };

        let signature = alice
            .client
            .sign_group_information(information.clone())
            .unwrap();

        assert!(verify_group_information(
            alice.uuid.clone(),
            alice.client.signature_public_key(),
            information,
            signature,
        ));
    }

    /// A version of a group expense written by `author`, in `group_uuid`.
    fn group_expense_version(group_uuid: &str, author: &TestUser) -> GroupExpenseVersion {
        GroupExpenseVersion {
            group_uuid: group_uuid.to_string(),
            expense_uuid: Uuid::new_v4().to_string(),
            revision: 1,
            title: "Groceries".to_string(),
            description: String::new(),
            amount: "42.00".to_string(),
            timestamp: "2026-10-30T09:00:00Z".to_string(),
            creditor_uuid: author.uuid.clone(),
            beneficiaries: vec![GroupExpenseBeneficiary {
                user_uuid: author.uuid.clone(),
                share: "42.00".to_string(),
                is_share_fixed: false,
            }],
            is_settlement: false,
        }
    }

    #[test]
    fn test_a_client_signs_a_group_expense_with_the_key_its_peers_pin() {
        let alice = TestUser::new();

        let version = group_expense_version(&new_group_uuid(), &alice);

        let signature = alice.client.sign_group_expense(version.clone()).unwrap();

        assert!(verify_group_expense(
            version,
            alice.uuid.clone(),
            alice.client.signature_public_key(),
            signature,
        ));
    }

    #[test]
    fn test_a_client_signs_a_group_expense_deletion_with_the_key_its_peers_pin() {
        let alice = TestUser::new();

        let version = group_expense_version(&new_group_uuid(), &alice);

        let deletion = GroupExpenseDeletion {
            group_uuid: version.group_uuid.clone(),
            expense_uuid: version.expense_uuid.clone(),
            deletion_revision: 1,
            is_deleted: true,
        };

        let signature = alice
            .client
            .sign_group_expense_deletion(deletion.clone())
            .unwrap();

        assert!(verify_group_expense_deletion(
            deletion,
            version,
            alice.uuid.clone(),
            alice.client.signature_public_key(),
            signature,
        ));
    }

    /// The key the group's tree holds for a member, as [`MlsGroup::members`]
    /// reports it, is one their group expenses check out under: what a reader
    /// goes by for a member who is no contact of theirs.
    #[test]
    fn test_a_group_expense_verifies_under_the_key_the_group_holds_for_its_author() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let group_uuid = new_group_uuid();
        let groups = establish_group_as(&group_uuid, &alice, &[&bob, &carol]);

        let version = group_expense_version(&group_uuid, &bob);
        let signature = bob.client.sign_group_expense(version.clone()).unwrap();

        let as_carol_holds_bob = groups[2]
            .members()
            .unwrap()
            .into_iter()
            .find(|member| member.user_uuid == bob.uuid)
            .unwrap();

        assert!(verify_group_expense(
            version.clone(),
            bob.uuid.clone(),
            as_carol_holds_bob.signature_key,
            signature.clone(),
        ));

        // Nor does it pass for Alice's, under the key the group holds for her.
        let as_carol_holds_alice = groups[2]
            .members()
            .unwrap()
            .into_iter()
            .find(|member| member.user_uuid == alice.uuid)
            .unwrap();

        assert!(!verify_group_expense(
            version,
            alice.uuid.clone(),
            as_carol_holds_alice.signature_key,
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
            .process_incoming_message(message, None)
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

        // When the key packages expire, the first eight bytes of the record.
        let openable_until = u64::from_be_bytes(
            bob.store
                .get(MlsNamespace::Metadata, record)
                .unwrap()
                .unwrap()[..8]
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
    fn test_every_member_is_reported_with_the_signature_key_their_leaf_holds() {
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let users = [&alice, &bob, &carol];
        let groups = establish_group(&alice, &[&bob, &carol]);

        for group in &groups {
            let members = group.members().unwrap();

            assert_eq!(members.len(), users.len());

            for user in users {
                let member = members
                    .iter()
                    .find(|member| member.user_uuid == user.uuid)
                    .unwrap();

                assert_eq!(member.signature_key, user.client.signature_public_key());
            }
        }
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

        match bob_group
            .process_incoming_message(ciphertext, None)
            .unwrap()
        {
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
    fn test_concurrent_removals_of_a_departed_member_converge_on_server_order() {
        // Carol has left, and Alice, the creator, and Bob both commit her
        // removal in the same epoch, neither having seen the other's.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let groups = establish_group(&alice, &[&bob, &carol]);
        let (alice_group, bob_group) = (&groups[0], &groups[1]);

        let policy = commit_policy(&alice.uuid, &[&carol.uuid]);
        let epoch_before = alice_group.epoch().unwrap();

        let alice_commit = alice_group
            .remove_members(vec![carol.uuid.clone()])
            .unwrap();
        let bob_commit = bob_group.remove_members(vec![carol.uuid.clone()]).unwrap();

        // The server stores Bob's, which came first, so Bob's wins for
        // everyone.
        assert!(matches!(
            alice_group
                .process_incoming_message(bob_commit, policy.clone())
                .unwrap(),
            ProcessedMessage::Commit { committer_user_uuid, .. }
                if committer_user_uuid == Some(bob.uuid.clone())
        ));

        // Applying the winning commit discards Alice's, which simply never
        // happened, and removed nobody Bob's did not.
        assert!(!alice_group.has_pending_commit().unwrap());

        accept(bob_group);

        assert_eq!(alice_group.epoch().unwrap(), epoch_before + 1);
        assert_eq!(bob_group.epoch().unwrap(), epoch_before + 1);

        let mut expected = uuids(&[&alice, &bob]);
        expected.sort();

        assert_eq!(member_uuids(alice_group), expected);
        assert_eq!(member_uuids(bob_group), expected);

        // Bob rejects Alice's now-stale commit rather than forking.
        assert!(
            bob_group
                .process_incoming_message(alice_commit, policy.clone())
                .is_err()
        );

        // The group is still usable by both.
        let ciphertext = bob_group
            .encrypt_application_message(b"still working".to_vec())
            .unwrap();

        assert!(matches!(
            alice_group
                .process_incoming_message(ciphertext, policy)
                .unwrap(),
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
                .process_incoming_message(proposal.clone(), None)
                .unwrap(),
            ProcessedMessage::Proposal { .. }
        ));

        bob_group.process_incoming_message(proposal, None).unwrap();

        // A remaining member commits it, and only then is Carol gone.
        let commit = alice_group.update().unwrap();
        accept(alice_group);

        bob_group.process_incoming_message(commit, None).unwrap();

        let mut expected = vec![alice.uuid.clone(), bob.uuid.clone()];
        expected.sort();

        assert_eq!(member_uuids(alice_group), expected);
        assert_eq!(member_uuids(bob_group), expected);
    }

    #[test]
    fn test_a_member_deleting_their_account_is_removed_by_another_members_commit_not_by_their_proposal()
     {
        // Carol is deleting her account, and proposes her own removal, which
        // members holding to a commit policy refuse. Once she has departed,
        // Bob, a member, commits her removal while Alice, the creator, is
        // away.
        let alice = TestUser::new();
        let bob = TestUser::new();
        let carol = TestUser::new();

        let groups = establish_group(&alice, &[&bob, &carol]);
        let (alice_group, bob_group, carol_group) = (&groups[0], &groups[1], &groups[2]);

        let policy = commit_policy(&alice.uuid, &[&carol.uuid]);

        let proposal = carol_group.propose_self_remove().unwrap();

        for group in [alice_group, bob_group] {
            assert!(matches!(
                group
                    .process_incoming_message(proposal.clone(), policy.clone())
                    .unwrap_err(),
                MlsError::UnauthorizedChange
            ));
        }

        let removal = bob_group.remove_members(vec![carol.uuid.clone()]).unwrap();

        assert!(matches!(
            alice_group
                .process_incoming_message(removal, policy)
                .unwrap(),
            ProcessedMessage::Commit { committer_user_uuid, .. }
                if committer_user_uuid == Some(bob.uuid.clone())
        ));

        accept(bob_group);

        let mut expected = uuids(&[&alice, &bob]);
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

    #[test]
    fn test_a_group_whose_state_does_not_open_is_deleted_all_the_same() {
        let alice = TestUser::new();
        let bob = TestUser::new();

        let group_uuid = new_group_uuid();
        let groups = establish_group_as(&group_uuid, &alice, &[&bob]);
        let group_id = groups[1].mls_group_id().unwrap();

        drop(groups);

        // Bob's state fails authentication, as one the host damaged does.
        let mut sealed = bob
            .store
            .get(MlsNamespace::GroupState, group_id.clone())
            .unwrap()
            .unwrap();
        *sealed.last_mut().unwrap() ^= 1;

        bob.store
            .put(MlsNamespace::GroupState, group_id.clone(), sealed)
            .unwrap();

        assert!(matches!(
            bob.client.load_group(group_id.clone()).unwrap_err(),
            MlsError::StorageIntegrityFailed
        ));

        bob.client.delete_group(group_id.clone()).unwrap();

        assert!(matches!(
            bob.client.load_group(group_id.clone()).unwrap_err(),
            MlsError::GroupNotFound
        ));
        assert!(bob.store.keys(MlsNamespace::GroupEpoch).unwrap().is_empty());

        // The epoch it was at unknown, every Welcome to it is refused, even one
        // adding Bob back later.
        let alice_group = alice.client.load_group(group_id).unwrap();

        alice_group.remove_members(vec![bob.uuid.clone()]).unwrap();
        accept(&alice_group);

        let addition = alice_group
            .add_members(vec![bob.invitation()], None)
            .unwrap();

        assert!(matches!(
            bob.client
                .inspect_welcome(addition.welcome, Some(group_uuid))
                .unwrap_err(),
            MlsError::GroupAlreadyJoined
        ));
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
