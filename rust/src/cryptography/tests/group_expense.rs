#[cfg(test)]
mod tests {
    use base64::Engine;
    use base64::prelude::BASE64_STANDARD;
    use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
    use serde_json::{Value, json};
    use uuid::Uuid;

    use crate::cryptography::encryption::decrypt::decrypt_using_symmetric_key_with_associated_data;
    use crate::cryptography::encryption::encrypt::encrypt_using_symmetric_key_with_associated_data;
    use crate::cryptography::encryption::encrypted_field::EncryptedField;
    use crate::cryptography::encryption::keys::generate_symmetric_encryption_key;
    use crate::cryptography::mls::config::generate_signature_key_pair;
    use crate::cryptography::mls::group_expense::{
        self, GroupExpenseBeneficiary, GroupExpenseVersion, sign, verify_group_expense,
    };
    use crate::cryptography::mls::group_information::{self, GroupInformation};
    use crate::cryptography::mls::one_time_expense::{
        self, OneTimeExpenseManifest, OneTimeExpenseSettledMark, SealedValue,
    };
    use crate::cryptography::mls::sign_content::{self, labelled};

    const BOB: &str = "3c9a7d41-2e6b-4f08-9a15-c47e0b2d8f63";
    const CAROL: &str = "7f2e9b04-6d1a-4c53-8e27-0a9c5b3d1f48";
    const DAVE: &str = "b51d0e8c-3f7a-4296-a4c0-e82f6b19d7a5";

    struct Author {
        uuid: String,
        secret_key: SignatureSecretKey,
        public_key: SignaturePublicKey,
    }

    impl Author {
        fn new() -> Self {
            let (secret_key, public_key) = generate_signature_key_pair().unwrap();

            Author {
                uuid: Uuid::new_v4().to_string(),
                secret_key,
                public_key,
            }
        }

        fn sign(&self, version: &GroupExpenseVersion) -> Vec<u8> {
            sign(&self.secret_key, &self.uuid, version.clone()).unwrap()
        }

        fn verifies(&self, version: &GroupExpenseVersion, signature: &[u8]) -> bool {
            verify_group_expense(
                version.clone(),
                self.uuid.clone(),
                self.public_key.to_vec(),
                signature.to_vec(),
            )
        }

        /// Signs `signed` as this author the way a group expense is signed,
        /// but under `label`.
        fn sign_labelled(&self, label: &[u8], signed: &impl mls_rs_codec::MlsEncode) -> Vec<u8> {
            let signed = labelled(label, &self.uuid, signed).unwrap();

            sign_content::sign(&self.secret_key, &signed).unwrap()
        }
    }

    fn beneficiary(user_uuid: &str, share: &str, is_share_fixed: bool) -> GroupExpenseBeneficiary {
        GroupExpenseBeneficiary {
            user_uuid: user_uuid.to_string(),
            share: share.to_string(),
            is_share_fixed,
        }
    }

    /// One way of tampering with a signed version.
    type Change = fn(&mut GroupExpenseVersion);

    /// One way of tampering with one beneficiary of a signed version.
    type BeneficiaryChange = fn(&mut GroupExpenseBeneficiary);

    /// A version whose beneficiaries are listed in UUID order, as they are
    /// signed.
    fn version() -> GroupExpenseVersion {
        GroupExpenseVersion {
            group_uuid: "0b4f1a0e-5c3d-8e2a-9f61-7d2c4b8a1e05".to_string(),
            expense_uuid: "8d1e5823-c00c-83b7-8212-500089e3b975".to_string(),
            revision: 3,
            title: "Dinner at the harbour".to_string(),
            description: "Fish, wine and the tip".to_string(),
            amount: "90.00".to_string(),
            timestamp: "2026-10-30T19:45:00Z".to_string(),
            creditor_uuid: BOB.to_string(),
            beneficiaries: vec![
                beneficiary(BOB, "30.00", true),
                beneficiary(CAROL, "60.00", false),
            ],
            is_settlement: false,
            is_deleted: false,
        }
    }

    /// Bob paying `recipient_uuid` back what he owes them.
    fn settlement(recipient_uuid: &str) -> GroupExpenseVersion {
        GroupExpenseVersion {
            beneficiaries: vec![beneficiary(recipient_uuid, "90.00", false)],
            is_settlement: true,
            ..version()
        }
    }

    /// The context a version is sealed bound to, as the app seals it.
    fn context(group_uuid: &str, expense_uuid: &str) -> Vec<u8> {
        format!("group_expense:{group_uuid}:{expense_uuid}").into_bytes()
    }

    /// Seals `version` under `key` as the app does: its fields, its author
    /// and the signature, as JSON, bound to its expense. The group, the
    /// expense and the revision are left out, the server serving the version
    /// with them.
    fn seal(
        key: &Vec<u8>,
        version: &GroupExpenseVersion,
        author_uuid: &str,
        signature: &[u8],
    ) -> EncryptedField {
        let beneficiaries: Vec<Value> = version
            .beneficiaries
            .iter()
            .map(|beneficiary| {
                json!({
                    "user_uuid": beneficiary.user_uuid,
                    "share": beneficiary.share,
                    "is_share_fixed": beneficiary.is_share_fixed,
                })
            })
            .collect();

        let content = json!({
            "title": version.title,
            "description": version.description,
            "amount": version.amount,
            "timestamp": version.timestamp,
            "creditor_uuid": version.creditor_uuid,
            "beneficiaries": beneficiaries,
            "is_settlement": version.is_settlement,
            "is_deleted": version.is_deleted,
            "author_uuid": author_uuid,
            "signature": BASE64_STANDARD.encode(signature),
        });

        encrypt_using_symmetric_key_with_associated_data(
            key,
            &content.to_string().into_bytes(),
            &context(&version.group_uuid, &version.expense_uuid),
        )
        .unwrap()
    }

    /// What `sealed` opens to under `key`, served as `revision` of
    /// `expense_uuid` in `group_uuid`: the version, its author and the
    /// signature, or `None` when it does not open.
    fn open(
        key: &Vec<u8>,
        sealed: &EncryptedField,
        group_uuid: &str,
        expense_uuid: &str,
        revision: u64,
    ) -> Option<(GroupExpenseVersion, String, Vec<u8>)> {
        let plaintext = decrypt_using_symmetric_key_with_associated_data(
            key,
            &sealed.ciphertext,
            &sealed.nonce,
            &context(group_uuid, expense_uuid),
        )
        .ok()?;

        let content: Value = serde_json::from_slice(&plaintext).unwrap();
        let text = |value: &Value, field: &str| value[field].as_str().unwrap().to_string();

        let version = GroupExpenseVersion {
            group_uuid: group_uuid.to_string(),
            expense_uuid: expense_uuid.to_string(),
            revision,
            title: text(&content, "title"),
            description: text(&content, "description"),
            amount: text(&content, "amount"),
            timestamp: text(&content, "timestamp"),
            creditor_uuid: text(&content, "creditor_uuid"),
            beneficiaries: content["beneficiaries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|beneficiary| GroupExpenseBeneficiary {
                    user_uuid: text(beneficiary, "user_uuid"),
                    share: text(beneficiary, "share"),
                    is_share_fixed: beneficiary["is_share_fixed"].as_bool().unwrap(),
                })
                .collect(),
            is_settlement: content["is_settlement"].as_bool().unwrap(),
            is_deleted: content["is_deleted"].as_bool().unwrap(),
        };

        let signature = BASE64_STANDARD.decode(text(&content, "signature")).unwrap();

        Some((version, text(&content, "author_uuid"), signature))
    }

    #[test]
    fn test_a_signed_version_verifies() {
        // Alice neither paid nor benefits: any member may write any expense.
        let alice = Author::new();
        let version = version();

        let signature = alice.sign(&version);

        assert!(alice.verifies(&version, &signature));
    }

    /// A version is signed over what it opens to and not over the bytes it is
    /// sealed in, so it is as much its author's sealed again under another key
    /// of the group: one a member reads under an older key, or one sealed
    /// again under the newest.
    #[test]
    fn test_a_version_sealed_again_under_another_key_still_verifies() {
        let alice = Author::new();
        let version = version();
        let older_key = generate_symmetric_encryption_key();
        let newer_key = generate_symmetric_encryption_key();
        let served = |key: &Vec<u8>, sealed: &EncryptedField| {
            open(
                key,
                sealed,
                &version.group_uuid,
                &version.expense_uuid,
                version.revision,
            )
        };

        let sealed = seal(&older_key, &version, &alice.uuid, &alice.sign(&version));

        let (opened, author_uuid, signature) = served(&older_key, &sealed).unwrap();

        assert_eq!(author_uuid, alice.uuid);
        assert!(alice.verifies(&opened, &signature));

        let sealed_again = seal(&newer_key, &opened, &author_uuid, &signature);

        let (opened_again, author_uuid, signature) = served(&newer_key, &sealed_again).unwrap();

        assert_eq!(author_uuid, alice.uuid);
        assert!(alice.verifies(&opened_again, &signature));
        assert!(served(&older_key, &sealed_again).is_none());
    }

    #[test]
    fn test_a_sealed_version_opens_only_as_its_own_expense() {
        let alice = Author::new();
        let version = version();
        let key = generate_symmetric_encryption_key();
        let sealed = seal(&key, &version, &alice.uuid, &alice.sign(&version));

        let group_uuid = &version.group_uuid;
        let expense_uuid = &version.expense_uuid;
        let another_uuid = &Uuid::new_v4().to_string();

        assert!(open(&key, &sealed, group_uuid, expense_uuid, version.revision).is_some());
        assert!(open(&key, &sealed, group_uuid, another_uuid, version.revision).is_none());
        assert!(open(&key, &sealed, another_uuid, expense_uuid, version.revision).is_none());
        assert!(open(&key, &sealed, expense_uuid, group_uuid, version.revision).is_none());
    }

    #[test]
    fn test_a_version_without_a_description_verifies() {
        let alice = Author::new();
        let mut version = version();
        version.description = String::new();

        let signature = alice.sign(&version);

        assert!(alice.verifies(&version, &signature));
    }

    #[test]
    fn test_the_order_beneficiaries_come_in_does_not_matter() {
        let alice = Author::new();
        let mut version = version();
        version.beneficiaries.push(beneficiary(DAVE, "0.00", false));

        let signature = alice.sign(&version);

        let mut reversed = version.clone();
        reversed.beneficiaries.reverse();

        let mut rotated = version.clone();
        rotated.beneficiaries.rotate_left(1);

        assert!(alice.verifies(&reversed, &signature));
        assert!(alice.verifies(&rotated, &signature));

        // Signed out of order, it verifies in order too.
        assert!(alice.verifies(&version, &alice.sign(&rotated)));
    }

    #[test]
    fn test_any_change_to_a_signed_version_is_refused() {
        let alice = Author::new();
        let signature = alice.sign(&version());

        let changes: Vec<(&str, Change)> = vec![
            ("another group", |v| {
                v.group_uuid = Uuid::new_v4().to_string()
            }),
            ("another expense", |v| {
                v.expense_uuid = Uuid::new_v4().to_string()
            }),
            ("the group and expense swapped", |v| {
                std::mem::swap(&mut v.group_uuid, &mut v.expense_uuid)
            }),
            ("an older revision", |v| v.revision = 2),
            ("a newer revision", |v| v.revision = 4),
            ("the title", |v| {
                v.title = "Lunch at the harbour".to_string()
            }),
            ("the title emptied", |v| v.title = String::new()),
            ("the description", |v| v.description.push('!')),
            ("the amount", |v| v.amount = "91.00".to_string()),
            ("the amount written otherwise", |v| {
                v.amount = "90".to_string()
            }),
            ("the timestamp", |v| {
                v.timestamp = "2026-10-30T19:46:00Z".to_string()
            }),
            ("another creditor", |v| v.creditor_uuid = CAROL.to_string()),
            ("the title and description swapped", |v| {
                std::mem::swap(&mut v.title, &mut v.description)
            }),
            ("a beneficiary dropped", |v| {
                v.beneficiaries.pop();
            }),
            ("a beneficiary added", |v| {
                v.beneficiaries.push(beneficiary(DAVE, "0.00", false))
            }),
            ("every beneficiary dropped", |v| v.beneficiaries.clear()),
            ("two shares swapped", |v| {
                let first = v.beneficiaries[0].share.clone();
                v.beneficiaries[0].share = v.beneficiaries[1].share.clone();
                v.beneficiaries[1].share = first;
            }),
            ("made a settlement", |v| v.is_settlement = true),
            ("deleted", |v| v.is_deleted = true),
        ];

        for (change, apply) in changes {
            let mut changed = version();
            apply(&mut changed);

            assert!(
                !alice.verifies(&changed, &signature),
                "{change} must not verify"
            );
        }
    }

    #[test]
    fn test_any_change_to_a_beneficiary_is_refused() {
        let alice = Author::new();
        let signature = alice.sign(&version());

        let changes: Vec<(&str, BeneficiaryChange)> = vec![
            ("their UUID", |b| b.user_uuid = Uuid::new_v4().to_string()),
            ("their share", |b| b.share = "45.00".to_string()),
            ("their share written otherwise", |b| b.share.push('0')),
            ("their share emptied", |b| b.share = String::new()),
            ("their fixed-share flag flipped", |b| {
                b.is_share_fixed = !b.is_share_fixed
            }),
        ];

        for index in 0..version().beneficiaries.len() {
            for (change, apply) in &changes {
                let mut changed = version();
                apply(&mut changed.beneficiaries[index]);

                assert!(
                    !alice.verifies(&changed, &signature),
                    "{change} of beneficiary {index} must not verify"
                );
            }
        }
    }

    #[test]
    fn test_a_settlement_signed_by_its_recipient_verifies() {
        let alice = Author::new();
        let settlement = settlement(&alice.uuid);

        let signature = alice.sign(&settlement);

        assert!(alice.verifies(&settlement, &signature));
    }

    /// Only the member paid can say they were: anybody else's word for it,
    /// however good their signature, would let them make up a repayment.
    #[test]
    fn test_a_settlement_signed_by_anybody_but_its_recipient_is_refused() {
        let alice = Author::new();

        // Bob paying Carol, recorded by Alice.
        let recorded_by_another = settlement(CAROL);

        // Alice paying Carol, recorded by Alice, who paid.
        let recorded_by_its_payer = GroupExpenseVersion {
            creditor_uuid: alice.uuid.clone(),
            ..settlement(CAROL)
        };

        for settlement in [recorded_by_another, recorded_by_its_payer] {
            let signature = alice.sign(&settlement);

            assert!(!alice.verifies(&settlement, &signature));
        }
    }

    /// A settlement is paid to one member: one that would be paid to more, or
    /// to nobody, is nobody's to record, its recipient's among them.
    #[test]
    fn test_a_settlement_with_other_beneficiaries_than_its_recipient_is_refused() {
        let alice = Author::new();

        let beneficiaries = [
            vec![
                beneficiary(&alice.uuid, "45.00", false),
                beneficiary(CAROL, "45.00", false),
            ],
            vec![
                beneficiary(CAROL, "45.00", false),
                beneficiary(&alice.uuid, "45.00", false),
            ],
            Vec::new(),
        ];

        for beneficiaries in beneficiaries {
            let settlement = GroupExpenseVersion {
                beneficiaries,
                ..settlement(&alice.uuid)
            };

            let signature = alice.sign(&settlement);

            assert!(!alice.verifies(&settlement, &signature));
        }
    }

    #[test]
    fn test_a_deleted_settlement_is_refused_once_restored_or_made_an_expense() {
        let alice = Author::new();
        let settlement = GroupExpenseVersion {
            is_deleted: true,
            ..settlement(&alice.uuid)
        };

        let signature = alice.sign(&settlement);

        assert!(alice.verifies(&settlement, &signature));

        let mut restored = settlement.clone();
        restored.is_deleted = false;

        let mut expense = settlement.clone();
        expense.is_settlement = false;

        assert!(!alice.verifies(&restored, &signature));
        assert!(!alice.verifies(&expense, &signature));
    }

    /// Each field is told apart from its neighbours by the length ahead of it,
    /// so text moved across the boundary between two of them changes what is
    /// signed, even though the two read the same end to end.
    #[test]
    fn test_text_moved_from_one_field_to_the_next_is_refused() {
        let alice = Author::new();
        let signature = alice.sign(&version());

        let changes: Vec<(&str, Change)> = vec![
            ("from the group to the expense", |v| {
                let moved = v.group_uuid.pop().unwrap();
                v.expense_uuid.insert(0, moved);
            }),
            ("from the title to the description", |v| {
                v.title = "Dinner at the".to_string();
                v.description = " harbourFish, wine and the tip".to_string();
            }),
            ("from the description to the amount", |v| {
                v.description = "Fish, wine and the ti".to_string();
                v.amount = "p90.00".to_string();
            }),
            ("from the amount to the timestamp", |v| {
                v.amount = "90.0".to_string();
                v.timestamp = "02026-10-30T19:45:00Z".to_string();
            }),
            ("from the timestamp to the creditor", |v| {
                let moved = v.timestamp.pop().unwrap();
                v.creditor_uuid.insert(0, moved);
            }),
            ("from a beneficiary's UUID to their share", |v| {
                let moved = v.beneficiaries[0].user_uuid.pop().unwrap();
                v.beneficiaries[0].share.insert(0, moved);
            }),
        ];

        for (change, apply) in changes {
            let mut changed = version();
            apply(&mut changed);

            assert!(
                !alice.verifies(&changed, &signature),
                "text moved {change} must not verify"
            );
        }
    }

    #[test]
    fn test_a_version_is_refused_under_another_author() {
        let alice = Author::new();
        let signature = alice.sign(&version());

        // The version naming someone else as its author, with Alice's key.
        assert!(!verify_group_expense(
            version(),
            Uuid::new_v4().to_string(),
            alice.public_key.to_vec(),
            signature,
        ));
    }

    #[test]
    fn test_a_version_is_refused_under_another_member_s_key() {
        let alice = Author::new();
        let carol = Author::new();
        let signature = alice.sign(&version());

        assert!(!verify_group_expense(
            version(),
            alice.uuid.clone(),
            carol.public_key.to_vec(),
            signature,
        ));
    }

    #[test]
    fn test_a_member_cannot_sign_for_another() {
        // Carol holds the group key and so can seal any version she likes,
        // but she signs with her own key, not Alice's.
        let alice = Author::new();
        let carol = Author::new();

        let forged = sign(&carol.secret_key, &alice.uuid, version()).unwrap();

        assert!(!alice.verifies(&version(), &forged));
    }

    #[test]
    fn test_a_member_s_version_cannot_be_passed_off_as_another_s() {
        // Carol's own version, signed as herself, sealed again with Alice
        // named as its author: her UUID is signed, so it holds for her alone,
        // whichever key it is checked under.
        let alice = Author::new();
        let carol = Author::new();
        let signature = carol.sign(&version());

        assert!(carol.verifies(&version(), &signature));

        for key in [alice.public_key.to_vec(), carol.public_key.to_vec()] {
            assert!(!verify_group_expense(
                version(),
                alice.uuid.clone(),
                key,
                signature.clone(),
            ));
        }
    }

    #[test]
    fn test_a_signature_of_another_kind_does_not_pass_for_a_version() {
        let alice = Author::new();
        let version = version();

        // The very bytes a version is signed over, labelled as a version, as
        // group information, as a one-time expense and as a settled mark: only
        // the first one verifies.
        assert!(alice.verifies(
            &version,
            &alice.sign_labelled(group_expense::LABEL, &version),
        ));

        for label in [
            group_information::LABEL,
            one_time_expense::LABEL,
            one_time_expense::SETTLED_MARK_LABEL,
        ] {
            assert!(!alice.verifies(&version, &alice.sign_labelled(label, &version)));
        }
    }

    #[test]
    fn test_a_version_s_signature_does_not_pass_for_another_kind() {
        let alice = Author::new();

        let information = GroupInformation {
            group_uuid: "0b4f1a0e-5c3d-8e2a-9f61-7d2c4b8a1e05".to_string(),
            revision: 3,
            title: "Lisbon trip".to_string(),
            description: String::new(),
            currency_uuid: "6e0f4c2a-8b1d-4f3e-a5c7-2d9b1e8f0a64".to_string(),
        };

        let sealed = |label: &str| SealedValue {
            nonce: format!("{label} nonce").into_bytes(),
            ciphertext: format!("{label} ciphertext").into_bytes(),
        };

        let manifest = OneTimeExpenseManifest {
            revision: 3,
            title: sealed("title"),
            description: sealed("description"),
            amount: sealed("amount"),
            currency: sealed("currency"),
            timestamp: sealed("timestamp"),
            beneficiaries: Vec::new(),
        };

        let mark = OneTimeExpenseSettledMark {
            expense_uuid: "8d1e5823-c00c-83b7-8212-500089e3b975".to_string(),
            marked_at: 1_760_400_000_000,
            is_settled: true,
        };

        // Each of them signed the way it is, but under a version's label.
        assert!(!group_information::verify_group_information(
            alice.uuid.clone(),
            alice.public_key.to_vec(),
            information.clone(),
            alice.sign_labelled(group_expense::LABEL, &information),
        ));

        assert!(!one_time_expense::verify_one_time_expense(
            alice.uuid.clone(),
            alice.public_key.to_vec(),
            manifest.clone(),
            alice.sign_labelled(group_expense::LABEL, &manifest),
        ));

        assert!(!one_time_expense::verify_one_time_expense_settled_mark(
            alice.uuid.clone(),
            alice.public_key.to_vec(),
            mark.clone(),
            alice.sign_labelled(group_expense::LABEL, &mark),
        ));
    }

    #[test]
    fn test_malformed_keys_and_signatures_are_refused() {
        let alice = Author::new();
        let signature = alice.sign(&version());

        assert!(!alice.verifies(&version(), &[]));
        assert!(!alice.verifies(&version(), &signature[1..]));

        for key in [Vec::new(), vec![0; 3], vec![0; 32]] {
            assert!(!verify_group_expense(
                version(),
                alice.uuid.clone(),
                key,
                signature.clone(),
            ));
        }
    }
}
