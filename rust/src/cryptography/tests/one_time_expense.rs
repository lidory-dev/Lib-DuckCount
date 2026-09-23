#[cfg(test)]
mod tests {
    use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
    use uuid::Uuid;

    use crate::cryptography::mls::config::generate_signature_key_pair;
    use crate::cryptography::mls::one_time_expense::{
        OneTimeExpenseBeneficiary, OneTimeExpenseManifest, SealedValue, sign,
        verify_one_time_expense,
    };

    struct Creditor {
        uuid: String,
        secret_key: SignatureSecretKey,
        public_key: SignaturePublicKey,
    }

    impl Creditor {
        fn new() -> Self {
            let (secret_key, public_key) = generate_signature_key_pair().unwrap();

            Creditor {
                uuid: Uuid::new_v4().to_string(),
                secret_key,
                public_key,
            }
        }

        fn sign(&self, manifest: &OneTimeExpenseManifest) -> Vec<u8> {
            sign(&self.secret_key, &self.uuid, manifest.clone()).unwrap()
        }

        fn verifies(&self, manifest: &OneTimeExpenseManifest, signature: &[u8]) -> bool {
            verify_one_time_expense(
                self.uuid.clone(),
                self.public_key.to_vec(),
                manifest.clone(),
                signature.to_vec(),
            )
        }
    }

    fn sealed(label: &str) -> SealedValue {
        SealedValue {
            nonce: format!("{label} nonce").into_bytes(),
            ciphertext: format!("{label} ciphertext").into_bytes(),
        }
    }

    fn beneficiary(user_uuid: &str) -> OneTimeExpenseBeneficiary {
        OneTimeExpenseBeneficiary {
            user_uuid: user_uuid.to_string(),
            share: sealed(&format!("{user_uuid} share")),
            is_share_fixed: sealed(&format!("{user_uuid} is_share_fixed")),
        }
    }

    /// One way of tampering with a signed version.
    type Change = fn(&mut OneTimeExpenseManifest);

    fn manifest() -> OneTimeExpenseManifest {
        OneTimeExpenseManifest {
            revision: 3,
            is_settlement: false,
            title: sealed("title"),
            description: sealed("description"),
            amount: sealed("amount"),
            currency: sealed("currency"),
            timestamp: sealed("timestamp"),
            beneficiaries: vec![beneficiary("bob"), beneficiary("carol")],
        }
    }

    #[test]
    fn test_a_signed_version_verifies() {
        let alice = Creditor::new();
        let manifest = manifest();

        let signature = alice.sign(&manifest);

        assert!(alice.verifies(&manifest, &signature));
    }

    #[test]
    fn test_the_order_the_server_lists_beneficiaries_in_does_not_matter() {
        let alice = Creditor::new();
        let manifest = manifest();
        let signature = alice.sign(&manifest);

        let mut reordered = manifest.clone();
        reordered.beneficiaries.reverse();

        assert!(alice.verifies(&reordered, &signature));
    }

    #[test]
    fn test_any_change_to_a_signed_version_is_refused() {
        let alice = Creditor::new();
        let signature = alice.sign(&manifest());

        let changes: Vec<(&str, Change)> = vec![
            ("an older revision", |m| m.revision = 2),
            ("the settlement flag", |m| m.is_settlement = true),
            ("the title's ciphertext", |m| m.title.ciphertext.push(0)),
            ("the title's nonce", |m| m.title.nonce.push(0)),
            ("the description", |m| m.description = sealed("other")),
            ("the amount", |m| m.amount = sealed("other")),
            ("the currency", |m| m.currency = sealed("other")),
            ("the timestamp", |m| m.timestamp = sealed("other")),
            ("the title and description swapped", |m| {
                std::mem::swap(&mut m.title, &mut m.description)
            }),
            ("a share", |m| m.beneficiaries[0].share = sealed("other")),
            ("a fixed-share flag", |m| {
                m.beneficiaries[0].is_share_fixed = sealed("other")
            }),
            ("two shares swapped", |m| {
                let first = m.beneficiaries[0].share.clone();
                m.beneficiaries[0].share = m.beneficiaries[1].share.clone();
                m.beneficiaries[1].share = first;
            }),
            ("a beneficiary renamed", |m| {
                m.beneficiaries[0].user_uuid = "mallory".to_string()
            }),
            ("a beneficiary dropped", |m| {
                m.beneficiaries.pop();
            }),
            ("a beneficiary added", |m| {
                m.beneficiaries.push(beneficiary("mallory"))
            }),
        ];

        for (change, apply) in changes {
            let mut changed = manifest();
            apply(&mut changed);

            assert!(
                !alice.verifies(&changed, &signature),
                "{change} must not verify"
            );
        }
    }

    #[test]
    fn test_a_version_is_refused_under_another_creditor() {
        let alice = Creditor::new();
        let signature = alice.sign(&manifest());

        // The server naming someone else as the creditor, with Alice's key.
        assert!(!verify_one_time_expense(
            Uuid::new_v4().to_string(),
            alice.public_key.to_vec(),
            manifest(),
            signature,
        ));
    }

    #[test]
    fn test_a_participant_cannot_sign_for_the_creditor() {
        // Carol holds the expense key and so can seal any version she likes,
        // but she signs with her own key, not Alice's.
        let alice = Creditor::new();
        let carol = Creditor::new();

        let forged = sign(&carol.secret_key, &alice.uuid, manifest()).unwrap();

        assert!(!alice.verifies(&manifest(), &forged));
    }

    #[test]
    fn test_malformed_keys_and_signatures_are_refused() {
        let alice = Creditor::new();
        let signature = alice.sign(&manifest());

        assert!(!alice.verifies(&manifest(), &[]));
        assert!(!alice.verifies(&manifest(), &signature[1..]));

        for key in [Vec::new(), vec![0; 3], vec![0; 32]] {
            assert!(!verify_one_time_expense(
                alice.uuid.clone(),
                key,
                manifest(),
                signature.clone(),
            ));
        }
    }
}
