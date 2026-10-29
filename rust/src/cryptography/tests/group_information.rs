#[cfg(test)]
mod tests {
    use mls_rs_core::crypto::{SignaturePublicKey, SignatureSecretKey};
    use uuid::Uuid;

    use crate::cryptography::mls::config::generate_signature_key_pair;
    use crate::cryptography::mls::group_information::{
        self, GroupInformation, sign, verify_group_information,
    };
    use crate::cryptography::mls::one_time_expense;
    use crate::cryptography::mls::sign_content::{self, labelled};

    struct Owner {
        uuid: String,
        secret_key: SignatureSecretKey,
        public_key: SignaturePublicKey,
    }

    impl Owner {
        fn new() -> Self {
            let (secret_key, public_key) = generate_signature_key_pair().unwrap();

            Owner {
                uuid: Uuid::new_v4().to_string(),
                secret_key,
                public_key,
            }
        }

        fn sign(&self, information: &GroupInformation) -> Vec<u8> {
            sign(&self.secret_key, &self.uuid, information.clone()).unwrap()
        }

        fn verifies(&self, information: &GroupInformation, signature: &[u8]) -> bool {
            verify_group_information(
                self.uuid.clone(),
                self.public_key.to_vec(),
                information.clone(),
                signature.to_vec(),
            )
        }

        /// Signs `information` as this owner the way it is signed, but under
        /// `label`.
        fn sign_labelled(&self, label: &[u8], information: &GroupInformation) -> Vec<u8> {
            let signed = labelled(label, &self.uuid, information).unwrap();

            sign_content::sign(&self.secret_key, &signed).unwrap()
        }
    }

    /// One way of tampering with a signed version.
    type Change = fn(&mut GroupInformation);

    fn information() -> GroupInformation {
        GroupInformation {
            group_uuid: "0b4f1a0e-5c3d-8e2a-9f61-7d2c4b8a1e05".to_string(),
            revision: 3,
            title: "Lisbon trip".to_string(),
            description: "Flights, the flat and dinners".to_string(),
            currency_uuid: "6e0f4c2a-8b1d-4f3e-a5c7-2d9b1e8f0a64".to_string(),
        }
    }

    #[test]
    fn test_a_signed_version_verifies() {
        let alice = Owner::new();
        let information = information();

        let signature = alice.sign(&information);

        assert!(alice.verifies(&information, &signature));
    }

    #[test]
    fn test_a_version_without_a_description_verifies() {
        let alice = Owner::new();
        let mut information = information();
        information.description = String::new();

        let signature = alice.sign(&information);

        assert!(alice.verifies(&information, &signature));
    }

    #[test]
    fn test_any_change_to_a_signed_version_is_refused() {
        let alice = Owner::new();
        let signature = alice.sign(&information());

        let changes: Vec<(&str, Change)> = vec![
            ("another group", |i| {
                i.group_uuid = Uuid::new_v4().to_string()
            }),
            ("an older revision", |i| i.revision = 2),
            ("a newer revision", |i| i.revision = 4),
            ("the title", |i| i.title = "Porto trip".to_string()),
            ("the title emptied", |i| i.title = String::new()),
            ("the description", |i| i.description.push('!')),
            ("the currency", |i| {
                i.currency_uuid = Uuid::new_v4().to_string()
            }),
            ("the title and description swapped", |i| {
                std::mem::swap(&mut i.title, &mut i.description)
            }),
            ("a word moved from the title to the description", |i| {
                i.title = "Lisbon".to_string();
                i.description = " tripFlights, the flat and dinners".to_string();
            }),
        ];

        for (change, apply) in changes {
            let mut changed = information();
            apply(&mut changed);

            assert!(
                !alice.verifies(&changed, &signature),
                "{change} must not verify"
            );
        }
    }

    #[test]
    fn test_a_version_is_refused_under_another_owner() {
        let alice = Owner::new();
        let signature = alice.sign(&information());

        // The server naming someone else as the owner, with Alice's key.
        assert!(!verify_group_information(
            Uuid::new_v4().to_string(),
            alice.public_key.to_vec(),
            information(),
            signature,
        ));
    }

    #[test]
    fn test_a_member_cannot_sign_for_the_owner() {
        // Carol holds the group key and so can seal any version she likes,
        // but she signs with her own key, not Alice's.
        let alice = Owner::new();
        let carol = Owner::new();

        let forged = sign(&carol.secret_key, &alice.uuid, information()).unwrap();

        assert!(!alice.verifies(&information(), &forged));
    }

    #[test]
    fn test_a_one_time_expense_signature_does_not_pass_for_a_version() {
        let alice = Owner::new();
        let information = information();

        // The very bytes a version is signed over, labelled as a version, as a
        // one-time expense and as a settled mark: only the first one verifies.
        assert!(alice.verifies(
            &information,
            &alice.sign_labelled(group_information::LABEL, &information),
        ));

        for label in [
            one_time_expense::LABEL,
            one_time_expense::SETTLED_MARK_LABEL,
        ] {
            assert!(!alice.verifies(&information, &alice.sign_labelled(label, &information)));
        }
    }

    #[test]
    fn test_malformed_keys_and_signatures_are_refused() {
        let alice = Owner::new();
        let signature = alice.sign(&information());

        assert!(!alice.verifies(&information(), &[]));
        assert!(!alice.verifies(&information(), &signature[1..]));

        for key in [Vec::new(), vec![0; 3], vec![0; 32]] {
            assert!(!verify_group_information(
                alice.uuid.clone(),
                key,
                information(),
                signature.clone(),
            ));
        }
    }
}
