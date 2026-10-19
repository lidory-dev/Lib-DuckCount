#[cfg(test)]
mod tests {
    use crate::cryptography::mls::identity::fingerprint::{fingerprint, safety_number};

    /// A UUID lower than [`HIGHER_UUID`], so the order of the halves is known.
    const LOWER_UUID: &str = "01234567-89ab-4cde-8f01-23456789abcd";

    const HIGHER_UUID: &str = "fedcba98-7654-4321-8fed-cba987654321";

    /// Sorts after [`HIGHER_KEY`], and renders with [`LOWER_UUID`] a
    /// fingerprint that sorts after the higher user's, so putting the halves
    /// in the order of the keys or of the fingerprints renders another number
    /// than putting them in the order of the UUIDs.
    const LOWER_KEY: &[u8] = b"the lower user's signature public key";

    const HIGHER_KEY: &[u8] = b"the higher user's signature public key";

    /// The safety number of the shared vector, as seen from the lower user's
    /// device.
    fn number() -> String {
        safety_number(LOWER_UUID, LOWER_KEY, HIGHER_UUID, HIGHER_KEY)
    }

    /// The two halves of a safety number: the fingerprint of the lower UUID,
    /// then the one of the higher.
    fn halves(safety_number: &str) -> (&str, &str) {
        let (lower, higher) = safety_number.split_at(35);

        (lower, higher.trim_start())
    }

    #[test]
    fn test_both_sides_render_the_same_number() {
        assert_eq!(
            safety_number(HIGHER_UUID, HIGHER_KEY, LOWER_UUID, LOWER_KEY),
            number()
        );
    }

    #[test]
    fn test_a_safety_number_is_twelve_groups_of_five_digits() {
        let number = number();
        let groups = number.split(' ').collect::<Vec<_>>();

        assert_eq!(groups.len(), 12);
        assert!(groups.iter().all(|group| {
            group.len() == 5 && group.chars().all(|character| character.is_ascii_digit())
        }));
    }

    #[test]
    fn test_the_halves_follow_the_order_of_the_uuids() {
        let lower = fingerprint(LOWER_UUID, LOWER_KEY);
        let higher = fingerprint(HIGHER_UUID, HIGHER_KEY);

        // Ordered by key or by fingerprint, the higher UUID's half would come
        // first.
        assert!(LOWER_KEY > HIGHER_KEY);
        assert!(lower > higher);

        // On both devices, the lower UUID's half comes first.
        assert_eq!(number(), format!("{lower} {higher}"));
        assert_eq!(
            safety_number(HIGHER_UUID, HIGHER_KEY, LOWER_UUID, LOWER_KEY),
            format!("{lower} {higher}")
        );
    }

    /// What a man in the middle substituting one user's key on the other
    /// user's device would look like: only the half of the user he passed his
    /// key off as differs, and the half he left alone still matches, which
    /// tells the two users whose key was substituted.
    #[test]
    fn test_another_key_changes_only_its_own_half() {
        let man_in_the_middle_key = b"the man in the middle's key".as_slice();

        let real = number();
        let (real_lower, real_higher) = halves(&real);

        // The higher user's key, substituted on the lower user's device.
        let substituted = safety_number(LOWER_UUID, LOWER_KEY, HIGHER_UUID, man_in_the_middle_key);
        let (lower, higher) = halves(&substituted);

        assert_eq!(lower, real_lower);
        assert_ne!(higher, real_higher);

        // The lower user's key, substituted on the higher user's device.
        let substituted = safety_number(HIGHER_UUID, HIGHER_KEY, LOWER_UUID, man_in_the_middle_key);
        let (lower, higher) = halves(&substituted);

        assert_ne!(lower, real_lower);
        assert_eq!(higher, real_higher);
    }

    #[test]
    fn test_the_number_changes_with_either_key_or_either_uuid() {
        let other_uuid = "0fedcba9-8765-4432-8fed-cba987654321";
        let other_key = b"another signature key".as_slice();

        let variants = [
            safety_number(other_uuid, LOWER_KEY, HIGHER_UUID, HIGHER_KEY),
            safety_number(LOWER_UUID, other_key, HIGHER_UUID, HIGHER_KEY),
            safety_number(LOWER_UUID, LOWER_KEY, other_uuid, HIGHER_KEY),
            safety_number(LOWER_UUID, LOWER_KEY, HIGHER_UUID, other_key),
        ];

        for variant in variants {
            assert_ne!(variant, number());
        }
    }

    /// The digits vouch for whom a key is bound to, not just for the key.
    #[test]
    fn test_the_same_key_bound_to_another_user_renders_another_fingerprint() {
        assert_ne!(
            fingerprint(LOWER_UUID, LOWER_KEY),
            fingerprint(HIGHER_UUID, LOWER_KEY)
        );
    }

    /// Without the length prefixes, both identities would hash the same bytes.
    #[test]
    fn test_moving_bytes_between_the_uuid_and_the_key_renders_another_fingerprint() {
        assert_ne!(fingerprint("ab", b"c"), fingerprint("a", b"bc"));
    }

    /// Pins the encoding both devices must reproduce, the order of the halves
    /// included. Changing it silently would leave every user who verified a
    /// contact looking at a number that no longer matches the one they marked.
    #[test]
    fn test_safety_number_known_answer() {
        assert_eq!(
            number(),
            "95006 99813 14865 14424 12827 08161 76732 68463 29070 36260 62956 56594"
        );
    }
}
