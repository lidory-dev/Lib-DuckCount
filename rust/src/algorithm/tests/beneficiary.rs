#[cfg(test)]
mod tests {
    use crate::algorithm::beneficiary::Beneficiary;
    use uuid::Uuid;

    #[test]
    fn test_beneficiary_new() {
        let user_uuid = Uuid::new_v4().to_string();
        let share = "50.00";
        let beneficiary = Beneficiary::new(&user_uuid, share);

        assert_eq!(beneficiary.user_uuid, user_uuid);
        assert_eq!(beneficiary.share, share);
        assert_eq!(beneficiary.share_percentage, None);
    }

    #[test]
    fn test_beneficiary_with_percentage() {
        let user_uuid = Uuid::new_v4().to_string();
        let beneficiary = Beneficiary::with_percentage(&user_uuid, "25.00", "25");

        assert_eq!(beneficiary.user_uuid, user_uuid);
        assert_eq!(beneficiary.share, "25.00");
        assert_eq!(beneficiary.share_percentage.as_deref(), Some("25"));
    }
}
