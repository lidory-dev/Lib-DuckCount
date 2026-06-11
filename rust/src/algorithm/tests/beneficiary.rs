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
    }
}
