#[cfg(test)]
mod tests {
    use crate::algorithm::beneficiary::Beneficiary;
    use uuid::Uuid;

    #[test]
    fn test_beneficiary_new() {
        let user_id = Uuid::new_v4().to_string();
        let share = Some(String::from("50.00"));
        let beneficiary = Beneficiary::new(&user_id, share.clone());

        assert_eq!(beneficiary.user_id, user_id);
        assert_eq!(beneficiary.share, share);
    }
}
