#[cfg(test)]
mod tests {
    use crate::algorithm::currency::{Currency, CurrencyError};

    #[test]
    fn test_create_currency_with_subunit() {
        let _currency = Currency::new("Euro", "€", true).unwrap();
    }

    #[test]
    fn test_create_currency_without_subunit() {
        let _currency = Currency::new("Euro", "€", false).unwrap();
    }

    #[test]
    fn test_currency_name_too_short() {
        let currency = Currency::new("", "€", true).unwrap_err();

        assert_eq!(currency, CurrencyError::NameLengthInvalid);
    }

    #[test]
    fn test_currency_name_too_long() {
        let currency = Currency::new("TheGreatEuropeanCurrency", "€", true).unwrap_err();

        assert_eq!(currency, CurrencyError::NameLengthInvalid);
    }

    #[test]
    fn test_currency_symbol_too_short() {
        let currency = Currency::new("Euro", "", true).unwrap_err();

        assert_eq!(currency, CurrencyError::SymbolLengthInvalid);
    }

    #[test]
    fn test_currency_symbol_too_long() {
        let currency = Currency::new("Euro", "€€€€€", true).unwrap_err();

        assert_eq!(currency, CurrencyError::SymbolLengthInvalid);
    }
}
