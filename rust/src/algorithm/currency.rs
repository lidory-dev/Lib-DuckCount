use thiserror::Error;

pub const CURRENCY_NAME_LENGHT: usize = 20;

#[derive(Debug, Clone, uniffi::Record)]
pub struct Currency {
    pub name: String,
    pub symbol: String,
    pub has_sub_unit: bool,
}

/// Represents possible errors that can occur when creating a currency.
#[derive(Error, Debug, PartialEq, uniffi::Error)]
pub enum CurrencyError {
    /// The name is too short or too long. It should be between 1 and 20 characters.
    #[error("The name should be between 1 and 20 characters.")]
    NameLengthInvalid,
    /// The symbol is too short or too long. It should be exactly one character.
    #[error("The symbol should be a single character.")]
    SymbolLengthInvalid,
}

impl Currency {
    /// Creates a new [Currency].
    ///
    /// This constructor initializes a [Currency] with the given name, symbol and if it has a subunit.
    ///
    /// # Arguments
    ///
    /// * `name` - The name of the currency.
    /// * `symbol` - The symbol that represents the currency.
    /// * `has_sub_unit` - If the currency has a subunit or not.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use lib_duckcount::algorithm::currency::Currency;
    ///
    /// let currency = Currency::new("Euro", "€", true).unwrap();
    /// ```
    pub fn new(name: &str, symbol: &str, has_sub_unit: bool) -> Result<Self, CurrencyError> {
        if !(1..CURRENCY_NAME_LENGHT + 1).contains(&name.chars().count()) {
            return Err(CurrencyError::NameLengthInvalid);
        }

        if symbol.chars().count() != 1 {
            return Err(CurrencyError::SymbolLengthInvalid);
        }

        Ok(Self {
            name: name.to_owned(),
            symbol: symbol.to_owned(),
            has_sub_unit,
        })
    }
}
