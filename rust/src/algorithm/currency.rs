use bigdecimal::{BigDecimal, RoundingMode};
use thiserror::Error;

pub const CURRENCY_NAME_LENGHT: usize = 20;
pub const CURRENCY_SYMBOL_LENGTH: usize = 4;

#[derive(PartialEq, Eq, Debug, Clone, uniffi::Object)]
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
    /// The symbol is too short or too long. It should be between 1 and 4 characters.
    #[error("The symbol should be between 1 and 4 characters.")]
    SymbolLengthInvalid,
}

impl Currency {
    /// How many digits an amount in this currency has after its decimal point. For now, if the
    /// currency has a subunit, we consider it to be cents.
    pub(crate) fn subunit_digits(&self) -> i64 {
        match self.has_sub_unit {
            true => 2,
            false => 0,
        }
    }

    /// `amount` written the one way the library hands an amount out and takes one to validate:
    /// `12` in a currency without a subunit, and `12.00` in a currency with one.
    pub(crate) fn write_amount(&self, amount: &BigDecimal) -> String {
        amount
            .with_scale_round(self.subunit_digits(), RoundingMode::HalfUp)
            .to_plain_string()
    }
}

#[uniffi::export]
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
    #[uniffi::constructor]
    pub fn new(name: &str, symbol: &str, has_sub_unit: bool) -> Result<Self, CurrencyError> {
        if !(1..CURRENCY_NAME_LENGHT + 1).contains(&name.chars().count()) {
            return Err(CurrencyError::NameLengthInvalid);
        }

        if !(1..CURRENCY_SYMBOL_LENGTH + 1).contains(&symbol.chars().count()) {
            return Err(CurrencyError::SymbolLengthInvalid);
        }

        Ok(Self {
            name: name.to_owned(),
            symbol: symbol.to_owned(),
            has_sub_unit,
        })
    }
}
