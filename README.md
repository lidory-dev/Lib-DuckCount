# 🦆 Lib DuckCount

A Rust library for **shared expense management** and **secure cryptographic utilities**, designed for use in the **DuckCount app**.

## 🎯 Features

### **Expense Management**
- **Track Expenses**: Easily add and manage expenses among users.
- **Calculate Debts**: Automatically calculate net debts for each user.
- **Equilibrate Transactions**: Determine the optimal set of transactions to settle debts.
- **Deterministic Calculations**: Ensure consistent and predictable results using UUIDs for tie-breaking.

### **Cryptography & Security**
- **🔒 Secure Authentication**: Tools for user authentication using the OPAQUE protocol.
- **🔑 Symmetric Key Encryption**: Encrypt and decrypt data using symmetric keys.
- **🗄️ Encrypted Vault & Secure Server Storage**: Tools for securely storing and managing encrypted data using zero-access encryption.
- **🔄 Deterministic & Non-Deterministic Encryption**: Support for both deterministic and non-deterministic encryption methods.
- **🔑 Password Generation**: Generate strong, random passwords.
- **🔐 Key Derivation**: Securely derive cryptographic keys from passwords.

## ⚠️ Important Notes

- **UUIDs**: We recommend using only UUID version 4 or 7 for expense calculations, as they are used as tie-breakers and provide the necessary uniqueness and randomness.
- **Security**: This crate uses industry-standard cryptographic algorithms and best practices for secure data handling. All sensitive data is securely stored on the server using zero-access encryption.
- **Audits**: No third-party audit has been conducted yet, but the crate relies on trusted and audited libraries for cryptography.
- **Vulnerability Reporting**: To report vulnerabilities, please contact us at **[security@duckcount.com](mailto:security@duckcount.com)**.

## 🛠️ Usage

### Expense Management Example

```rust
use lib_duckcount::algorithm::{beneficiary::Beneficiary, expense::Expense, group::Group};
use uuid::Uuid;

fn main() {
    let group = Group::new();

    let alice_id = Uuid::new_v4().to_string();
    let bob_id = Uuid::new_v4().to_string();
    let charlie_id = Uuid::new_v4().to_string();

    let group = group.with_added_user(&alice_id);
    let group = group.with_added_user(&bob_id);
    let group = group.with_added_user(&charlie_id);

    let beneficiaries = vec![
        Beneficiary::new(&bob_id, Some(String::from("50.0"))),
        Beneficiary::new(&charlie_id, None),
    ];

    let expense = Expense::new(&alice_id, &String::from("100.0"), beneficiaries).unwrap();
    let group = group.with_added_expense(&expense);

    let net_debts = group.calculate_net_debts_per_user().unwrap();
    for (user_id, debt) in net_debts {
        println!("User {} has a net debt of {:.2}", user_id, debt);
    }

    let transactions = group.calculate_transactions_to_equilibrate().unwrap();
    for transaction in transactions {
        println!("{} owes {:.2} to {}", transaction.debtor_id, transaction.amount, transaction.creditor_id);
    }
}
```

### Cryptography Examples

*(For cryptographic usage examples, please refer to the doc code)*

## 📚 Documentation

The library is fully documented with functional and tested doc code.

## 📃 License

This project is licensed under the **European Union Public License (EUPL)** - see the [LICENSE](LICENSE) file for details.
