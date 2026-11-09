# 🦆 Lib DuckCount

A Rust library for **shared expense management** and **secure cryptographic utilities**, designed for use in the **DuckCount app**.

## 🎯 Features

### **Expense Management**
- **Track Expenses**: Easily add and manage expenses among users.
- **Flexible Shares**: Split an expense evenly, name a beneficiary's share as an amount, set it as a percentage of the amount, or weigh it against the others (2, 1 and 1 of 100 is 50, 25 and 25), in any mix. Shares are rounded so that they always add up to the amount exactly.
- **One Amount Format**: Every amount the library hands out is `12` in a currency without a subunit and `12.00` in one with, and `validate_expense` takes no other: `canonical_amount` writes an amount that way before it is sealed, padded then to `sealed_amount_length()` so that the server cannot read its size from its length.
- **Calculate Debts**: Automatically calculate net debts for each user.
- **Equilibrate Transactions**: Determine the optimal set of transactions to settle debts.
- **Deterministic Calculations**: Ensure consistent and predictable results using UUIDs for tie-breaking.

### **Cryptography & Security**
- **🔒 Secure Authentication**: Tools for user authentication using the OPAQUE protocol.
- **🪪 Usernames**: Turn a handle into the digest the server knows it by, hashed with **SHA3-512** under a domain separator. A *discovery* username is normalized and validated first (trimmed, lowercased, ASCII letters and digits only, starting with a letter) and hashed under `duckcount:discovery-username:v1:`; a *login* username is an opaque credential identifier, normalized and validated first (trimmed, lowercased, ASCII letters and digits only, starting with a letter), and hashed under `duckcount:login-username:v1:`. The distinct domains keep the same handle from ever producing the same digest for both purposes. Algorithm and domain strings are wire protocol: every client must reproduce them exactly.
- **👥 End-to-End Encrypted Groups**: Group messaging built on **MLS** (RFC 9420, via `mls-rs`), used to distribute per-expense keys. The server relays Welcomes, Commits, and application messages as opaque ciphertext and holds no group secrets. The one exception is a member rejoining a group after a log-out: the GroupInfo another member exports for them, and the Commit they rejoin with, travel in the clear (MLS sends every Commit from outside a group that way), which shows the server the group's public tree, its members' UUIDs and public keys, and nothing it could read the group with.
- **🛡️ Post-Quantum Confidentiality**: MLS groups run on the **ML-KEM-768 + X25519** hybrid cipher suite, so traffic captured today stays private even against a future quantum adversary. It is the only suite enabled, which makes a downgrade impossible.
- **📌 Identity Pinning**: Each member's signature key is pinned to their user UUID on first contact and any later change is refused, so the server cannot substitute its own key for a peer's. Two users verify each other out of band with their safety number: sixty digits each device builds from both users' UUIDs, its own user's key and the key it pinned for the other user, so the two devices show the same digits only when neither pin was substituted. A member rejoining after a log-out takes a GroupInfo only when it is signed by a member whose key it pinned, by one nothing is pinned for under the key the host recorded for them in that group while it held it (`VouchedMember`), or by their own key, and every member takes nothing from outside the group but a member's resync of their own leaf under the signature key it already held, so neither the server nor anybody it hands a GroupInfo to can seat a key of its own.
- **🔑 Symmetric Key Encryption**: Encrypt and decrypt data using symmetric keys.
- **🗄️ Encrypted Vault & Secure Server Storage**: Tools for securely storing and managing encrypted data using zero-access encryption.
- **🔄 Deterministic & Non-Deterministic Encryption**: Support for both deterministic and non-deterministic encryption methods.
- **🔑 Password Generation**: Generate strong, random passwords.
- **🔐 Key Derivation**: Securely derive cryptographic keys from passwords.

## ⚠️ Important Notes

- **UUIDs**: We recommend using only UUID version 4 or 7 for expense calculations, as they are used as tie-breakers and provide the necessary uniqueness and randomness.
- **Security**: This crate uses industry-standard cryptographic algorithms and best practices for secure data handling. All sensitive data is securely stored on the server using zero-access encryption.
- **MLS state**: MLS group state and key package secrets are persisted by the host through the `MlsStore` callback interface. Every record is sealed with AES-256-GCM under a key derived from the user's vault secret before it leaves this crate, and is bound to the slot it is stored in, so the host never holds usable group secrets. A log-out empties it: the user's signature key comes back from the vault, and each group comes back through an RFC 9420 resync, an external commit removing the leaf the user had and seating a new one under the same UUID and signature key, built from a GroupInfo another member exports on request (`MlsGroup::rejoin_group_info`, `MlsClient::rejoin_group`). Any member may rejoin, and the members of the group stay the same.
- **Build prerequisites**: The post-quantum cipher suite comes from `aws-lc-sys`, which needs **CMake** on `PATH` to cross-compile for Android and iOS. The `bindgen` feature is enabled for those targets because AWS-LC ships no pre-generated bindings for them.
- **Audits**: No third-party audit has been conducted yet, but the crate relies on trusted and audited libraries for cryptography.
- **Vulnerability Reporting**: To report vulnerabilities, please contact us at **[security@duckcount.com](mailto:security@duckcount.com)**.

## 🛠️ Usage

### Expense Management Example

```rust
use lib_duckcount::algorithm::{beneficiary::Beneficiary, currency::Currency, expense::{Expense, compute_beneficiaries}, group::Group};

use std::{collections::HashMap, sync::Arc};
use uuid::Uuid;

fn main() {
    let alice_uuid = Uuid::new_v4().to_string();
    let bob_uuid = Uuid::new_v4().to_string();
    let charlie_uuid = Uuid::new_v4().to_string();

    let currency = Currency::new("Euro", "€", true).unwrap();
    let users_uuid = vec![alice_uuid.clone(), bob_uuid.clone(), charlie_uuid.clone()];
    let group = Group::new(&currency, &users_uuid, &vec![]).unwrap();

    let amount = "100.00";
    
    let beneficiary_uuids = vec![bob_uuid.clone(), charlie_uuid.clone()];
    
    let mut fixed_shares = HashMap::new();
    fixed_shares.insert(bob_uuid.clone(), String::from("50.00"));
    
    let beneficiaries =
        compute_beneficiaries(amount, &currency, &beneficiary_uuids, &fixed_shares, &HashMap::new(), &HashMap::new())
            .unwrap();

    let expense = Expense::new(&alice_uuid, amount, &currency, &beneficiaries).unwrap();
    let group = group.with_added_expense(Arc::new(expense)).unwrap();

    let net_debts = group.calculate_net_debts_per_user().unwrap();
    for (user_uuid, debt) in net_debts {
        println!("User {} has a net debt of {}", user_uuid, debt);
    }

    let transactions = group.calculate_transactions_to_equilibrate().unwrap();
    for transaction in transactions {
        println!("{} owes {} to {}", transaction.debtor_uuid, transaction.amount, transaction.creditor_uuid);
    }
}
```

### Cryptography Examples

*(For cryptographic usage examples, please refer to the doc code)*

## 📚 Documentation

The library is fully documented with functional and tested doc code.

## 📃 License

This project is licensed under the **European Union Public License (EUPL)** - see the [LICENSE](LICENSE) file for details.
