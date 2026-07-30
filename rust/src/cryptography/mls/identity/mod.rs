//! Who a group member actually is.
//!
//! MLS itself takes no position on which signature key belongs to which user;
//! that is delegated to an identity provider. DuckCount members are identified
//! by their user UUID, carried in a basic credential, and bound to a signature
//! key by trust on first use. See [`pinning_provider`] for why the binding
//! matters and [`fingerprint`] for how a user can check it by hand.

pub mod credential;
pub mod fingerprint;
pub mod pinning_provider;
pub mod signature_key;
