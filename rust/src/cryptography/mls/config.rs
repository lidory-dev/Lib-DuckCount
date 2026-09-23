//! The one MLS configuration DuckCount clients run.
//!
//! mls-rs clients are generic over their providers, which is convenient in Rust
//! and impossible across a uniffi boundary. [`DuckCountMlsConfig`] pins every
//! provider so a client can be held in a struct field and handed to Kotlin.
//!
//! Every deviation from mls-rs's defaults below is deliberate; the comments say
//! why, because the defaults are reasonable and a future reader should not
//! "restore" them by accident.

use std::time::Duration;

use mls_rs::client_builder::{
    BaseConfig, PaddingMode, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo,
};
use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rules::{CommitOptions, DefaultMlsRules, EncryptionOptions};
use mls_rs::{Client, CryptoProvider};
use mls_rs_core::crypto::SignatureSecretKey;
use mls_rs_crypto_awslc::AwsLcCryptoProvider;

use crate::cryptography::mls::{
    CIPHER_SUITE, MlsError,
    identity::pinning_provider::PinningIdentityProvider,
    storage::{group_state::SealedGroupStateStorage, key_package::SealedKeyPackageStorage},
};

/// How long a generated key package stays valid.
///
/// A key package a peer picks up after expiry is refused, so this is the
/// longest a client may go without republishing. Ninety days is long enough
/// that an infrequently used install still works and short enough that an
/// abandoned key package stops being usable within a season.
const KEY_PACKAGE_LIFETIME: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// The fully resolved provider set of a DuckCount MLS client.
///
/// The pre-shared key slot keeps its in-memory default: DuckCount never injects
/// external PSKs, so nothing is ever stored there.
pub type DuckCountMlsConfig = WithIdentityProvider<
    PinningIdentityProvider,
    WithCryptoProvider<
        AwsLcCryptoProvider,
        WithGroupStateStorage<
            SealedGroupStateStorage,
            WithKeyPackageRepo<SealedKeyPackageStorage, BaseConfig>,
        >,
    >,
>;

/// The crypto provider, restricted to the single supported cipher suite.
///
/// Restriction is the point. `AwsLcCryptoProvider::new()` would also enable the
/// classical suites, and a client that supports them can be steered onto one by
/// a peer, losing post-quantum confidentiality without anything visibly going
/// wrong. With only [`CIPHER_SUITE`] enabled, a downgrade attempt fails instead.
pub fn crypto_provider() -> AwsLcCryptoProvider {
    AwsLcCryptoProvider::with_enabled_cipher_suites(vec![CIPHER_SUITE])
}

/// The protocol rules every DuckCount client applies.
pub fn mls_rules() -> DefaultMlsRules {
    let commit_options = CommitOptions::new()
        // The server stores no ratchet tree, so it has to travel with the
        // Welcome. This is already the mls-rs default; it is set explicitly
        // because turning it off would silently break every join.
        .with_ratchet_tree_extension(true)
        // The DuckCount API takes one Welcome *per* invited member
        // (`InvitedGroupMember`), so the single fan-out Welcome that mls-rs
        // produces by default cannot be addressed to anyone.
        .with_single_welcome_message(false)
        // An add-only commit may skip the update path under RFC 9420. Requiring
        // it costs one extra public key operation per commit in groups this
        // small, and buys post-compromise security on every commit rather than
        // only on those that happen to include a path.
        .with_path_required(true)
        // Nobody joins a DuckCount group without an invitation.
        .with_allow_external_commit(false);

    let encryption_options = EncryptionOptions::new(
        // Commits and proposals travel as PrivateMessage rather than the
        // default PublicMessage.
        true,
        // Pad message lengths, so the relayed ciphertext size stops being a
        // side channel for the content it carries.
        PaddingMode::StepFunction,
    );

    DefaultMlsRules::new()
        .with_commit_options(commit_options)
        .with_encryption_options(encryption_options)
}

/// Assembles a client from an identity and the storage adapters backing it.
///
/// # Arguments
///
/// * `signing_identity` - The user's credential and signature public key.
/// * `signer` - The matching signature private key.
/// * `key_packages` - Storage for the secrets behind published key packages.
/// * `group_states` - Storage for group state and retained prior epochs.
/// * `identity_provider` - The pinning provider validating other members.
///
/// # Returns
///
/// * `Client<DuckCountMlsConfig>` - A client ready to create or join groups.
pub fn build_client(
    signing_identity: SigningIdentity,
    signer: SignatureSecretKey,
    key_packages: SealedKeyPackageStorage,
    group_states: SealedGroupStateStorage,
    identity_provider: PinningIdentityProvider,
) -> Client<DuckCountMlsConfig> {
    Client::builder()
        .key_package_repo(key_packages)
        .group_state_storage(group_states)
        .crypto_provider(crypto_provider())
        .identity_provider(identity_provider)
        .mls_rules(mls_rules())
        .key_package_lifetime(KEY_PACKAGE_LIFETIME)
        .signing_identity(signing_identity, signer, CIPHER_SUITE)
        .build()
}

/// The primitives of [`CIPHER_SUITE`]: its signatures, hashes and AEAD.
///
/// # Errors
///
/// * `MlsError::ProtocolFailed` - If the cipher suite is unavailable.
pub fn cipher_suite_provider()
-> Result<<AwsLcCryptoProvider as CryptoProvider>::CipherSuiteProvider, MlsError> {
    crypto_provider()
        .cipher_suite_provider(CIPHER_SUITE)
        .ok_or_else(|| {
            MlsError::ProtocolFailed("The configured cipher suite is unavailable.".to_string())
        })
}

/// Generates a fresh signature key pair for the configured cipher suite.
///
/// # Returns
///
/// * `Result<(SignatureSecretKey, mls_rs_core::crypto::SignaturePublicKey), MlsError>` -
///   The new key pair.
///
/// # Errors
///
/// * `MlsError::ProtocolFailed` - If the cipher suite is unavailable or key
///   generation fails.
pub fn generate_signature_key_pair()
-> Result<(SignatureSecretKey, mls_rs_core::crypto::SignaturePublicKey), MlsError> {
    use mls_rs::CipherSuiteProvider;

    cipher_suite_provider()?
        .signature_key_generate()
        .map_err(|error| MlsError::ProtocolFailed(error.to_string()))
}
