//! The one MLS configuration DuckCount clients run.
//!
//! mls-rs clients are generic over their providers, which is convenient in Rust
//! and impossible across a uniffi boundary. [`DuckCountMlsConfig`] pins every
//! provider so a client can be held in a struct field and handed to Kotlin.
//!
//! Every deviation from mls-rs's defaults below is deliberate; the comments say
//! why, because the defaults are reasonable and a future reader should not
//! "restore" them by accident.

use std::cell::RefCell;
use std::time::Duration;

use mls_rs::client_builder::{
    BaseConfig, PaddingMode, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
    WithKeyPackageRepo, WithMlsRules,
};
use mls_rs::group::{GroupContext, Roster};
use mls_rs::identity::SigningIdentity;
use mls_rs::mls_rules::{
    CommitDirection, CommitOptions, CommitSource, EncryptionOptions, ProposalBundle,
};
use mls_rs::{Client, CryptoProvider, MlsRules};
use mls_rs_core::crypto::SignatureSecretKey;
use mls_rs_crypto_awslc::AwsLcCryptoProvider;

use crate::cryptography::mls::{
    CIPHER_SUITE, MlsError,
    identity::{credential::user_uuid_from, pinning_provider::PinningIdentityProvider},
    storage::{group_state::SealedGroupStateStorage, key_package::SealedKeyPackageStorage},
};

/// How long a generated key package stays valid.
///
/// A key package a peer picks up after expiry is refused, so this is the
/// longest a client may go without republishing. Ninety days is long enough
/// that an infrequently used install still works and short enough that an
/// abandoned key package stops being usable within a season.
pub(crate) const KEY_PACKAGE_LIFETIME: Duration = Duration::from_secs(90 * 24 * 60 * 60);

/// How long the secrets of a key package are kept once it has expired.
///
/// No peer builds a Welcome from an expired key package, since the commit that
/// adds the user checks its lifetime, but one built just before expiry can
/// still be on its way: a DuckCount peer keeps attaching a Welcome to what it
/// sends for up to a week, and it then waits on the server for as long as the
/// host leaves it unread. So the host prunes only once it has read everything
/// waiting for it, and this only has to cover what can still arrive after
/// that, the week a Welcome is attached and any difference between the two
/// clocks, which ninety days does many times over. Older ones are deleted by
/// [`MlsClient::prune_key_packages`](crate::cryptography::mls::client::MlsClient::prune_key_packages).
pub(crate) const KEY_PACKAGE_RETENTION_AFTER_EXPIRY: Duration =
    Duration::from_secs(90 * 24 * 60 * 60);

/// The fully resolved provider set of a DuckCount MLS client.
///
/// The pre-shared key slot keeps its in-memory default: DuckCount never injects
/// external PSKs, so nothing is ever stored there.
pub type DuckCountMlsConfig = WithMlsRules<
    DuckCountMlsRules,
    WithIdentityProvider<
        PinningIdentityProvider,
        WithCryptoProvider<
            AwsLcCryptoProvider,
            WithGroupStateStorage<
                SealedGroupStateStorage,
                WithKeyPackageRepo<SealedKeyPackageStorage, BaseConfig>,
            >,
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
pub fn mls_rules() -> DuckCountMlsRules {
    let commit_options = CommitOptions::new()
        // The server stores no ratchet tree, so it has to travel with the
        // Welcome. This is already the mls-rs default; it is set explicitly
        // because turning it off would silently break every join.
        .with_ratchet_tree_extension(true)
        // One Welcome for every member a commit adds, which the DuckCount API
        // delivers once to each of them. This is the mls-rs default; it is set
        // explicitly because a Welcome per member carries the whole ratchet
        // tree each time, some 15 MB of Welcomes for a group of a hundred,
        // where the one Welcome is under 300 KB.
        .with_single_welcome_message(true)
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

    DuckCountMlsRules {
        commit_options,
        encryption_options,
    }
}

/// The protocol rules of [`mls_rules`]: the options it sets, and on receipt,
/// the one member the host allows to commit, see `with_allowed_committer`.
#[derive(Clone, Debug)]
pub struct DuckCountMlsRules {
    commit_options: CommitOptions,
    encryption_options: EncryptionOptions,
}

impl MlsRules for DuckCountMlsRules {
    type Error = MlsError;

    /// Refuses a received Commit from anybody but the member allowed to
    /// commit, if the host named one, and lets every other Commit through as
    /// it is, as mls-rs's own rules do.
    ///
    /// mls-rs asks this once it has authenticated the Commit, and before it
    /// checks anything the Commit carries: the identity of each member it
    /// adds or updates above all, which the identity provider checks against
    /// the keys pinned for them. A member who may not commit would otherwise
    /// choose which error the Commit is refused with, and whom it names: an
    /// `IdentityKeyMismatch` for a contact of the receiver, say, which tells
    /// of a key that contact never changed.
    fn filter_proposals(
        &self,
        direction: CommitDirection,
        source: CommitSource,
        _current_roster: &Roster,
        _current_context: &GroupContext,
        proposals: ProposalBundle,
    ) -> Result<ProposalBundle, MlsError> {
        // A Commit from outside the group comes as a PublicMessage, which
        // `MlsGroup::process_incoming_message` refuses before mls-rs reads it.
        if direction == CommitDirection::Receive
            && let CommitSource::ExistingMember(committer) = &source
            && let Some(allowed_committer) = ALLOWED_COMMITTER.with_borrow(Clone::clone)
            && user_uuid_from(&committer.signing_identity.credential)? != allowed_committer
        {
            return Err(MlsError::UnauthorizedChange);
        }

        Ok(proposals)
    }

    fn commit_options(
        &self,
        _new_roster: &Roster,
        _new_context: &GroupContext,
        _proposals: &ProposalBundle,
    ) -> Result<CommitOptions, MlsError> {
        Ok(self.commit_options)
    }

    fn encryption_options(
        &self,
        _current_roster: &Roster,
        _current_context: &GroupContext,
    ) -> Result<EncryptionOptions, MlsError> {
        Ok(self.encryption_options)
    }
}

thread_local! {
    /// The only member whose Commits the group this thread is processing a
    /// message for applies, if the host named one, see
    /// [`with_allowed_committer`].
    static ALLOWED_COMMITTER: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// Runs `process`, which processes a message, refusing a Commit from anybody
/// but `allowed_committer`, a user UUID, if given, see
/// [`DuckCountMlsRules::filter_proposals`].
///
/// mls-rs hands its rules the group and the Commit and nothing more, and the
/// client holds a single copy of them for every group. They run within the
/// group's `process_incoming_message`, though, on the thread that called it,
/// so a committer kept for that thread while `process` runs reaches that
/// message and no other.
pub(crate) fn with_allowed_committer<T>(
    allowed_committer: Option<String>,
    process: impl FnOnce() -> T,
) -> T {
    /// Puts back the committer there was, however `process` ends.
    struct Restore(Option<String>);

    impl Drop for Restore {
        fn drop(&mut self) {
            ALLOWED_COMMITTER.set(self.0.take());
        }
    }

    let _restore = Restore(ALLOWED_COMMITTER.replace(allowed_committer));

    process()
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
