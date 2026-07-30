//! Generation of one-time and last-resort key packages.

use mls_rs::extension::MlsExtension;
use mls_rs::extension::recommended::LastResortKeyPackageExt;
use mls_rs::{Client, ExtensionList};

use crate::cryptography::mls::{MlsError, config::DuckCountMlsConfig, types::KeyPackageBundle};

/// Largest batch of one-time key packages the DuckCount API accepts in a single
/// publication. Larger requests are rejected outright, so the batch is clamped
/// here rather than left to fail at the network layer.
pub const MAX_ONE_TIME_KEY_PACKAGES_PER_PUBLICATION: u32 = 100;

/// Generates a bundle of key packages for publication.
///
/// The bundle carries one **last-resort** key package, marked with the
/// extension that tells the server it may be handed out repeatedly, plus
/// `one_time_count` ordinary key packages that are each consumed once. Peers
/// receive a one-time package while any remain; once the pool is empty the
/// server falls back to the last-resort package, whose reuse weakens forward
/// secrecy on that first message until the group's next commit. Republishing
/// rotates the last-resort package and refills the pool, so clients should do
/// it regularly rather than once.
///
/// Generating a key package is not free, each one holds a fresh ML-KEM key
/// pair whose secret is stored locally, so a few dozen at a time, topped up as
/// they are consumed, suits a mobile client better than the maximum.
///
/// # Arguments
///
/// * `client` - The MLS client whose identity the key packages assert.
/// * `one_time_count` - How many one-time key packages to generate. Values
///   above [`MAX_ONE_TIME_KEY_PACKAGES_PER_PUBLICATION`] are clamped to it.
///
/// # Returns
///
/// * `Result<KeyPackageBundle, MlsError>` - The key packages to publish.
///
/// # Errors
///
/// * `MlsError::ProtocolFailed` - If key package generation or serialisation fails.
/// * `MlsError::InvalidKeyPackage` - If the last-resort extension cannot be encoded.
/// * `MlsError::StorageFailed` - If the generated secrets cannot be stored.
pub fn generate_key_packages(
    client: &Client<DuckCountMlsConfig>,
    one_time_count: u32,
) -> Result<KeyPackageBundle, MlsError> {
    let last_resort_extensions: ExtensionList = vec![
        LastResortKeyPackageExt
            .into_extension()
            .map_err(|_| MlsError::InvalidKeyPackage)?,
    ]
    .into();

    let last_resort_key_package = client
        .generate_key_package_message(last_resort_extensions, ExtensionList::default(), None)?
        .to_bytes()?;

    let one_time_count = one_time_count.min(MAX_ONE_TIME_KEY_PACKAGES_PER_PUBLICATION);

    let one_time_key_packages = (0..one_time_count)
        .map(|_| {
            client
                .generate_key_package_message(
                    ExtensionList::default(),
                    ExtensionList::default(),
                    None,
                )?
                .to_bytes()
                .map_err(MlsError::from)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(KeyPackageBundle {
        last_resort_key_package,
        one_time_key_packages,
    })
}
