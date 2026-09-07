use sha3::{Digest, Sha3_512};

/// Hashes `value` under `domain` with SHA3-512, hexadecimal encoded.
///
/// The domain separator is what keeps digests minted for one purpose from ever
/// colliding with digests minted for another over the same input, so every caller
/// passes one and no caller passes the empty string.
///
/// The output is always 128 lowercase hexadecimal characters; a caller that only
/// needs part of it truncates the result rather than the digest.
pub(crate) fn hash_with_domain(domain: &str, value: &[u8]) -> String {
    let mut hasher = Sha3_512::new();

    hasher.update(domain.as_bytes());
    hasher.update(value);

    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
