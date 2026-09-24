use crate::model::DependencyRecord;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha512};
use std::time::Duration;

const MAX_ARTIFACT_BYTES: usize = 64 * 1024 * 1024;

pub fn npm_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(true)
        .max_redirects(0)
        .timeout_global(Some(Duration::from_secs(30)))
        .build()
        .new_agent()
}

pub fn download_npm(agent: &ureq::Agent, dependency: &DependencyRecord) -> Result<Vec<u8>, String> {
    if dependency.ecosystem != "npm" {
        return Err(format!(
            "online artifact inspection supports npm only; skipped {} ({})",
            dependency.name, dependency.ecosystem
        ));
    }
    let url = dependency
        .resolved
        .as_deref()
        .ok_or_else(|| format!("{} has no exact resolved artifact URL", dependency.name))?;
    if !is_allowed_registry_url(url) {
        return Err(format!(
            "{} resolved URL is outside the HTTPS npm registry allowlist",
            dependency.name
        ));
    }
    let integrity = dependency
        .integrity
        .as_deref()
        .ok_or_else(|| format!("{} has no lockfile integrity value", dependency.name))?;
    let response = agent
        .get(url)
        .call()
        .map_err(|error| format!("download failed for {}: {error}", dependency.name))?;
    let bytes = response
        .into_body()
        .with_config()
        .limit((MAX_ARTIFACT_BYTES + 1) as u64)
        .read_to_vec()
        .map_err(|error| format!("cannot read artifact for {}: {error}", dependency.name))?;
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(format!(
            "{} artifact exceeds {MAX_ARTIFACT_BYTES} byte limit",
            dependency.name
        ));
    }
    verify_integrity(&bytes, integrity)
        .map_err(|error| format!("{} artifact integrity failed: {error}", dependency.name))?;
    Ok(bytes)
}

fn is_allowed_registry_url(url: &str) -> bool {
    url.starts_with("https://registry.npmjs.org/")
        && !url.bytes().any(|byte| matches!(byte, b'?' | b'#' | b'\\'))
        && !url.chars().any(char::is_control)
}

pub fn verify_integrity(bytes: &[u8], integrity: &str) -> Result<(), String> {
    let candidates = integrity
        .split_ascii_whitespace()
        .filter_map(|token| token.strip_prefix("sha512-"))
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return Err("lockfile has no supported sha512 integrity token".to_owned());
    }
    let digest = Sha512::digest(bytes);
    for candidate in candidates {
        if candidate.contains('?') {
            continue;
        }
        let expected = STANDARD
            .decode(candidate)
            .map_err(|_| "malformed sha512 integrity token".to_owned())?;
        if expected.as_slice() == digest.as_slice() {
            return Ok(());
        }
    }
    Err("downloaded bytes do not match any sha512 integrity token".to_owned())
}

#[cfg(test)]
mod tests {
    use super::verify_integrity;
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use sha2::{Digest, Sha512};

    #[test]
    fn verifies_lockfile_integrity_before_archive_inspection() {
        let content = b"inert package bytes";
        let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(content)));
        assert!(verify_integrity(content, &integrity).is_ok());
        assert!(verify_integrity(b"different bytes", &integrity).is_err());
        assert!(verify_integrity(content, "sha1-deadbeef").is_err());
    }

    #[test]
    fn rejects_untrusted_artifact_hosts_and_redirect_targets() {
        for url in [
            "http://registry.npmjs.org/pkg.tgz",
            "https://registry.npmjs.org.evil.test/pkg.tgz",
            "https://user@registry.npmjs.org/pkg.tgz",
            "https://registry.npmjs.org/pkg.tgz?redirect=https://evil.test",
        ] {
            assert!(!super::is_allowed_registry_url(url), "accepted {url}");
        }
        assert!(super::is_allowed_registry_url(
            "https://registry.npmjs.org/@scope/pkg/-/pkg-1.0.0.tgz"
        ));
    }
}
