use crate::contain::ContainStrategy;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const RULES_PUBLIC_KEY: &str =
    "c9c3a749405430b178ce968485a3a335c02b67cc28ee7dbccc4f32c853a313e5";

/// Runtime (unsigned) settings kept separate from the signature-protected
/// threat rules, so changing them does not require re-signing rules.json.
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct RuntimeConfig {
    pub default_action: Option<String>, // "quarantine" or "delete"
    pub downloads_dir: Option<String>,
    /// When true (default), a mining-port connection is only alerted on unless
    /// an additional signal (blacklisted IP or suspicious temp path) is present.
    pub miner_detection_require_secondary_signal: Option<bool>,
    /// How detected malicious processes are contained before being killed:
    /// "auto" (cgroup v2 freezer, SIGSTOP fallback), "cgroup", "sigstop", or
    /// "off" (legacy immediate-kill, no freezing).
    pub process_containment: Option<String>,
}

/// Locates and loads the runtime config, preferring in order:
/// $FERROSHIELD_CONFIG, ./config.json, /etc/ferroshield/config.json,
/// then legacy rules.json "settings" (development fallback).
pub fn load_runtime_config() -> RuntimeConfig {
    let candidates = std::env::var("FERROSHIELD_CONFIG")
        .map(PathBuf::from)
        .into_iter()
        .chain([
            PathBuf::from("config.json"),
            PathBuf::from("/etc/ferroshield/config.json"),
        ]);

    let mut cfg = RuntimeConfig::default();
    for path in candidates {
        if path.exists()
            && let Ok(content) = std::fs::read_to_string(&path)
            && let Ok(parsed) = serde_json::from_str::<RuntimeConfig>(&content)
        {
            cfg = parsed;
            break;
        }
    }
    cfg
}

/// Returns the effective default action, falling back to legacy rules.json settings.
pub fn effective_default_action(runtime: &RuntimeConfig, rules: &RulesConfig) -> String {
    if let Some(action) = &runtime.default_action {
        return action.clone();
    }
    rules
        .settings
        .as_ref()
        .and_then(|s| s.default_action.clone())
        .unwrap_or_else(|| "quarantine".to_string())
}

/// Returns the effective downloads dir, falling back to legacy rules.json settings.
pub fn effective_downloads_dir(runtime: &RuntimeConfig, rules: &RulesConfig) -> Option<String> {
    if runtime.downloads_dir.is_some() {
        runtime.downloads_dir.clone()
    } else {
        rules
            .settings
            .as_ref()
            .and_then(|s| s.downloads_dir.clone())
    }
}

/// Resolves the process-containment strategy from the runtime config
/// (defaults to `Auto`: cgroup v2 freezer with SIGSTOP fallback).
pub fn effective_contain_strategy(runtime: &RuntimeConfig) -> ContainStrategy {
    runtime
        .process_containment
        .as_deref()
        .map(ContainStrategy::from_str)
        .unwrap_or(ContainStrategy::Auto)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Hashes {
    pub sha256: Option<String>,
    pub md5: Option<String>,
    pub tlsh: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Signatures {
    pub hashes: Option<Hashes>,
    pub patterns: Option<Vec<String>>,
    pub extension_ids: Option<Vec<String>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Rule {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    pub signatures: Signatures,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Settings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_action: Option<String>, // "quarantine" or "delete"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub downloads_dir: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkBlacklist {
    pub ips: Vec<String>,
    pub domains: Vec<String>,
}

impl NetworkBlacklist {
    /// Builds an indexed runtime representation with O(1) IP lookups and
    /// efficient subdomain suffix matching.
    pub fn to_fast(&self) -> FastBlacklist {
        FastBlacklist::new(self)
    }
}

/// Runtime representation of the network blacklist optimized for hot-path lookups.
#[derive(Debug, Clone, Default)]
pub struct FastBlacklist {
    pub ips: std::collections::HashSet<String>,
    pub domains: std::collections::HashSet<String>,
}

impl FastBlacklist {
    pub fn new(blacklist: &NetworkBlacklist) -> Self {
        let ips: std::collections::HashSet<String> = blacklist.ips.iter().cloned().collect();
        let domains: std::collections::HashSet<String> = blacklist
            .domains
            .iter()
            .map(|d| d.trim().trim_end_matches('.').to_lowercase())
            .filter(|d| !d.is_empty() && d.contains('.'))
            .collect();
        Self { ips, domains }
    }

    pub fn contains_ip(&self, ip: &str) -> bool {
        self.ips.contains(ip)
    }

    pub fn match_domain(&self, host: &str) -> Option<String> {
        let host = host.trim().trim_end_matches('.').to_lowercase();
        if host.is_empty() {
            return None;
        }
        let mut current = host.as_str();
        loop {
            if self.domains.contains(current) {
                return Some(current.to_string());
            }
            match current.find('.') {
                Some(idx) => {
                    current = &current[idx + 1..];
                }
                None => break,
            }
        }
        None
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RulesConfig {
    pub settings: Option<Settings>,
    pub rules: Vec<Rule>,
    pub network_blacklist: NetworkBlacklist,
    /// Expected SHA-256 of the eBPF object file, recorded in the signed
    /// rules.json so the loader refuses tampered modules. Absent on legacy files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ebpf_sha256: Option<String>,
    /// Expected SHA-256 of rules.yar, recorded in the signed rules.json so the
    /// YARA ruleset cannot be silently replaced. Absent on legacy files.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules_yar_sha256: Option<String>,
}

fn decode_hex(s: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
        })
        .collect()
}

/// Loads the Ed25519 public key, preferring a `rules.pub` file next to the rules
/// file or in /etc/ferroshield, and falling back to the compiled-in key.
fn load_public_key(rules_path: &Path) -> Result<VerifyingKey, Box<dyn std::error::Error>> {
    let mut candidates = Vec::new();
    let dir = rules_path.parent().unwrap_or_else(|| Path::new("."));
    candidates.push(dir.join("rules.pub"));
    candidates.push(PathBuf::from("/etc/ferroshield/rules.pub"));

    for candidate in candidates {
        if candidate.exists()
            && let Ok(content) = std::fs::read_to_string(&candidate)
        {
            let hex = content.trim();
            if let Ok(bytes) = decode_hex(hex)
                && bytes.len() == 32
            {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return VerifyingKey::from_bytes(&arr)
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);
            }
        }
    }

    let pub_key_bytes = decode_hex(RULES_PUBLIC_KEY)?;
    let mut pub_key_arr = [0u8; 32];
    pub_key_arr.copy_from_slice(&pub_key_bytes);
    VerifyingKey::from_bytes(&pub_key_arr).map_err(|e| Box::new(e) as Box<dyn std::error::Error>)
}

/// Generates a fresh Ed25519 keypair and writes rules.key (private, 0400)
/// and rules.pub (public, 0400) into the given directory.
pub fn gen_rules_keypair<P: AsRef<Path>>(
    dir: P,
) -> Result<(PathBuf, PathBuf), Box<dyn std::error::Error>> {
    use rand::RngCore;
    use std::os::unix::fs::PermissionsExt;

    let dir = dir.as_ref();
    std::fs::create_dir_all(dir)?;

    let mut secret = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut secret);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let verifying_key = signing_key.verifying_key();

    let key_path = dir.join("rules.key");
    let pub_path = dir.join("rules.pub");
    std::fs::write(&key_path, secret)?;
    std::fs::write(&pub_path, hex_encode(&verifying_key.to_bytes()))?;

    let mut key_perms = std::fs::metadata(&key_path)?.permissions();
    key_perms.set_mode(0o400);
    std::fs::set_permissions(&key_path, key_perms)?;
    let mut pub_perms = std::fs::metadata(&pub_path)?.permissions();
    pub_perms.set_mode(0o400);
    std::fs::set_permissions(&pub_path, pub_perms)?;

    Ok((key_path, pub_path))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn verify_rules_signature<P: AsRef<Path>>(
    rules_path: P,
) -> Result<(), Box<dyn std::error::Error>> {
    let rules_path = rules_path.as_ref();
    let sig_path = PathBuf::from(format!("{}.sig", rules_path.to_string_lossy()));

    if !rules_path.exists() {
        return Err(format!("Rules file not found: {:?}", rules_path).into());
    }
    if !sig_path.exists() {
        return Err(format!("Signature file not found: {:?}", sig_path).into());
    }

    let rules_bytes = std::fs::read(rules_path)?;
    let sig_bytes = std::fs::read(sig_path)?;

    let public_key = load_public_key(rules_path)?;

    let mut sig_arr = [0u8; 64];
    if sig_bytes.len() != 64 {
        return Err("Signature file must be exactly 64 bytes".into());
    }
    sig_arr.copy_from_slice(&sig_bytes);
    let signature = Signature::from_bytes(&sig_arr);

    public_key.verify(&rules_bytes, &signature)?;
    Ok(())
}

pub fn sign_rules<P: AsRef<Path>>(
    rules_path: P,
    key_path: P,
) -> Result<(), Box<dyn std::error::Error>> {
    let rules_path = rules_path.as_ref();
    let key_path = key_path.as_ref();
    let rules_bytes = std::fs::read(rules_path)?;
    let key_bytes = std::fs::read(key_path)?;

    let mut key_arr = [0u8; 32];
    if key_bytes.len() != 32 {
        return Err("Private key file must be exactly 32 bytes".into());
    }
    key_arr.copy_from_slice(&key_bytes);

    let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_arr);
    let signature = ed25519_dalek::Signer::sign(&signing_key, &rules_bytes);

    let sig_path = PathBuf::from(format!("{}.sig", rules_path.to_string_lossy()));
    std::fs::write(sig_path, signature.to_bytes())?;
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    let mut hasher = Sha256::new();
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Records the SHA-256 of the eBPF object file into the `ebpf_sha256` field of
/// rules.json so the loader can refuse tampered kernel modules. The first
/// existing candidate path is used; when none exists the field is cleared. The
/// resulting rules.json still needs to be signed afterwards (`sign_rules`).
pub fn update_ebpf_sha256_in_rules<P: AsRef<Path>>(
    rules_path: P,
    ebpf_candidates: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error>> {
    let rules_path = rules_path.as_ref();
    let mut config: RulesConfig = serde_json::from_str(&std::fs::read_to_string(rules_path)?)?;
    config.ebpf_sha256 = None;
    for candidate in ebpf_candidates {
        if candidate.exists() {
            config.ebpf_sha256 = Some(sha256_file(candidate)?);
            break;
        }
    }
    std::fs::write(rules_path, serde_json::to_string_pretty(&config)?)?;
    Ok(())
}

/// Records the SHA-256 of rules.yar into the `rules_yar_sha256` field of
/// rules.json so the YARA ruleset cannot be replaced undetected. The first
/// existing candidate path is used; when none exists the field is cleared.
pub fn update_rules_yar_sha256_in_rules<P: AsRef<Path>>(
    rules_path: P,
    rules_yar_candidates: &[PathBuf],
) -> Result<(), Box<dyn std::error::Error>> {
    let rules_path = rules_path.as_ref();
    let mut config: RulesConfig = serde_json::from_str(&std::fs::read_to_string(rules_path)?)?;
    config.rules_yar_sha256 = None;
    for candidate in rules_yar_candidates {
        if candidate.exists() {
            config.rules_yar_sha256 = Some(sha256_file(candidate)?);
            break;
        }
    }
    std::fs::write(rules_path, serde_json::to_string_pretty(&config)?)?;
    Ok(())
}

/// Locates rules.json, preferring ./rules.json (current working directory) and
/// falling back to the installed location /etc/ferroshield/rules.json. Mirrors
/// the resolution used for config.json so subcommands work from any directory.
pub fn resolve_rules_path() -> PathBuf {
    let cwd = PathBuf::from("rules.json");
    if cwd.exists() {
        cwd
    } else {
        PathBuf::from("/etc/ferroshield/rules.json")
    }
}

pub fn load_rules<P: AsRef<Path>>(path: P) -> Result<RulesConfig, Box<dyn std::error::Error>> {
    let path_ref = path.as_ref();
    verify_rules_signature(path_ref)?;

    let mut file = File::open(path_ref)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let config: RulesConfig = serde_json::from_str(&contents)?;
    Ok(config)
}

/// Loads and validates rules from disk, updating the shared thread-safe config
/// and the scanner's derived hash/TLSH indexes atomically only when verification
/// succeeds. If loading or signature verification fails, the existing config and
/// scanner indexes remain active (fail-safe).
pub fn reload_rules<P: AsRef<Path>>(
    path: P,
    rules_lock: &std::sync::RwLock<RulesConfig>,
    scanner_lock: &std::sync::RwLock<crate::scanner::Scanner>,
) -> Result<RulesConfig, Box<dyn std::error::Error>> {
    let new_config = load_rules(path)?;
    {
        let mut guard = rules_lock
            .write()
            .map_err(|e| format!("Gagal mendapatkan write lock rules: {}", e))?;
        *guard = new_config.clone();
    }
    {
        let mut scanner_guard = scanner_lock
            .write()
            .map_err(|e| format!("Gagal mendapatkan write lock scanner: {}", e))?;
        scanner_guard.update_rules(new_config.rules.clone());
    }
    Ok(new_config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferroshield_test_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const SAMPLE_RULES: &str = r#"{
        "settings": { "default_action": "quarantine" },
        "rules": [],
        "network_blacklist": { "ips": [], "domains": [] }
    }"#;

    #[test]
    fn test_gen_keypair_writes_valid_files() {
        let dir = temp_dir("keypair");
        let (key_path, pub_path) = gen_rules_keypair(&dir).unwrap();

        let key_bytes = fs::read(&key_path).unwrap();
        assert_eq!(key_bytes.len(), 32, "private key must be raw 32 bytes");

        let pub_hex = fs::read_to_string(&pub_path).unwrap();
        assert_eq!(pub_hex.trim().len(), 64, "public key must be 64 hex chars");
        assert!(decode_hex(pub_hex.trim()).unwrap().len() == 32);

        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o400, "private key must be 0400");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_sign_and_verify_with_rules_pub_override() {
        let dir = temp_dir("signverify");
        let rules_path = dir.join("rules.json");
        fs::write(&rules_path, SAMPLE_RULES).unwrap();

        let (key_path, _) = gen_rules_keypair(&dir).unwrap();

        // Sign then verify: default key discovery must find rules.pub next to rules.json.
        sign_rules(&rules_path, &key_path).unwrap();
        verify_rules_signature(&rules_path).unwrap();

        // A tampered rules file must fail verification.
        fs::write(&rules_path, "{\"tampered\": true}").unwrap();
        assert!(verify_rules_signature(&rules_path).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_update_ebpf_sha256_in_rules_records_and_clears() {
        let dir = temp_dir("ebpfhash");
        let rules_path = dir.join("rules.json");
        fs::write(&rules_path, SAMPLE_RULES).unwrap();
        let ebpf_path = dir.join("module.o");
        fs::write(&ebpf_path, b"some eBPF object bytes").unwrap();

        // Records the hash of the found object.
        update_ebpf_sha256_in_rules(&rules_path, &[dir.join("missing.o"), ebpf_path.clone()])
            .unwrap();
        let config: RulesConfig =
            serde_json::from_str(&fs::read_to_string(&rules_path).unwrap()).unwrap();
        let recorded = config.ebpf_sha256.unwrap();
        assert_eq!(recorded.len(), 64);

        // Recomputing must yield the same value (stable signing input).
        update_ebpf_sha256_in_rules(&rules_path, std::slice::from_ref(&ebpf_path)).unwrap();
        let config: RulesConfig =
            serde_json::from_str(&fs::read_to_string(&rules_path).unwrap()).unwrap();
        assert_eq!(config.ebpf_sha256.as_deref(), Some(recorded.as_str()));

        // No candidate found -> field cleared instead of keeping a stale hash.
        update_ebpf_sha256_in_rules(&rules_path, &[dir.join("nope.o")]).unwrap();
        let config: RulesConfig =
            serde_json::from_str(&fs::read_to_string(&rules_path).unwrap()).unwrap();
        assert_eq!(config.ebpf_sha256, None);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_update_rules_yar_sha256_in_rules_records_and_clears() {
        let dir = temp_dir("yaryarhash");
        let rules_path = dir.join("rules.json");
        fs::write(&rules_path, SAMPLE_RULES).unwrap();
        let yar_path = dir.join("rules.yar");
        fs::write(&yar_path, b"rule dummy { condition: false }").unwrap();

        update_rules_yar_sha256_in_rules(&rules_path, std::slice::from_ref(&yar_path)).unwrap();
        let config: RulesConfig =
            serde_json::from_str(&fs::read_to_string(&rules_path).unwrap()).unwrap();
        let recorded = config.rules_yar_sha256.unwrap();
        assert_eq!(recorded.len(), 64);

        // Missing candidate -> field cleared (no stale hash kept).
        update_rules_yar_sha256_in_rules(&rules_path, &[dir.join("nope.yar")]).unwrap();
        let config: RulesConfig =
            serde_json::from_str(&fs::read_to_string(&rules_path).unwrap()).unwrap();
        assert_eq!(config.rules_yar_sha256, None);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_runtime_config_prefers_env() {
        let dir = temp_dir("runtimecfg");
        let cfg_path = dir.join("config.json");
        fs::write(
            &cfg_path,
            r#"{"default_action": "delete", "downloads_dir": "/tmp/dl"}"#,
        )
        .unwrap();

        // SAFETY: test-only env mutation, single-threaded test.
        unsafe {
            std::env::set_var("FERROSHIELD_CONFIG", &cfg_path);
        }
        let cfg = load_runtime_config();
        // SAFETY: test-only env mutation, single-threaded test.
        unsafe {
            std::env::remove_var("FERROSHIELD_CONFIG");
        }

        assert_eq!(cfg.default_action.as_deref(), Some("delete"));
        assert_eq!(cfg.downloads_dir.as_deref(), Some("/tmp/dl"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_effective_default_action_falls_back_to_legacy() {
        let runtime = RuntimeConfig::default();
        let rules: RulesConfig = serde_json::from_str(
            r#"{"settings": {"default_action": "delete"}, "rules": [], "network_blacklist": {"ips": [], "domains": []}}"#,
        ).unwrap();
        assert_eq!(effective_default_action(&runtime, &rules), "delete");

        let rules_empty: RulesConfig = serde_json::from_str(
            r#"{"settings": null, "rules": [], "network_blacklist": {"ips": [], "domains": []}}"#,
        )
        .unwrap();
        assert_eq!(
            effective_default_action(&runtime, &rules_empty),
            "quarantine"
        );
    }

    #[test]
    fn test_reload_rules_updates_shared_rwlock_on_valid_signature() {
        use std::sync::{Arc, RwLock};

        let dir = temp_dir("reload_valid");
        let rules_path = dir.join("rules.json");
        let (key_path, _) = gen_rules_keypair(&dir).unwrap();

        let rules_v1 = r#"{
            "settings": { "default_action": "quarantine" },
            "rules": [],
            "network_blacklist": { "ips": ["1.1.1.1"], "domains": ["evil.com"] }
        }"#;
        fs::write(&rules_path, rules_v1).unwrap();
        sign_rules(&rules_path, &key_path).unwrap();

        let loaded_v1 = load_rules(&rules_path).unwrap();
        let shared_config = Arc::new(RwLock::new(loaded_v1));
        let scanner = crate::scanner::Scanner::without_yara(vec![], 0);
        let shared_scanner = Arc::new(RwLock::new(scanner));

        // Verify initial state (Version A)
        {
            let guard = shared_config.read().unwrap();
            assert_eq!(guard.network_blacklist.ips, vec!["1.1.1.1"]);
            assert_eq!(guard.network_blacklist.domains, vec!["evil.com"]);
        }

        // Update file to Version B with a valid signature
        let rules_v2 = r#"{
            "settings": { "default_action": "delete" },
            "rules": [],
            "network_blacklist": { "ips": ["2.2.2.2", "3.3.3.3"], "domains": ["malware.org"] }
        }"#;
        fs::write(&rules_path, rules_v2).unwrap();
        sign_rules(&rules_path, &key_path).unwrap();

        // Perform reload
        let reload_result = reload_rules(&rules_path, &shared_config, &shared_scanner);
        assert!(reload_result.is_ok());

        // Verify that the shared config now reflects Version B
        {
            let guard = shared_config.read().unwrap();
            assert_eq!(guard.network_blacklist.ips, vec!["2.2.2.2", "3.3.3.3"]);
            assert_eq!(guard.network_blacklist.domains, vec!["malware.org"]);
            assert_eq!(
                guard.settings.as_ref().unwrap().default_action.as_deref(),
                Some("delete")
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reload_rules_invalid_signature_preserves_previous_config() {
        use std::sync::{Arc, RwLock};

        let dir = temp_dir("reload_invalid");
        let rules_path = dir.join("rules.json");
        let (key_path, _) = gen_rules_keypair(&dir).unwrap();

        let rules_v1 = r#"{
            "settings": { "default_action": "quarantine" },
            "rules": [],
            "network_blacklist": { "ips": ["1.1.1.1"], "domains": ["evil.com"] }
        }"#;
        fs::write(&rules_path, rules_v1).unwrap();
        sign_rules(&rules_path, &key_path).unwrap();

        let loaded_v1 = load_rules(&rules_path).unwrap();
        let shared_config = Arc::new(RwLock::new(loaded_v1));
        let scanner = crate::scanner::Scanner::without_yara(vec![], 0);
        let shared_scanner = Arc::new(RwLock::new(scanner));

        // Overwrite rules.json with Version B without re-signing (invalid signature for new content)
        let rules_v2 = r#"{
            "settings": { "default_action": "delete" },
            "rules": [],
            "network_blacklist": { "ips": ["9.9.9.9"], "domains": ["hacked.net"] }
        }"#;
        fs::write(&rules_path, rules_v2).unwrap();

        // Perform reload, expect failure
        let reload_result = reload_rules(&rules_path, &shared_config, &shared_scanner);
        assert!(reload_result.is_err());

        // Verify that the shared config is still Version A (unchanged)
        {
            let guard = shared_config.read().unwrap();
            assert_eq!(guard.network_blacklist.ips, vec!["1.1.1.1"]);
            assert_eq!(guard.network_blacklist.domains, vec!["evil.com"]);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_reload_rules_updates_scanner_index_e2e() {
        use sha2::{Digest, Sha256};
        use std::sync::{Arc, RwLock};

        let dir = temp_dir("scanner_reload_e2e");
        let rules_path = dir.join("rules.json");
        let (key_path, _) = gen_rules_keypair(&dir).unwrap();

        // Create a test file to scan
        let target_file = dir.join("sample_malware.bin");
        fs::write(&target_file, b"malicious binary payload version B").unwrap();

        // Calculate SHA-256 of target_file
        let mut hasher = Sha256::new();
        hasher.update(b"malicious binary payload version B");
        let target_sha256 = format!("{:x}", hasher.finalize());

        // Version A: rules list is empty
        let rules_v1 = r#"{
            "settings": { "default_action": "quarantine" },
            "rules": [],
            "network_blacklist": { "ips": [], "domains": [] }
        }"#;
        fs::write(&rules_path, rules_v1).unwrap();
        sign_rules(&rules_path, &key_path).unwrap();

        let loaded_v1 = load_rules(&rules_path).unwrap();
        let shared_config = Arc::new(RwLock::new(loaded_v1));
        let scanner = crate::scanner::Scanner::without_yara(vec![], 0);
        let shared_scanner = Arc::new(RwLock::new(scanner));

        // Before reload: scanning target_file must NOT detect anything
        {
            let scanner_guard = shared_scanner.read().unwrap();
            let scan_res = scanner_guard.scan_file(&target_file);
            assert!(
                scan_res.is_none(),
                "Target file must not be detected under Version A rules"
            );
        }

        // Version B: contains a rule with target_sha256
        let rules_v2 = format!(
            r#"{{
                "settings": {{ "default_action": "quarantine" }},
                "rules": [
                    {{
                        "id": "RULE-TEST-V2",
                        "name": "Test Rule V2",
                        "description": "Detects payload via SHA256",
                        "severity": "Critical",
                        "signatures": {{
                            "hashes": {{
                                "sha256": "{}",
                                "md5": null,
                                "tlsh": null
                            }},
                            "patterns": null,
                            "extension_ids": null
                        }}
                    }}
                ],
                "network_blacklist": {{ "ips": [], "domains": [] }}
            }}"#,
            target_sha256
        );
        fs::write(&rules_path, rules_v2).unwrap();
        sign_rules(&rules_path, &key_path).unwrap();

        // Reload rules and scanner atomically
        let reload_res = reload_rules(&rules_path, &shared_config, &shared_scanner);
        assert!(reload_res.is_ok());

        // After reload: scanning target_file MUST detect the rule via updated scanner index
        {
            let scanner_guard = shared_scanner.read().unwrap();
            let scan_res = scanner_guard.scan_file(&target_file);
            assert!(
                scan_res.is_some(),
                "Target file must be detected after reload to Version B"
            );
            let result = scan_res.unwrap();
            assert_eq!(result.triggered_rules.len(), 1);
            assert_eq!(result.triggered_rules[0].id, "RULE-TEST-V2");
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
