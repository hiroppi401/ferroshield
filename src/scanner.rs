use crate::config::Rule;
use md5::Context as Md5Context;
use regex::bytes::Regex as BytesRegex;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use walkdir::WalkDir;
use yara_x::{Compiler, Rules as YaraRules, ScanError, Scanner as YaraScanner};

/// Per-scan timeout for the YARA engine. Third-party rulesets can contain
/// regexes with pathological backtracking (ReDoS); this bounds the time a
/// single file may spend in YARA so a bad rule cannot stall Browser Guard or
/// the scan daemon.
const YARA_SCAN_TIMEOUT: Duration = Duration::from_millis(1000);

/// Logs the YARA timeout warning only once per process to avoid flooding logs.
static YARA_TIMEOUT_LOGGED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub struct ScanResult {
    pub file_path: String,
    pub triggered_rules: Vec<Rule>,
}

type RuleIndexes = (
    Vec<(String, BytesRegex)>,
    HashMap<String, Arc<Rule>>,
    HashMap<String, Arc<Rule>>,
    Vec<(tlsh_fixed::Tlsh, Arc<Rule>)>,
);

fn build_rule_indexes(rules: &[Arc<Rule>]) -> RuleIndexes {
    use std::str::FromStr;

    let mut compiled_regexes = Vec::new();
    let mut sha256_index = HashMap::new();
    let mut md5_index = HashMap::new();
    let mut tlsh_rules = Vec::new();

    for rule in rules {
        if let Some(ref patterns) = rule.signatures.patterns {
            for pattern in patterns {
                if let Ok(re) = BytesRegex::new(pattern) {
                    compiled_regexes.push((rule.id.clone(), re));
                }
            }
        }
        if let Some(ref hashes) = rule.signatures.hashes {
            if let Some(ref sha) = hashes.sha256 {
                let s = sha.trim().to_lowercase();
                if !s.is_empty() {
                    sha256_index.insert(s, Arc::clone(rule));
                }
            }
            if let Some(ref md5_hash) = hashes.md5 {
                let m = md5_hash.trim().to_lowercase();
                if !m.is_empty() {
                    md5_index.insert(m, Arc::clone(rule));
                }
            }
            if let Some(ref tlsh_str) = hashes.tlsh
                && let Ok(tlsh) = tlsh_fixed::Tlsh::from_str(tlsh_str.trim())
            {
                tlsh_rules.push((tlsh, Arc::clone(rule)));
            }
        }
    }

    (compiled_regexes, sha256_index, md5_index, tlsh_rules)
}

#[derive(Clone)]
pub struct Scanner {
    rules: Vec<Arc<Rule>>,
    compiled_regexes: Vec<(String, BytesRegex)>, // (rule_id, compiled_regex)
    sha256_index: HashMap<String, Arc<Rule>>,
    md5_index: HashMap<String, Arc<Rule>>,
    tlsh_rules: Vec<(tlsh_fixed::Tlsh, Arc<Rule>)>,
    yara_rules: Option<Arc<YaraRules>>,
    throttle_ms: u64,
}

impl Scanner {
    pub fn new(
        rules: Vec<Rule>,
        throttle_ms: u64,
        expected_rules_yar_sha256: Option<&str>,
    ) -> Self {
        let arc_rules: Vec<Arc<Rule>> = rules.into_iter().map(Arc::new).collect();
        let (compiled_regexes, sha256_index, md5_index, tlsh_rules) =
            build_rule_indexes(&arc_rules);

        // Attempt to load and compile rules.yar if it exists
        let yara_rules = if Path::new("rules.yar").exists() {
            // Verify rules.yar integrity against the hash recorded in the signed
            // rules.json. A mismatch disables YARA with a clear warning instead
            // of silently accepting a tampered ruleset.
            if !yara_ruleset_integrity_ok(expected_rules_yar_sha256) {
                None
            } else {
                let mut compiler = Compiler::new();
                if let Ok(content) = std::fs::read_to_string("rules.yar") {
                    if compiler.add_source(content.as_str()).is_ok() {
                        Some(Arc::new(compiler.build()))
                    } else {
                        eprintln!("[-] Gagal kompilasi rules.yar");
                        None
                    }
                } else {
                    None
                }
            }
        } else {
            None
        };

        Self {
            rules: arc_rules,
            compiled_regexes,
            sha256_index,
            md5_index,
            tlsh_rules,
            yara_rules,
            throttle_ms,
        }
    }

    /// Rebuilds all derived hash, TLSH, and regex indexes when rules are reloaded.
    pub fn update_rules(&mut self, rules: Vec<Rule>) {
        let arc_rules: Vec<Arc<Rule>> = rules.into_iter().map(Arc::new).collect();
        let (compiled_regexes, sha256_index, md5_index, tlsh_rules) =
            build_rule_indexes(&arc_rules);
        self.rules = arc_rules;
        self.compiled_regexes = compiled_regexes;
        self.sha256_index = sha256_index;
        self.md5_index = md5_index;
        self.tlsh_rules = tlsh_rules;
    }

    #[cfg(test)]
    pub fn sha256_index(&self) -> &HashMap<String, Arc<Rule>> {
        &self.sha256_index
    }

    #[cfg(test)]
    pub fn md5_index(&self) -> &HashMap<String, Arc<Rule>> {
        &self.md5_index
    }

    #[cfg(test)]
    pub fn tlsh_rules(&self) -> &[(tlsh_fixed::Tlsh, Arc<Rule>)] {
        &self.tlsh_rules
    }

    /// Constructs a scanner without loading the YARA ruleset. Only hash/regex
    /// scanning is available. Used by unit tests that would otherwise spend
    /// tens of seconds compiling the full rules.yar.
    #[cfg(test)]
    pub fn without_yara(rules: Vec<Rule>, throttle_ms: u64) -> Self {
        let arc_rules: Vec<Arc<Rule>> = rules.into_iter().map(Arc::new).collect();
        let (compiled_regexes, sha256_index, md5_index, tlsh_rules) =
            build_rule_indexes(&arc_rules);
        Self {
            rules: arc_rules,
            compiled_regexes,
            sha256_index,
            md5_index,
            tlsh_rules,
            yara_rules: None,
            throttle_ms,
        }
    }

    /// Calculates MD5 and SHA-256 hashes of a file in a memory-efficient streaming manner.
    pub fn calculate_hashes<P: AsRef<Path>>(&self, path: P) -> io::Result<(String, String)> {
        let mut file = File::open(path)?;
        let mut sha256_hasher = Sha256::new();
        let mut md5_context = Md5Context::new();
        let mut buffer = [0; 65536]; // 64KB buffer

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            sha256_hasher.update(&buffer[..bytes_read]);
            md5_context.consume(&buffer[..bytes_read]);
        }

        let sha256_result = format!("{:x}", sha256_hasher.finalize());
        let md5_result = format!("{:x}", md5_context.compute());

        Ok((sha256_result, md5_result))
    }

    /// Calculates MD5, SHA-256, and TLSH fuzzy hash of a file.
    pub fn calculate_hashes_and_tlsh<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> io::Result<(String, String, Option<String>)> {
        let mut file = File::open(path)?;
        let mut sha256_hasher = Sha256::new();
        let mut md5_context = Md5Context::new();
        let mut tlsh_builder = tlsh_fixed::TlshBuilder::new(
            tlsh_fixed::BucketKind::Bucket128,
            tlsh_fixed::ChecksumKind::OneByte,
            tlsh_fixed::Version::Version4,
        );
        let mut buffer = [0; 65536]; // 64KB buffer
        let mut total_bytes = 0;

        // TLSH limit: l_capturing() will fail and cause a panic for lengths > 4,224,281,216 bytes
        const MAX_TLSH_FILE_SIZE: u64 = 4_224_281_216;
        let file_len = file.metadata().map(|m| m.len()).unwrap_or(0);
        let mut use_tlsh = file_len <= MAX_TLSH_FILE_SIZE;

        loop {
            let bytes_read = file.read(&mut buffer)?;
            if bytes_read == 0 {
                break;
            }
            sha256_hasher.update(&buffer[..bytes_read]);
            md5_context.consume(&buffer[..bytes_read]);

            if use_tlsh {
                if total_bytes + bytes_read <= MAX_TLSH_FILE_SIZE as usize {
                    tlsh_builder.update(&buffer[..bytes_read]);
                } else {
                    use_tlsh = false;
                }
            }
            total_bytes += bytes_read;
        }

        let sha256_result = format!("{:x}", sha256_hasher.finalize());
        let md5_result = format!("{:x}", md5_context.compute());

        let tlsh_result = if use_tlsh && total_bytes >= 50 {
            match tlsh_builder.build() {
                Ok(t) => Some(t.hash()),
                Err(_) => None,
            }
        } else {
            None
        };

        Ok((sha256_result, md5_result, tlsh_result))
    }

    /// Scans a single file against the loaded rules.
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Option<ScanResult> {
        let path_ref = path.as_ref();
        if !path_ref.is_file() {
            return None;
        }

        // Whitelist check
        let path_str = path_ref.to_string_lossy().to_string();
        if crate::utils::load_whitelist().contains(&path_str) {
            return None;
        }

        let mut triggered_rules = Vec::new();

        // 1. Hash Check
        if let Ok((sha256, md5, tlsh_opt)) = self.calculate_hashes_and_tlsh(path_ref) {
            // O(1) direct lookup for SHA-256
            if let Some(rule) = self.sha256_index.get(&sha256.to_lowercase())
                && !triggered_rules.iter().any(|r: &Rule| r.id == rule.id)
            {
                triggered_rules.push((**rule).clone());
            }
            // O(1) direct lookup for MD5
            if let Some(rule) = self.md5_index.get(&md5.to_lowercase())
                && !triggered_rules.iter().any(|r: &Rule| r.id == rule.id)
            {
                triggered_rules.push((**rule).clone());
            }
            // TLSH similarity check against pre-parsed rule hashes
            if let Some(ref file_tlsh_str) = tlsh_opt {
                use std::str::FromStr;
                if let Ok(file_tlsh) = tlsh_fixed::Tlsh::from_str(file_tlsh_str) {
                    for (rule_tlsh, rule) in &self.tlsh_rules {
                        // A difference score of <= 50 indicates high similarity
                        let diff_score = file_tlsh.diff(rule_tlsh, true);
                        if diff_score <= 50
                            && !triggered_rules.iter().any(|r: &Rule| r.id == rule.id)
                        {
                            triggered_rules.push((**rule).clone());
                        }
                    }
                }
            }
        }

        // 2. Pattern (Regex) & YARA Check - Only scan files of reasonable size to avoid high memory/CPU usage
        if let Ok(metadata) = path_ref.metadata()
            && metadata.len() < 10 * 1024 * 1024
            && let Ok(mut file) = File::open(path_ref)
        {
            let mut bytes = Vec::new();
            if file.read_to_end(&mut bytes).is_ok() {
                // A. Regex Check directly on &bytes (zero-copy, no 10MB heap String allocation)
                for (rule_id, regex) in &self.compiled_regexes {
                    if regex.is_match(&bytes)
                        && let Some(rule) = self.rules.iter().find(|r| r.id == *rule_id)
                        && !triggered_rules.iter().any(|r| r.id == rule.id)
                    {
                        triggered_rules.push((**rule).clone());
                    }
                }

                // B. YARA-X Check
                if let Some(ref yara_rules) = self.yara_rules {
                    let mut yara_scanner = YaraScanner::new(yara_rules);
                    yara_scanner.set_timeout(YARA_SCAN_TIMEOUT);
                    match yara_scanner.scan(&bytes) {
                        Ok(scan_results) => {
                            for matched_rule in scan_results.matching_rules() {
                                let rule_name = matched_rule.identifier();
                                let rule_id = format!("YARA-{}", rule_name);
                                let rule = Rule {
                                    id: rule_id.clone(),
                                    name: rule_name.to_string(),
                                    description: format!("Aturan YARA terdeteksi: {}", rule_name),
                                    severity: "High".to_string(),
                                    signatures: crate::config::Signatures {
                                        hashes: None,
                                        patterns: None,
                                        extension_ids: None,
                                    },
                                };
                                if !triggered_rules.iter().any(|r| r.id == rule.id) {
                                    triggered_rules.push(rule);
                                }
                            }
                        }
                        Err(ScanError::Timeout) => {
                            if !YARA_TIMEOUT_LOGGED.swap(true, std::sync::atomic::Ordering::SeqCst)
                            {
                                eprintln!(
                                    "[-] Peringatan: scan YARA timeout pada {:?}. Rule bermasalah diabaikan agar daemon tetap responsif.",
                                    path_ref
                                );
                            }
                        }
                        Err(e) => {
                            eprintln!("[-] Gagal scan YARA pada {:?}: {}", path_ref, e);
                        }
                    }
                }

                // C. Heuristic Entropy Check
                if bytes.len() >= 4096 {
                    let entropy = calculate_entropy(&bytes);
                    if entropy > 7.5 {
                        let mut is_executable = false;

                        // 1. Check if ELF format and filter out relocatable object files (ET_REL / .o)
                        if bytes.starts_with(&[0x7f, 0x45, 0x4c, 0x46]) {
                            is_executable = true;
                            if bytes.len() >= 18 {
                                let endian = bytes[5];
                                let e_type = if endian == 1 {
                                    // Little endian
                                    bytes[16] as u16 | ((bytes[17] as u16) << 8)
                                } else {
                                    // Big endian
                                    ((bytes[16] as u16) << 8) | bytes[17] as u16
                                };
                                // e_type == 1 is ET_REL (Relocatable object file, e.g. .o, .obj)
                                if e_type == 1 {
                                    is_executable = false;
                                }
                            }
                        }
                        // 2. Check if PE (Windows executable) format
                        else if bytes.starts_with(&[0x4d, 0x5a]) {
                            is_executable = true;
                        }

                        if is_executable {
                            // 3. Exclude compiler artifacts, archives, and build directories
                            if let Some(path_str) = path_ref.to_str() {
                                let path_lower = path_str.to_lowercase();
                                let is_artifact = path_lower.ends_with(".o")
                                    || path_lower.ends_with(".obj")
                                    || path_lower.ends_with(".a")
                                    || path_lower.ends_with(".lib")
                                    || path_lower.ends_with(".la")
                                    || path_lower.ends_with(".lai")
                                    || path_lower.ends_with(".lo")
                                    || path_lower.ends_with(".ko")
                                    || path_lower.ends_with(".pdb")
                                    || path_lower.ends_with(".d")
                                    || path_lower.ends_with(".o.d")
                                    || path_lower.ends_with(".node")
                                    || path_lower.ends_with(".json")
                                    || path_lower.ends_with(".zip")
                                    || path_lower.ends_with(".tar.gz")
                                    || path_lower.ends_with(".tgz")
                                    || path_lower.ends_with(".png")
                                    || path_lower.ends_with(".jpg")
                                    || path_lower.ends_with(".jpeg")
                                    || path_lower.ends_with(".webp")
                                    || path_lower.ends_with(".gif");

                                let in_build_dir = path_lower.contains("cmakefiles/")
                                    || path_lower.contains("/build/")
                                    || path_lower.contains("/target/")
                                    || path_lower.contains("node_modules/")
                                    || path_lower.contains(".git/")
                                    || path_lower.contains(".cargo/");

                                if !is_artifact && !in_build_dir {
                                    let rule = Rule {
                                        id: "HEURISTIC-ENTROPY".to_string(),
                                        name: "High Entropy Packed/Encrypted Executable"
                                            .to_string(),
                                        description: format!(
                                            "Berkas eksekusi memiliki entropy tinggi ({:.2}), menandakan proteksi packer, obfuscation, atau enkripsi malware.",
                                            entropy
                                        ),
                                        severity: "Medium".to_string(),
                                        signatures: crate::config::Signatures {
                                            hashes: None,
                                            patterns: None,
                                            extension_ids: None,
                                        },
                                    };
                                    if !triggered_rules.iter().any(|r| r.id == rule.id) {
                                        triggered_rules.push(rule);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if !triggered_rules.is_empty() {
            Some(ScanResult {
                file_path: path_ref.to_string_lossy().into_owned(),
                triggered_rules,
            })
        } else {
            None
        }
    }

    /// Recursively scans a directory with CPU throttling (sleep), ignoring system folders.
    pub fn scan_directory<P: AsRef<Path>, F>(
        &self,
        dir_path: P,
        already_scanned: &HashSet<String>,
        total_files_opt: Option<usize>,
        mut progress_cb: F,
    ) -> Vec<ScanResult>
    where
        F: FnMut(usize, usize, &str, Option<&ScanResult>) -> bool,
    {
        let mut results = Vec::new();
        let skip_prefixes = [
            "/proc/",
            "/sys/",
            "/dev/",
            "/run/",
            "/tmp/",
            "/var/lib/ferroshield/quarantine/",
        ];

        let is_rules_db =
            |path_str: &str| path_str.ends_with("rules.yar") || path_str.ends_with("rules.json");

        let path_ref = dir_path.as_ref();

        // 1. Quick File Count
        let total_files = match total_files_opt {
            Some(total) => total,
            None => {
                let mut total_files = 0;
                let walk_count = WalkDir::new(path_ref).into_iter();
                for entry in walk_count.filter_map(Result::ok) {
                    let path = entry.path();
                    let path_str = path.to_string_lossy();
                    if path.is_file() {
                        if skip_prefixes
                            .iter()
                            .any(|&prefix| path_str.starts_with(prefix))
                            || path_str.contains(".quarantine/")
                            || path_str.ends_with(".quarantine")
                            || is_rules_db(&path_str)
                        {
                            continue;
                        }
                        total_files += 1;
                    }
                }
                total_files
            }
        };

        // 2. Perform Scan
        let whitelist = crate::utils::load_whitelist();
        let walk = WalkDir::new(path_ref).into_iter();
        let mut scanned_files = 0;

        for entry in walk.filter_map(Result::ok) {
            let path = entry.path();
            let path_str = path.to_string_lossy();

            // Skip virtual/temp systems and quarantine folder to prevent infinite loop or self-alert
            if skip_prefixes
                .iter()
                .any(|&prefix| path_str.starts_with(prefix))
                || path_str.contains(".quarantine/")
                || path_str.ends_with(".quarantine")
                || is_rules_db(&path_str)
            {
                continue;
            }

            if path.is_file() {
                scanned_files += 1;

                if whitelist.contains(&path_str.to_string()) {
                    if !progress_cb(scanned_files, total_files, &path_str, None) {
                        break;
                    }
                    continue;
                }

                if already_scanned.contains(&path_str.to_string()) {
                    if !progress_cb(scanned_files, total_files, &path_str, None) {
                        break;
                    }
                    continue;
                }

                let scan_res = self.scan_file(path);
                if !progress_cb(scanned_files, total_files, &path_str, scan_res.as_ref()) {
                    break;
                }

                if let Some(result) = scan_res {
                    results.push(result);
                }

                // CPU Throttling: sleep after scanning each file
                if self.throttle_ms > 0 {
                    thread::sleep(Duration::from_millis(self.throttle_ms));
                }
            }
        }

        results
    }
}

/// True when the rules.yar in the working directory matches the SHA-256 recorded
/// in the signed rules.json. `None` (legacy rules.json without the field) allows
/// compilation; a mismatch or unreadable file disables YARA with a clear warning.
fn yara_ruleset_integrity_ok(expected_rules_yar_sha256: Option<&str>) -> bool {
    match expected_rules_yar_sha256 {
        None => true,
        Some(expected) => match crate::network::file_sha256(Path::new("rules.yar")) {
            Ok(actual) if actual.eq_ignore_ascii_case(expected.trim()) => true,
            Ok(actual) => {
                eprintln!(
                    "[-] PERINGATAN: SHA-256 rules.yar tidak cocok dengan rules.json (ditemukan {}, diharapkan {}). YARA dinonaktifkan.",
                    actual, expected
                );
                false
            }
            Err(e) => {
                eprintln!(
                    "[-] Gagal menghitung SHA-256 rules.yar: {}. YARA dinonaktifkan.",
                    e
                );
                false
            }
        },
    }
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }
    let mut entropy = 0.0;
    let len = data.len() as f64;
    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const PATHOLOGICAL_BASE64_RULE: &str = r#"
rule base64_packed {
  strings:
    $f = /(atob|btoa|;base64|base64,)/ nocase
    $fff = /([A-Za-z0-9]{4})*([A-Za-z0-9]{2}==|[A-Za-z0-9]{3}=|[A-Za-z0-9]{4})/
  condition:
    $f and $fff
}"#;

    const FIXED_BASE64_RULE: &str = r#"
rule base64_packed {
  strings:
    $f = /(atob|btoa|;base64|base64,)/ nocase
    $fff = /[A-Za-z0-9]{4}([A-Za-z0-9]{2}==|[A-Za-z0-9]{3}=|[A-Za-z0-9]{4})?/
  condition:
    $f and $fff
}"#;

    fn compile_yara(src: &str) -> YaraRules {
        let mut compiler = Compiler::new();
        compiler.add_source(src).expect("rule must compile");
        compiler.build()
    }

    #[test]
    fn test_yara_fixed_base64_regex_scan_is_fast() {
        // ReDoS regression: the old /([A-Za-z0-9]{4})*.../ pattern made scan time
        // grow polynomially on long alphanumeric input. The fixed pattern must
        // complete within the 1s per-scan timeout. Release builds enforce the full
        // 1 MB requirement; the debug WASM interpreter is ~30x slower, so it uses
        // a smaller buffer while still proving the scan terminates in-time.
        let rules = compile_yara(FIXED_BASE64_RULE);
        let data: Vec<u8> = if cfg!(debug_assertions) {
            (0..(8 << 10)).map(|i| b"Aa0Zz9"[i % 6]).collect()
        } else {
            (0..(1 << 20)).map(|i| b"Aa0Zz9"[i % 6]).collect()
        };

        let started = std::time::Instant::now();
        let mut scanner = YaraScanner::new(&rules);
        scanner.set_timeout(Duration::from_secs(1));
        assert!(
            scanner.scan(&data).is_ok(),
            "fixed regex did not complete within the 1s scan timeout (elapsed {:?})",
            started.elapsed()
        );
    }

    #[test]
    fn test_yara_scan_timeout_aborts_pathological_rule() {
        // The unfixed pattern is confirmed pathological (>>30s on 4 MB in
        // release mode). The per-scan timeout must abort promptly instead of
        // stalling Browser Guard / the scan daemon.
        let rules = compile_yara(PATHOLOGICAL_BASE64_RULE);
        let data = vec![b'a'; 4 << 20]; // 4 MB alphanumeric

        let started = std::time::Instant::now();
        let mut scanner = YaraScanner::new(&rules);
        scanner.set_timeout(Duration::from_millis(500));
        let result = scanner.scan(&data);
        assert!(matches!(result, Err(ScanError::Timeout)));
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "timeout did not abort the scan promptly: {:?}",
            started.elapsed()
        );
    }

    #[test]
    fn test_yara_timeout_does_not_block_scan_file() {
        // End-to-end: a pathological rule inside a loaded ruleset must not hang
        // Scanner::scan_file; it should return a scan result (no panic).
        let rules = compile_yara(PATHOLOGICAL_BASE64_RULE);
        let mut scanner = Scanner::without_yara(vec![], 0);
        scanner.yara_rules = Some(Arc::new(rules));

        // 1 MB is the worst case the pathological pattern can stall on; in debug
        // mode it would exceed 30s, so the timeout must abort it promptly.
        let path = Path::new("test_redos_trigger.bin");
        fs::write(path, vec![b'a'; 1 << 20]).unwrap();
        let started = std::time::Instant::now();
        let _ = scanner.scan_file(path);
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "scan_file hung on pathological rule: {:?}",
            started.elapsed()
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_rules_yar_integrity_check_uses_recorded_hash() {
        // Tests run with CWD = crate root where rules.yar exists. Computing the
        // real hash makes the assertion independent of the file's contents.
        let actual = crate::network::file_sha256(Path::new("rules.yar"))
            .expect("rules.yar must be readable");
        assert!(yara_ruleset_integrity_ok(Some(&actual)));
        assert!(
            yara_ruleset_integrity_ok(None),
            "legacy rules.json allows compile"
        );
        assert!(
            !yara_ruleset_integrity_ok(Some(
                "0000000000000000000000000000000000000000000000000000000000000000"
            )),
            "a single changed hash must disable YARA"
        );
    }

    #[test]
    fn test_calculate_hashes_and_tlsh_small() {
        // Construct Scanner directly to avoid compiling the full rules.yar (which
        // takes ~30s in debug): only hash calculation is exercised here.
        let scanner = Scanner::without_yara(vec![], 0);
        let test_path = Path::new("test_small_file.txt");
        fs::write(test_path, b"too small").unwrap();

        let res = scanner.calculate_hashes_and_tlsh(test_path).unwrap();
        assert_eq!(
            res.0,
            "b4e1b307efbc77df67ffa56cfb9fbeeae65b7cf2782229277e07c47504cba62f"
        ); // SHA-256
        assert_eq!(res.1, "6a3f0eb6d9c4fa20039a170c29be7100"); // MD5
        assert_eq!(res.2, None); // TLSH (size < 50)

        let _ = fs::remove_file(test_path);
    }

    #[test]
    fn test_calculate_hashes_and_tlsh_sufficient_size() {
        let scanner = Scanner::without_yara(vec![], 0);
        let test_path = Path::new("test_large_file.txt");
        // TLSH requires at least 50 bytes of sufficiently varied data
        let mut data = Vec::new();
        for i in 0..100 {
            data.push(i as u8);
        }
        fs::write(test_path, &data).unwrap();

        let res = scanner.calculate_hashes_and_tlsh(test_path).unwrap();
        assert!(res.2.is_some()); // TLSH should be computed

        let _ = fs::remove_file(test_path);
    }

    #[test]
    fn test_hash_index_lookup_matches_expected() {
        let test_path = Path::new("test_index_hash_match.bin");
        fs::write(test_path, b"test content for hash matching").unwrap();

        let (sha256, md5) = {
            let temp_scanner = Scanner::without_yara(vec![], 0);
            temp_scanner.calculate_hashes(test_path).unwrap()
        };

        let sha_rule = Rule {
            id: "RULE-SHA".to_string(),
            name: "Rule SHA".to_string(),
            description: "Detects by SHA256".to_string(),
            severity: "High".to_string(),
            signatures: crate::config::Signatures {
                hashes: Some(crate::config::Hashes {
                    sha256: Some(sha256.to_uppercase()), // test case insensitivity
                    md5: None,
                    tlsh: None,
                }),
                patterns: None,
                extension_ids: None,
            },
        };

        let md5_rule = Rule {
            id: "RULE-MD5".to_string(),
            name: "Rule MD5".to_string(),
            description: "Detects by MD5".to_string(),
            severity: "High".to_string(),
            signatures: crate::config::Signatures {
                hashes: Some(crate::config::Hashes {
                    sha256: None,
                    md5: Some(md5.clone()),
                    tlsh: None,
                }),
                patterns: None,
                extension_ids: None,
            },
        };

        let other_rule = Rule {
            id: "RULE-OTHER".to_string(),
            name: "Rule Other".to_string(),
            description: "Non matching rule".to_string(),
            severity: "Low".to_string(),
            signatures: crate::config::Signatures {
                hashes: Some(crate::config::Hashes {
                    sha256: Some(
                        "0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string(),
                    ),
                    md5: Some("00000000000000000000000000000000".to_string()),
                    tlsh: None,
                }),
                patterns: None,
                extension_ids: None,
            },
        };

        let scanner =
            Scanner::without_yara(vec![sha_rule.clone(), md5_rule.clone(), other_rule], 0);

        // Verify index contents
        assert!(scanner.sha256_index().contains_key(&sha256.to_lowercase()));
        assert!(scanner.md5_index().contains_key(&md5.to_lowercase()));

        // Scan file and verify matches
        let result = scanner.scan_file(test_path).expect("should match rules");
        assert_eq!(result.triggered_rules.len(), 2);
        assert!(result.triggered_rules.iter().any(|r| r.id == "RULE-SHA"));
        assert!(result.triggered_rules.iter().any(|r| r.id == "RULE-MD5"));

        // Scan non-matching file
        let clean_path = Path::new("test_clean_file.bin");
        fs::write(clean_path, b"completely different clean content").unwrap();
        let clean_result = scanner.scan_file(clean_path);
        assert!(clean_result.is_none());

        let _ = fs::remove_file(test_path);
        let _ = fs::remove_file(clean_path);
    }

    #[test]
    fn test_tlsh_preparsed_in_index_avoids_reparsing() {
        let test_path = Path::new("test_tlsh_match.bin");
        let mut data = Vec::new();
        for i in 0..120 {
            data.push(i as u8);
        }
        fs::write(test_path, &data).unwrap();

        let temp_scanner = Scanner::without_yara(vec![], 0);
        let (_, _, tlsh_opt) = temp_scanner.calculate_hashes_and_tlsh(test_path).unwrap();
        let target_tlsh_str = tlsh_opt.expect("TLSH must be generated for >= 50 bytes");

        let tlsh_rule = Rule {
            id: "RULE-TLSH".to_string(),
            name: "Rule TLSH".to_string(),
            description: "Detects by TLSH".to_string(),
            severity: "Critical".to_string(),
            signatures: crate::config::Signatures {
                hashes: Some(crate::config::Hashes {
                    sha256: None,
                    md5: None,
                    tlsh: Some(target_tlsh_str),
                }),
                patterns: None,
                extension_ids: None,
            },
        };

        let scanner = Scanner::without_yara(vec![tlsh_rule], 0);

        // Prove that the index contains the pre-parsed Tlsh struct
        assert_eq!(scanner.tlsh_rules().len(), 1);
        let (parsed_tlsh, rule) = &scanner.tlsh_rules()[0];
        assert_eq!(rule.id, "RULE-TLSH");
        assert!(!parsed_tlsh.hash().is_empty());

        // Scan file and verify that matching succeeds with pre-parsed struct
        let result = scanner
            .scan_file(test_path)
            .expect("should match TLSH rule");
        assert_eq!(result.triggered_rules.len(), 1);
        assert_eq!(result.triggered_rules[0].id, "RULE-TLSH");

        let _ = fs::remove_file(test_path);
    }
}
