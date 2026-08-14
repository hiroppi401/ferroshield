use crate::config::Rule;
use md5::Context as Md5Context;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use walkdir::WalkDir;
use yara_x::{Compiler, Rules as YaraRules, Scanner as YaraScanner};

pub struct ScanResult {
    pub file_path: String,
    pub triggered_rules: Vec<Rule>,
}

#[derive(Clone)]
pub struct Scanner {
    rules: Vec<Rule>,
    compiled_regexes: Vec<(String, Regex)>, // (rule_id, compiled_regex)
    yara_rules: Option<Arc<YaraRules>>,
    throttle_ms: u64,
}

impl Scanner {
    pub fn new(rules: Vec<Rule>, throttle_ms: u64) -> Self {
        let mut compiled_regexes = Vec::new();
        for rule in &rules {
            if let Some(ref patterns) = rule.signatures.patterns {
                for pattern in patterns {
                    if let Ok(re) = Regex::new(pattern) {
                        compiled_regexes.push((rule.id.clone(), re));
                    }
                }
            }
        }

        // Attempt to load and compile rules.yar if it exists
        let yara_rules = if Path::new("rules.yar").exists() {
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
        } else {
            None
        };

        Self {
            rules,
            compiled_regexes,
            yara_rules,
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
            for rule in &self.rules {
                if let Some(ref hashes) = rule.signatures.hashes {
                    let mut matched = false;
                    if let Some(ref rule_sha256) = hashes.sha256
                        && sha256.eq_ignore_ascii_case(rule_sha256)
                    {
                        matched = true;
                    }
                    if let Some(ref rule_md5) = hashes.md5
                        && md5.eq_ignore_ascii_case(rule_md5)
                    {
                        matched = true;
                    }
                    if let Some(ref rule_tlsh_str) = hashes.tlsh
                        && let Some(ref file_tlsh_str) = tlsh_opt
                    {
                        use std::str::FromStr;
                        if let Ok(rule_tlsh) = tlsh_fixed::Tlsh::from_str(rule_tlsh_str)
                            && let Ok(file_tlsh) = tlsh_fixed::Tlsh::from_str(file_tlsh_str)
                        {
                            // A difference score of <= 50 indicates high similarity
                            let diff_score = file_tlsh.diff(&rule_tlsh, true);
                            if diff_score <= 50 {
                                matched = true;
                            }
                        }
                    }
                    if matched {
                        triggered_rules.push(rule.clone());
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
                // A. Regex Check
                let contents = String::from_utf8_lossy(&bytes).into_owned();
                for (rule_id, regex) in &self.compiled_regexes {
                    if regex.is_match(&contents)
                        && let Some(rule) = self.rules.iter().find(|r| r.id == *rule_id)
                        && !triggered_rules.iter().any(|r| r.id == rule.id)
                    {
                        triggered_rules.push(rule.clone());
                    }
                }

                // B. YARA-X Check
                if let Some(ref yara_rules) = self.yara_rules {
                    let mut yara_scanner = YaraScanner::new(yara_rules);
                    if let Ok(scan_results) = yara_scanner.scan(&bytes) {
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

        let is_rules_db = |path_str: &str| {
            path_str.ends_with("rules.yar") || path_str.ends_with("rules.json")
        };

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

    #[test]
    fn test_calculate_hashes_and_tlsh_small() {
        let scanner = Scanner::new(vec![], 0);
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
        let scanner = Scanner::new(vec![], 0);
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
}
