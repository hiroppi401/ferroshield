use crate::utils::log_message;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::Duration;

/// Upper bound for a downloaded threat feed body. Feeds are a few MB at most;
/// rejecting anything larger prevents a malformed/hijacked feed from exhausting
/// memory during `update-feed`.
const MAX_FEED_SIZE: usize = 50 * 1024 * 1024;

/// Downloads a feed over TLS (certificates fully validated by ureq's default
/// TLS stack) and returns the body, enforcing `max_bytes`. An oversized body is
/// an error, not a truncated silently-accepted one.
fn read_bounded<R: Read>(mut reader: R, max_bytes: usize) -> std::io::Result<Vec<u8>> {
    let mut body = Vec::with_capacity(max_bytes.min(1 << 20));
    let mut buffer = [0u8; 65536];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        body.extend_from_slice(&buffer[..n]);
        if body.len() > max_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("feed exceeds size limit of {} bytes", max_bytes),
            ));
        }
    }
    Ok(body)
}

/// Downloads `url` over TLS and returns its body, rejecting responses larger
/// than `MAX_FEED_SIZE` and any connection/status error.
fn fetch_feed_body(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let resp = ureq::get(url)
        .timeout(Duration::from_secs(15))
        .call()
        .map_err(|e| format!("Gagal mengunduh {}: {}", url, e))?;
    let body = read_bounded(resp.into_reader(), MAX_FEED_SIZE)
        .map_err(|e| format!("Gagal membaca feed {}: {}", url, e))?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Parses a Feodo Tracker IP blocklist: one IPv4 per line, `#` comments allowed.
/// Malformed lines are skipped with a log instead of aborting or panicking.
fn parse_feodo_ips(body: &str) -> Vec<String> {
    let mut ips = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.parse::<std::net::Ipv4Addr>() {
            Ok(_) => ips.push(line.to_string()),
            Err(_) => {
                log_message(&format!(
                    "[-] Feed Feodo: melewati baris IP tidak valid: {:?}",
                    line
                ));
            }
        }
    }
    ips
}

/// Parses a URLhaus host file: `127.0.0.1 <domain>` per line. Any other format
/// is skipped gracefully; domain entries are sanity-checked before being kept.
fn parse_urlhaus_domains(body: &str) -> Vec<String> {
    let mut domains = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() != 2 || parts[0] != "127.0.0.1" {
            continue;
        }
        let domain = parts[1];
        // Basic sanity: has a dot, no slash or whitespace (defensive against
        // malformed lines that would pollute rules.json with garbage).
        if domain.contains('.') && !domain.contains('/') && !domain.contains(' ') {
            domains.push(domain.to_string());
        } else {
            log_message(&format!(
                "[-] Feed URLhaus: melewati domain tidak valid: {:?}",
                domain
            ));
        }
    }
    domains
}

#[derive(serde::Deserialize)]
struct OtxResponse {
    #[serde(default)]
    results: Vec<OtxPulse>,
}

#[derive(serde::Deserialize)]
struct OtxPulse {
    name: Option<String>,
    author_name: Option<String>,
    #[serde(default)]
    indicators: Vec<OtxIndicator>,
}

#[derive(serde::Deserialize)]
struct OtxIndicator {
    indicator: Option<String>,
    #[serde(rename = "type")]
    indicator_type: Option<String>,
}

/// Downloads initial page of subscribed AlienVault OTX pulses.
pub fn fetch_otx_pulses(api_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    fetch_otx_page(
        "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=50&page=1",
        api_key,
    )
}

/// Downloads a specific OTX pulse URL using the provided API key header.
fn fetch_otx_page(url: &str, api_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let resp = ureq::get(url)
        .set("X-OTX-API-KEY", api_key)
        .timeout(Duration::from_secs(15))
        .call()
        .map_err(|e| format!("Gagal mengunduh OTX dari {}: {}", url, e))?;
    let body = read_bounded(resp.into_reader(), MAX_FEED_SIZE)
        .map_err(|e| format!("Gagal membaca OTX feed dari {}: {}", url, e))?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Extracts the next pagination URL from an OTX JSON response body.
fn extract_otx_next_url(body: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct OtxNext {
        next: Option<String>,
    }
    let parsed: OtxNext = serde_json::from_str(body).ok()?;
    parsed.next.filter(|s| !s.trim().is_empty())
}

/// Parses an OTX pulses response body into IPs, domains, and hash-based rules.
pub fn parse_otx_pulses(body: &str) -> (Vec<String>, Vec<String>, Vec<crate::config::Rule>) {
    let mut ips = Vec::new();
    let mut domains = Vec::new();
    let mut rules = Vec::new();
    let mut skipped_other = 0usize;

    let parsed: OtxResponse = match serde_json::from_str(body) {
        Ok(res) => res,
        Err(e) => {
            log_message(&format!("[-] Feed OTX: Gagal mem-parsing JSON: {}", e));
            return (ips, domains, rules);
        }
    };

    for pulse in parsed.results {
        let pulse_name = pulse
            .name
            .unwrap_or_else(|| "Unknown OTX Pulse".to_string());
        let author_name = pulse
            .author_name
            .unwrap_or_else(|| "Unknown Author".to_string());

        for ind in pulse.indicators {
            let (raw_val, ind_type) = match (ind.indicator, ind.indicator_type) {
                (Some(val), Some(t)) => (val.trim().to_string(), t.trim().to_string()),
                _ => continue,
            };

            if raw_val.is_empty() {
                continue;
            }

            match ind_type.as_str() {
                "IPv4" => match raw_val.parse::<std::net::Ipv4Addr>() {
                    Ok(_) => ips.push(raw_val),
                    Err(_) => {
                        log_message(&format!(
                            "[-] Feed OTX: melewati baris IP tidak valid: {:?}",
                            raw_val
                        ));
                    }
                },
                "domain" | "hostname" => {
                    let d = raw_val.trim_end_matches('.').to_lowercase();
                    if d.contains('.') && !d.contains('/') && !d.contains(' ') {
                        domains.push(d);
                    } else {
                        log_message(&format!(
                            "[-] Feed OTX: melewati domain tidak valid: {:?}",
                            raw_val
                        ));
                    }
                }
                "FileHash-SHA256" => {
                    let hash_lower = raw_val.to_lowercase();
                    if hash_lower.len() == 64 && hash_lower.chars().all(|c| c.is_ascii_hexdigit()) {
                        rules.push(crate::config::Rule {
                            id: format!("OTX-SHA256-{}", hash_lower),
                            name: pulse_name.clone(),
                            description: format!(
                                "OTX Pulse: {} (Author: {})",
                                pulse_name, author_name
                            ),
                            severity: "medium".to_string(),
                            signatures: crate::config::Signatures {
                                hashes: Some(crate::config::Hashes {
                                    sha256: Some(hash_lower),
                                    md5: None,
                                    tlsh: None,
                                }),
                                patterns: None,
                                extension_ids: None,
                            },
                        });
                    } else {
                        log_message(&format!(
                            "[-] Feed OTX: melewati SHA256 tidak valid: {:?}",
                            raw_val
                        ));
                    }
                }
                "FileHash-MD5" => {
                    let hash_lower = raw_val.to_lowercase();
                    if hash_lower.len() == 32 && hash_lower.chars().all(|c| c.is_ascii_hexdigit()) {
                        rules.push(crate::config::Rule {
                            id: format!("OTX-MD5-{}", hash_lower),
                            name: pulse_name.clone(),
                            description: format!(
                                "OTX Pulse: {} (Author: {})",
                                pulse_name, author_name
                            ),
                            severity: "medium".to_string(),
                            signatures: crate::config::Signatures {
                                hashes: Some(crate::config::Hashes {
                                    sha256: None,
                                    md5: Some(hash_lower),
                                    tlsh: None,
                                }),
                                patterns: None,
                                extension_ids: None,
                            },
                        });
                    } else {
                        log_message(&format!(
                            "[-] Feed OTX: melewati MD5 tidak valid: {:?}",
                            raw_val
                        ));
                    }
                }
                _ => {
                    skipped_other += 1;
                }
            }
        }
    }

    if skipped_other > 0 {
        log_message(&format!(
            "[*] Feed OTX: melewati {} indicator bertipe lain (URL/CVE/dll).",
            skipped_other
        ));
    }

    (ips, domains, rules)
}

#[derive(serde::Deserialize)]
struct ThreatFoxResponse {
    query_status: Option<String>,
    #[serde(default)]
    data: Vec<ThreatFoxIoc>,
}

#[derive(serde::Deserialize)]
struct ThreatFoxIoc {
    ioc: Option<String>,
    ioc_type: Option<String>,
    malware_printable: Option<String>,
    tags: Option<Vec<String>>,
    confidence_level: Option<u32>,
}

/// Downloads recent IOCs from ThreatFox API using POST and Auth-Key header.
pub fn fetch_threatfox_iocs(auth_key: &str) -> Result<String, Box<dyn std::error::Error>> {
    let payload = serde_json::json!({
        "query": "get_iocs",
        "days": 1
    });
    let payload_str = serde_json::to_string(&payload)?;
    let resp = ureq::post("https://threatfox-api.abuse.ch/api/v1/")
        .set("Content-Type", "application/json")
        .set("Auth-Key", auth_key)
        .timeout(Duration::from_secs(15))
        .send_string(&payload_str)
        .map_err(|e| format!("Gagal memanggil ThreatFox API: {}", e))?;
    let body = read_bounded(resp.into_reader(), MAX_FEED_SIZE)
        .map_err(|e| format!("Gagal membaca ThreatFox feed: {}", e))?;
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Parses ThreatFox IOC JSON body into IPs, domains, and hash-based rules.
pub fn parse_threatfox_iocs(body: &str) -> (Vec<String>, Vec<String>, Vec<crate::config::Rule>) {
    let mut ips = Vec::new();
    let mut domains = Vec::new();
    let mut rules = Vec::new();
    let mut skipped_other = 0usize;

    let parsed: ThreatFoxResponse = match serde_json::from_str(body) {
        Ok(res) => res,
        Err(e) => {
            log_message(&format!(
                "[-] Feed ThreatFox: Gagal mem-parsing JSON: {}",
                e
            ));
            return (ips, domains, rules);
        }
    };

    if parsed.query_status.as_deref() != Some("ok") {
        log_message(&format!(
            "[-] Feed ThreatFox: query_status bukan 'ok': {:?}",
            parsed.query_status
        ));
        return (ips, domains, rules);
    }

    for item in parsed.data {
        let (raw_ioc, ioc_type) = match (item.ioc, item.ioc_type) {
            (Some(ioc), Some(t)) => (ioc.trim().to_string(), t.trim().to_lowercase()),
            _ => continue,
        };

        if raw_ioc.is_empty() {
            continue;
        }

        let malware = item
            .malware_printable
            .unwrap_or_else(|| "Unknown Malware".to_string());
        let tags = item.tags.unwrap_or_default();
        let tags_str = if tags.is_empty() {
            "-".to_string()
        } else {
            tags.join(", ")
        };
        let confidence = item.confidence_level.unwrap_or(100);
        let severity = if confidence < 50 {
            "low".to_string()
        } else {
            "medium".to_string()
        };

        if ioc_type == "domain" {
            let d = raw_ioc.trim_end_matches('.').to_lowercase();
            if d.contains('.') && !d.contains('/') && !d.contains(' ') {
                domains.push(d);
            } else {
                log_message(&format!(
                    "[-] Feed ThreatFox: melewati domain tidak valid: {:?}",
                    raw_ioc
                ));
            }
        } else if ioc_type == "ip:port" {
            let ip_part = raw_ioc.split(':').next().unwrap_or("").trim();
            match ip_part.parse::<std::net::Ipv4Addr>() {
                Ok(_) => ips.push(ip_part.to_string()),
                Err(_) => {
                    log_message(&format!(
                        "[-] Feed ThreatFox: melewati ip:port tidak valid: {:?}",
                        raw_ioc
                    ));
                }
            }
        } else if ioc_type.contains("hash") {
            let hash_lower = raw_ioc.to_lowercase();
            if (ioc_type == "sha256_hash" || hash_lower.len() == 64)
                && hash_lower.chars().all(|c| c.is_ascii_hexdigit())
            {
                rules.push(crate::config::Rule {
                    id: format!("THREATFOX-SHA256-{}", hash_lower),
                    name: malware.clone(),
                    description: format!(
                        "ThreatFox: {} (Tags: [{}], Confidence: {}%)",
                        malware, tags_str, confidence
                    ),
                    severity,
                    signatures: crate::config::Signatures {
                        hashes: Some(crate::config::Hashes {
                            sha256: Some(hash_lower),
                            md5: None,
                            tlsh: None,
                        }),
                        patterns: None,
                        extension_ids: None,
                    },
                });
            } else if (ioc_type == "md5_hash" || hash_lower.len() == 32)
                && hash_lower.chars().all(|c| c.is_ascii_hexdigit())
            {
                rules.push(crate::config::Rule {
                    id: format!("THREATFOX-MD5-{}", hash_lower),
                    name: malware.clone(),
                    description: format!(
                        "ThreatFox: {} (Tags: [{}], Confidence: {}%)",
                        malware, tags_str, confidence
                    ),
                    severity,
                    signatures: crate::config::Signatures {
                        hashes: Some(crate::config::Hashes {
                            sha256: None,
                            md5: Some(hash_lower),
                            tlsh: None,
                        }),
                        patterns: None,
                        extension_ids: None,
                    },
                });
            } else {
                log_message(&format!(
                    "[-] Feed ThreatFox: melewati hash tidak valid: {:?}",
                    raw_ioc
                ));
            }
        } else if ioc_type == "url" {
            // Skipped per design (network blacklist handles IP/domain)
            skipped_other += 1;
        } else {
            skipped_other += 1;
        }
    }

    if skipped_other > 0 {
        log_message(&format!(
            "[*] Feed ThreatFox: melewati {} indicator bertipe lain (URL/dll).",
            skipped_other
        ));
    }

    (ips, domains, rules)
}

/// Downloads Feodo Tracker, URLhaus, OTX, and ThreatFox feeds, parses them,
/// merges them into rules.json, and signs the new rules.json using rules.key.
pub fn update_threat_feed() -> Result<(), Box<dyn std::error::Error>> {
    log_message("[*] Memulai pembaruan threat feed...");

    // 1. Download Feodo Tracker IP Blocklist
    let mut feodo_ips = Vec::new();
    match fetch_feed_body("https://feodotracker.abuse.ch/downloads/ipblocklist.txt") {
        Ok(body) => {
            feodo_ips = parse_feodo_ips(&body);
            log_message(&format!(
                "[+] Berhasil mengunduh {} IP dari Feodo Tracker.",
                feodo_ips.len()
            ));
        }
        Err(e) => {
            log_message(&format!(
                "[-] Gagal mengunduh Feodo Tracker IP blocklist: {}",
                e
            ));
        }
    }

    // 2. Download URLhaus host list
    let mut urlhaus_domains = Vec::new();
    match fetch_feed_body("https://urlhaus.abuse.ch/downloads/hostfile/") {
        Ok(body) => {
            urlhaus_domains = parse_urlhaus_domains(&body);
            log_message(&format!(
                "[+] Berhasil mengunduh {} domain dari URLhaus.",
                urlhaus_domains.len()
            ));
        }
        Err(e) => {
            log_message(&format!("[-] Gagal mengunduh URLhaus host list: {}", e));
        }
    }

    // 3. Download OTX Subscribed Pulses (if API key configured)
    let runtime_config = crate::config::load_runtime_config();
    let mut otx_ips = Vec::new();
    let mut otx_domains = Vec::new();
    let mut otx_rules = Vec::new();

    if let Some(otx_key) = crate::config::effective_otx_api_key(&runtime_config) {
        log_message("[*] Mengunduh subscribed pulses dari AlienVault OTX...");
        let mut page_result = fetch_otx_pulses(&otx_key);
        let mut page_count = 0;

        loop {
            match page_result {
                Ok(body) => {
                    let next = extract_otx_next_url(&body);
                    let (ips, domains, rules) = parse_otx_pulses(&body);
                    otx_ips.extend(ips);
                    otx_domains.extend(domains);
                    otx_rules.extend(rules);
                    page_count += 1;

                    if page_count >= 20 {
                        log_message("[*] OTX: Mencapai batas wajar maksimum 20 halaman.");
                        break;
                    }

                    if let Some(url) = next {
                        page_result = fetch_otx_page(&url, &otx_key);
                    } else {
                        break;
                    }
                }
                Err(e) => {
                    log_message(&format!(
                        "[-] Gagal mengunduh OTX feed (halaman {}): {}",
                        page_count + 1,
                        e
                    ));
                    break;
                }
            }
        }
        log_message(&format!(
            "[+] Berhasil mengunduh OTX: {} IP, {} domain, {} hash rule (dari {} halaman).",
            otx_ips.len(),
            otx_domains.len(),
            otx_rules.len(),
            page_count
        ));
    } else {
        log_message("[-] OTX: api_key tidak dikonfigurasi, melewati sumber ini.");
    }

    // 4. Download ThreatFox IOCs (if Auth-Key configured)
    let mut tf_ips = Vec::new();
    let mut tf_domains = Vec::new();
    let mut tf_rules = Vec::new();

    if let Some(tf_key) = crate::config::effective_threatfox_auth_key(&runtime_config) {
        log_message("[*] Mengunduh IOC dari ThreatFox...");
        match fetch_threatfox_iocs(&tf_key) {
            Ok(body) => {
                let (ips, domains, rules) = parse_threatfox_iocs(&body);
                tf_ips = ips;
                tf_domains = domains;
                tf_rules = rules;
                log_message(&format!(
                    "[+] Berhasil mengunduh ThreatFox: {} IP, {} domain, {} hash rule.",
                    tf_ips.len(),
                    tf_domains.len(),
                    tf_rules.len()
                ));
            }
            Err(e) => {
                log_message(&format!("[-] Gagal mengunduh ThreatFox IOC: {}", e));
            }
        }
    } else {
        log_message("[-] ThreatFox: auth_key tidak dikonfigurasi, melewati sumber ini.");
    }

    let mut new_ips = feodo_ips;
    new_ips.extend(otx_ips);
    new_ips.extend(tf_ips);

    let mut new_domains = urlhaus_domains;
    new_domains.extend(otx_domains);
    new_domains.extend(tf_domains);

    let mut new_rules = otx_rules;
    new_rules.extend(tf_rules);

    if new_ips.is_empty() && new_domains.is_empty() && new_rules.is_empty() {
        return Err("Tidak ada threat feed baru yang berhasil diunduh.".into());
    }

    // 5. Load existing rules.json (local or installed location)
    let rules_path = crate::config::resolve_rules_path();
    let key_path = rules_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("rules.key");

    if !rules_path.exists() {
        return Err("rules.json tidak ditemukan.".into());
    }

    let data = fs::read_to_string(&rules_path)?;
    let mut config: crate::config::RulesConfig = serde_json::from_str(&data)?;

    // 6. Merge and deduplicate
    use std::collections::HashSet;

    let mut ip_set: HashSet<String> = config.network_blacklist.ips.into_iter().collect();
    for ip in new_ips {
        ip_set.insert(ip);
    }
    config.network_blacklist.ips = ip_set.into_iter().collect();

    let mut domain_set: HashSet<String> = config.network_blacklist.domains.into_iter().collect();
    for domain in new_domains {
        domain_set.insert(domain);
    }
    config.network_blacklist.domains = domain_set.into_iter().collect();

    let mut existing_sha256: HashSet<String> = HashSet::new();
    let mut existing_md5: HashSet<String> = HashSet::new();
    for rule in &config.rules {
        if let Some(ref hashes) = rule.signatures.hashes {
            if let Some(ref sha) = hashes.sha256 {
                existing_sha256.insert(sha.to_lowercase());
            }
            if let Some(ref md5) = hashes.md5 {
                existing_md5.insert(md5.to_lowercase());
            }
        }
    }

    for rule in new_rules {
        let mut is_dup = false;
        if let Some(ref hashes) = rule.signatures.hashes {
            if let Some(ref sha) = hashes.sha256
                && existing_sha256.contains(&sha.to_lowercase())
            {
                is_dup = true;
            }
            if let Some(ref md5) = hashes.md5
                && existing_md5.contains(&md5.to_lowercase())
            {
                is_dup = true;
            }
        }
        if !is_dup {
            if let Some(ref hashes) = rule.signatures.hashes {
                if let Some(ref sha) = hashes.sha256 {
                    existing_sha256.insert(sha.to_lowercase());
                }
                if let Some(ref md5) = hashes.md5 {
                    existing_md5.insert(md5.to_lowercase());
                }
            }
            config.rules.push(rule);
        }
    }

    // 7. Write back rules.json (only after all entries passed validation above)
    let updated_data = serde_json::to_string_pretty(&config)?;
    fs::write(&rules_path, updated_data)?;
    log_message("[+] Berkas rules.json berhasil diperbarui dengan feed terbaru.");

    // 8. Sign rules.json using rules.key if it exists
    if key_path.exists() {
        match crate::config::sign_rules(&rules_path, &key_path) {
            Ok(_) => {
                log_message("[+] Berhasil menandatangani rules.json dengan rules.key.");
            }
            Err(e) => {
                log_message(&format!("[-] Gagal menandatangani rules.json: {}", e));
            }
        }
    } else {
        log_message("[-] rules.key tidak ditemukan, melewati proses penandatanganan.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_bounded_enforces_size_limit() {
        let small = read_bounded(std::io::Cursor::new(b"abc".to_vec()), 10).unwrap();
        assert_eq!(small, b"abc");

        let big = read_bounded(std::io::Cursor::new(vec![b'x'; 100]), 10);
        assert!(
            big.is_err(),
            "oversized feed must be rejected, not truncated"
        );
    }

    #[test]
    fn test_parse_feodo_ips_handles_malformed_input() {
        let body = "\n# comment line\n192.168.1.1\n   \nnot-an-ip\n185.112.146.12\n300.1.1.1\n";
        let ips = parse_feodo_ips(body);
        assert_eq!(ips, vec!["192.168.1.1", "185.112.146.12"]);
    }

    #[test]
    fn test_parse_urlhaus_domains_handles_malformed_input() {
        let body = "\n# comment\n127.0.0.1 evil.example.com\n127.0.0.1\tsecond.example.net\n\
                    127.0.0.1 localhost\nnot-a-hostfile-line\n127.0.0.1\t\nmalformed.example.com/../\n\
                    8.8.8.8 evil2.example.org\n";
        let domains = parse_urlhaus_domains(body);
        assert_eq!(domains, vec!["evil.example.com", "second.example.net"]);
    }

    #[test]
    fn test_parse_otx_pulses_handles_various_indicator_types() {
        let sample_json = r#"{
            "count": 1,
            "next": "https://otx.alienvault.com/api/v1/pulses/subscribed?page=2",
            "results": [
                {
                    "id": "pulse123",
                    "name": "Malware Campaign Alpha",
                    "author_name": "AlienVault Team",
                    "TLP": "green",
                    "indicators": [
                        { "indicator": "198.51.100.42", "type": "IPv4" },
                        { "indicator": "bad.c2.example.org", "type": "domain" },
                        { "indicator": "host.attacker.com", "type": "hostname" },
                        { "indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "type": "FileHash-SHA256" },
                        { "indicator": "d41d8cd98f00b204e9800998ecf8427e", "type": "FileHash-MD5" },
                        { "indicator": "https://evil.example.com/payload.exe", "type": "URL" },
                        { "indicator": "CVE-2024-1234", "type": "CVE" },
                        { "indicator": "invalid-ip-999.999.999.999", "type": "IPv4" }
                    ]
                }
            ]
        }"#;

        let (ips, domains, rules) = parse_otx_pulses(sample_json);

        assert_eq!(ips, vec!["198.51.100.42"]);
        assert_eq!(domains, vec!["bad.c2.example.org", "host.attacker.com"]);
        assert_eq!(rules.len(), 2);

        // Check SHA256 rule
        let sha_rule = rules
            .iter()
            .find(|r| {
                r.signatures
                    .hashes
                    .as_ref()
                    .and_then(|h| h.sha256.as_deref())
                    .is_some()
            })
            .expect("SHA256 rule must exist");
        assert_eq!(
            sha_rule
                .signatures
                .hashes
                .as_ref()
                .unwrap()
                .sha256
                .as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(sha_rule.name, "Malware Campaign Alpha");
        assert!(sha_rule.description.contains("AlienVault Team"));
        assert_eq!(sha_rule.severity, "medium");

        // Check MD5 rule
        let md5_rule = rules
            .iter()
            .find(|r| {
                r.signatures
                    .hashes
                    .as_ref()
                    .and_then(|h| h.md5.as_deref())
                    .is_some()
            })
            .expect("MD5 rule must exist");
        assert_eq!(
            md5_rule.signatures.hashes.as_ref().unwrap().md5.as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
        assert_eq!(md5_rule.name, "Malware Campaign Alpha");
        assert!(md5_rule.description.contains("AlienVault Team"));
        assert_eq!(md5_rule.severity, "medium");
    }

    #[test]
    fn test_extract_otx_next_url() {
        let json_with_next = r#"{"count": 10, "next": "https://otx.alienvault.com/api/v1/pulses/subscribed?page=2", "results": []}"#;
        assert_eq!(
            extract_otx_next_url(json_with_next).as_deref(),
            Some("https://otx.alienvault.com/api/v1/pulses/subscribed?page=2")
        );

        let json_no_next = r#"{"count": 10, "next": null, "results": []}"#;
        assert_eq!(extract_otx_next_url(json_no_next), None);

        let json_empty_next = r#"{"count": 10, "next": "  ", "results": []}"#;
        assert_eq!(extract_otx_next_url(json_empty_next), None);
    }

    #[test]
    fn test_parse_threatfox_iocs_handles_various_ioc_types() {
        let sample_json = r#"{
            "query_status": "ok",
            "data": [
                {
                    "ioc": "evil.c2.example.com",
                    "ioc_type": "domain",
                    "threat_type": "botnet_cc",
                    "malware_printable": "Cobalt Strike",
                    "tags": ["ransomware", "c2"],
                    "confidence_level": 90
                },
                {
                    "ioc": "203.0.113.50:443",
                    "ioc_type": "ip:port",
                    "threat_type": "botnet_cc",
                    "malware_printable": "RedLine Stealer",
                    "tags": ["stealer"],
                    "confidence_level": 85
                },
                {
                    "ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "ioc_type": "sha256_hash",
                    "threat_type": "payload",
                    "malware_printable": "LockBit",
                    "tags": ["ransomware"],
                    "confidence_level": 95
                },
                {
                    "ioc": "d41d8cd98f00b204e9800998ecf8427e",
                    "ioc_type": "md5_hash",
                    "threat_type": "payload",
                    "malware_printable": "Suspicious Dropper",
                    "tags": ["dropper"],
                    "confidence_level": 30
                },
                {
                    "ioc": "https://threat.example.com/dl.bin",
                    "ioc_type": "url",
                    "threat_type": "payload_delivery",
                    "malware_printable": "Emotet",
                    "tags": ["emotet"],
                    "confidence_level": 100
                },
                {
                    "ioc": "invalid-ip-format:8080",
                    "ioc_type": "ip:port",
                    "threat_type": "botnet_cc",
                    "malware_printable": "Test",
                    "tags": [],
                    "confidence_level": 50
                }
            ]
        }"#;

        let (ips, domains, rules) = parse_threatfox_iocs(sample_json);

        assert_eq!(ips, vec!["203.0.113.50"]);
        assert_eq!(domains, vec!["evil.c2.example.com"]);
        assert_eq!(rules.len(), 2);

        let sha_rule = rules
            .iter()
            .find(|r| {
                r.signatures
                    .hashes
                    .as_ref()
                    .and_then(|h| h.sha256.as_deref())
                    .is_some()
            })
            .expect("SHA256 rule must exist");
        assert_eq!(
            sha_rule
                .signatures
                .hashes
                .as_ref()
                .unwrap()
                .sha256
                .as_deref(),
            Some("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        assert_eq!(sha_rule.name, "LockBit");
        assert_eq!(sha_rule.severity, "medium");
        assert!(sha_rule.description.contains("LockBit"));
        assert!(sha_rule.description.contains("ransomware"));

        let md5_rule = rules
            .iter()
            .find(|r| {
                r.signatures
                    .hashes
                    .as_ref()
                    .and_then(|h| h.md5.as_deref())
                    .is_some()
            })
            .expect("MD5 rule must exist");
        assert_eq!(
            md5_rule.signatures.hashes.as_ref().unwrap().md5.as_deref(),
            Some("d41d8cd98f00b204e9800998ecf8427e")
        );
        assert_eq!(md5_rule.name, "Suspicious Dropper");
        assert_eq!(md5_rule.severity, "low"); // Confidence 30 < 50
    }

    #[test]
    fn test_parse_threatfox_iocs_non_ok_query_status() {
        let no_result_json = r#"{
            "query_status": "no_result",
            "data": []
        }"#;
        let (ips, domains, rules) = parse_threatfox_iocs(no_result_json);
        assert!(ips.is_empty());
        assert!(domains.is_empty());
        assert!(rules.is_empty());

        let error_json = r#"{
            "query_status": "illegal_search_term"
        }"#;
        let (ips, domains, rules) = parse_threatfox_iocs(error_json);
        assert!(ips.is_empty());
        assert!(domains.is_empty());
        assert!(rules.is_empty());
    }

    #[test]
    fn test_parse_feed_never_panics_on_garbage() {
        // Binary garbage / weird encodings must be skipped, never panic.
        let garbage: Vec<u8> = (0..=255).cycle().take(4096).collect();
        let body = String::from_utf8_lossy(&garbage);
        let _ = parse_feodo_ips(&body);
        let _ = parse_urlhaus_domains(&body);
        let _ = parse_otx_pulses(&body);
        let _ = parse_threatfox_iocs(&body);
    }

    #[test]
    fn test_hash_rule_deduplication() {
        use std::collections::HashSet;

        let otx_json = r#"{
            "count": 1,
            "results": [
                {
                    "name": "OTX Rule 1",
                    "author_name": "Author 1",
                    "indicators": [
                        { "indicator": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "type": "FileHash-SHA256" }
                    ]
                }
            ]
        }"#;

        let tf_json = r#"{
            "query_status": "ok",
            "data": [
                {
                    "ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    "ioc_type": "sha256_hash",
                    "malware_printable": "Duplicate Malware",
                    "tags": ["tag"],
                    "confidence_level": 90
                },
                {
                    "ioc": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "ioc_type": "sha256_hash",
                    "malware_printable": "Unique Malware",
                    "tags": ["tag"],
                    "confidence_level": 90
                }
            ]
        }"#;

        let (_, _, otx_rules) = parse_otx_pulses(otx_json);
        let (_, _, tf_rules) = parse_threatfox_iocs(tf_json);

        let mut config_rules: Vec<crate::config::Rule> = Vec::new();
        let mut existing_sha256: HashSet<String> = HashSet::new();
        let mut existing_md5: HashSet<String> = HashSet::new();

        let mut all_new_rules = otx_rules;
        all_new_rules.extend(tf_rules);

        for rule in all_new_rules {
            let mut is_dup = false;
            if let Some(ref hashes) = rule.signatures.hashes {
                if let Some(ref sha) = hashes.sha256
                    && existing_sha256.contains(&sha.to_lowercase())
                {
                    is_dup = true;
                }
                if let Some(ref md5) = hashes.md5
                    && existing_md5.contains(&md5.to_lowercase())
                {
                    is_dup = true;
                }
            }
            if !is_dup {
                if let Some(ref hashes) = rule.signatures.hashes {
                    if let Some(ref sha) = hashes.sha256 {
                        existing_sha256.insert(sha.to_lowercase());
                    }
                    if let Some(ref md5) = hashes.md5 {
                        existing_md5.insert(md5.to_lowercase());
                    }
                }
                config_rules.push(rule);
            }
        }

        assert_eq!(config_rules.len(), 2);
        assert_eq!(config_rules[0].name, "OTX Rule 1");
        assert_eq!(config_rules[1].name, "Unique Malware");
    }
}
