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

/// Downloads Feodo Tracker and URLhaus feeds, parses them, merges them into rules.json,
/// and signs the new rules.json using rules.key.
// Note: do not use em dash anywhere in output
pub fn update_threat_feed() -> Result<(), Box<dyn std::error::Error>> {
    log_message("[*] Memulai pembaruan threat feed...");

    // 1. Download Feodo Tracker IP Blocklist
    let mut new_ips = Vec::new();
    match fetch_feed_body("https://feodotracker.abuse.ch/downloads/ipblocklist.txt") {
        Ok(body) => {
            new_ips = parse_feodo_ips(&body);
            log_message(&format!(
                "[+] Berhasil mengunduh {} IP dari Feodo Tracker.",
                new_ips.len()
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
    let mut new_domains = Vec::new();
    match fetch_feed_body("https://urlhaus.abuse.ch/downloads/hostfile/") {
        Ok(body) => {
            new_domains = parse_urlhaus_domains(&body);
            log_message(&format!(
                "[+] Berhasil mengunduh {} domain dari URLhaus.",
                new_domains.len()
            ));
        }
        Err(e) => {
            log_message(&format!("[-] Gagal mengunduh URLhaus host list: {}", e));
        }
    }

    if new_ips.is_empty() && new_domains.is_empty() {
        return Err("Tidak ada threat feed baru yang berhasil diunduh.".into());
    }

    // 3. Load existing rules.json (local or installed location)
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

    // 4. Merge and deduplicate
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

    // 5. Write back rules.json (only after all entries passed validation above)
    let updated_data = serde_json::to_string_pretty(&config)?;
    fs::write(&rules_path, updated_data)?;
    log_message("[+] Berkas rules.json berhasil diperbarui dengan feed terbaru.");

    // 6. Sign rules.json using rules.key if it exists
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
    fn test_parse_feed_never_panics_on_garbage() {
        // Binary garbage / weird encodings must be skipped, never panic.
        let garbage: Vec<u8> = (0..=255).cycle().take(4096).collect();
        let body = String::from_utf8_lossy(&garbage);
        let _ = parse_feodo_ips(&body);
        let _ = parse_urlhaus_domains(&body);
    }
}
