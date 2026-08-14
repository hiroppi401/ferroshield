use crate::utils::log_message;
use std::fs;
use std::path::Path;
use std::time::Duration;

/// Downloads Feodo Tracker and URLhaus feeds, parses them, merges them into rules.json,
/// and signs the new rules.json using rules.key.
// Note: do not use em dash anywhere in output
pub fn update_threat_feed() -> Result<(), Box<dyn std::error::Error>> {
    log_message("[*] Memulai pembaruan threat feed...");

    // 1. Download Feodo Tracker IP Blocklist
    let mut new_ips = Vec::new();
    match ureq::get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
        .timeout(Duration::from_secs(15))
        .call()
    {
        Ok(resp) => {
            if let Ok(body) = resp.into_string() {
                for line in body.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    if line.parse::<std::net::Ipv4Addr>().is_ok() {
                        new_ips.push(line.to_string());
                    }
                }
                log_message(&format!(
                    "[+] Berhasil mengunduh {} IP dari Feodo Tracker.",
                    new_ips.len()
                ));
            }
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
    match ureq::get("https://urlhaus.abuse.ch/downloads/hostfile/")
        .timeout(Duration::from_secs(15))
        .call()
    {
        Ok(resp) => {
            if let Ok(body) = resp.into_string() {
                for line in body.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') {
                        continue;
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() == 2 && parts[0] == "127.0.0.1" {
                        new_domains.push(parts[1].to_string());
                    }
                }
                log_message(&format!(
                    "[+] Berhasil mengunduh {} domain dari URLhaus.",
                    new_domains.len()
                ));
            }
        }
        Err(e) => {
            log_message(&format!("[-] Gagal mengunduh URLhaus host list: {}", e));
        }
    }

    if new_ips.is_empty() && new_domains.is_empty() {
        return Err("Tidak ada threat feed baru yang berhasil diunduh.".into());
    }

    // 3. Load existing rules.json
    let rules_path = "rules.json";
    let key_path = "rules.key";

    if !Path::new(rules_path).exists() {
        return Err("rules.json tidak ditemukan.".into());
    }

    let data = fs::read_to_string(rules_path)?;
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

    // 5. Write back rules.json
    let updated_data = serde_json::to_string_pretty(&config)?;
    fs::write(rules_path, updated_data)?;
    log_message("[+] Berkas rules.json berhasil diperbarui dengan feed terbaru.");

    // 6. Sign rules.json using rules.key if it exists
    if Path::new(key_path).exists() {
        match crate::config::sign_rules(rules_path, key_path) {
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
