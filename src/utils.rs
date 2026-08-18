use std::collections::VecDeque;
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

static LOG_BUFFER: OnceLock<Mutex<VecDeque<String>>> = OnceLock::new();

/// Formats a Unix epoch timestamp (seconds) into a readable UTC+7 (Jakarta / WIB) string.
pub fn format_wib_timestamp(epoch_secs: u64) -> String {
    let s = epoch_secs.saturating_add(7 * 3600);
    let sec = s % 60;
    let min = (s / 60) % 60;
    let hour = (s / 3600) % 24;
    let days = s / 86400;

    // Civil date algorithm from Euclidean Affine Days
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe.saturating_sub(doe / 1460) + doe / 36524).saturating_sub(doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let final_y = if m <= 2 { y + 1 } else { y };

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} WIB",
        final_y, m, d, hour, min, sec
    )
}

/// Logs a message to stdout and adds it to the global real-time logs memory buffer with UTC+7 (WIB) time
pub fn log_message(msg: &str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let wib_str = format_wib_timestamp(now);
    // Format: [timestamp] [YYYY-MM-DD HH:MM:SS WIB] Message
    let formatted = format!("[{}] [{}] {}", now, wib_str, msg);
    println!("{}", formatted);
    // Flush so log output is real-time (e.g. `tail -f`) and survives process::exit.
    let _ = std::io::stdout().flush();

    let buffer = LOG_BUFFER.get_or_init(|| Mutex::new(VecDeque::with_capacity(100)));
    if let Ok(mut lock) = buffer.lock() {
        if lock.len() >= 100 {
            lock.pop_front();
        }
        lock.push_back(formatted);
    }
}

/// Retrieves all log messages from the global memory buffer
pub fn get_logs() -> Vec<String> {
    let buffer = LOG_BUFFER.get_or_init(|| Mutex::new(VecDeque::with_capacity(100)));
    if let Ok(lock) = buffer.lock() {
        lock.iter().cloned().collect()
    } else {
        Vec::new()
    }
}

/// Fires a Linux desktop notification (via notify-send) for threat detections.
/// Silently no-ops when notify-send is unavailable or no notification daemon
/// is running, so it is safe to call unconditionally.
pub fn notify_desktop(title: &str, body: &str) {
    let title: String = title.chars().take(60).collect();
    let body: String = body.chars().take(250).collect();

    if let Ok(mut child) = Command::new("notify-send")
        .arg("-u")
        .arg("critical")
        .arg("-a")
        .arg("FerroShield")
        .arg("-i")
        .arg("dialog-warning")
        .arg(&title)
        .arg(&body)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        let _ = child.wait();
    }
}

/// Logs a threat detection and fires a desktop notification for it.
pub fn log_detection(msg: &str) {
    log_message(msg);
    notify_desktop("FerroShield - Indikasi Ancaman", msg);
}

/// Blocks until SIGTERM or SIGINT is received, then cleans up (hosts blocklist)
/// and exits gracefully. Call this from a dedicated thread in the daemon.
pub fn wait_for_shutdown_signal() {
    use signal_hook::consts::signal::{SIGINT, SIGTERM};
    use signal_hook::iterator::Signals;

    let mut signals = match Signals::new([SIGINT, SIGTERM]) {
        Ok(s) => s,
        Err(e) => {
            log_message(&format!(
                "[-] Gagal mendaftarkan penangan sinyal: {}. Menjalankan tanpa shutdown bersih.",
                e
            ));
            return;
        }
    };

    // Block until a shutdown signal arrives (we exit after the first one anyway).
    if let Some(_sig) = signals.forever().next() {
        log_message("[*] Menerima sinyal penghentian. Membersihkan dan menutup FerroShield...");
        if let Err(e) = crate::browser::clean_hosts_file() {
            log_message(&format!(
                "[-] Gagal membersihkan /etc/hosts saat shutdown: {}",
                e
            ));
        }
        log_message("[+] FerroShield ditutup dengan bersih.");
        std::process::exit(0);
    }
}

pub fn drop_capabilities() -> Result<(), Box<dyn std::error::Error>> {
    use caps::{CapSet, Capability};
    use std::collections::HashSet;

    log_message("[*] Menurunkan hak akses daemon (Capability Dropping)...");

    let mut retain = HashSet::new();
    retain.insert(Capability::CAP_NET_ADMIN);
    retain.insert(Capability::CAP_NET_RAW);
    retain.insert(Capability::CAP_KILL);
    retain.insert(Capability::CAP_DAC_OVERRIDE);

    // Clear Inheritable
    let _ = caps::clear(None, CapSet::Inheritable);

    // Set Permitted capabilities (this drops all others)
    caps::set(None, CapSet::Permitted, &retain)?;

    // Set Effective capabilities
    caps::set(None, CapSet::Effective, &retain)?;

    log_message(
        "[+] Capability Dropping berhasil! Mempertahankan: CAP_NET_ADMIN, CAP_NET_RAW, CAP_KILL, CAP_DAC_OVERRIDE.",
    );
    Ok(())
}

type WhitelistCache = Option<(SystemTime, Vec<String>)>;
static WHITELIST_CACHE: OnceLock<Mutex<WhitelistCache>> = OnceLock::new();

/// Loads the whitelist of file paths from whitelist.json with caching based on file modification time
pub fn load_whitelist() -> Vec<String> {
    let path = std::path::Path::new("whitelist.json");
    if !path.exists() {
        return Vec::new();
    }

    let metadata = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Vec::new(),
    };

    let mtime = match metadata.modified() {
        Ok(t) => t,
        Err(_) => return Vec::new(),
    };

    let cache_mutex = WHITELIST_CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(mut lock) = cache_mutex.lock() {
        if let Some((cached_time, ref list)) = *lock
            && cached_time == mtime
        {
            return list.clone();
        }

        // Cache miss or modified: reload file
        if let Ok(content) = std::fs::read_to_string(path) {
            let list: Vec<String> = serde_json::from_str(&content).unwrap_or_default();
            *lock = Some((mtime, list.clone()));
            list
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    }
}

/// Adds an item (file path, domain, IP) to whitelist.json and updates cache
pub fn add_to_whitelist(item: &str) -> std::io::Result<()> {
    let mut whitelist = load_whitelist();
    let trimmed = item.trim().to_string();
    if !whitelist.contains(&trimmed) {
        whitelist.push(trimmed);
        let content = serde_json::to_string_pretty(&whitelist)?;
        std::fs::write("whitelist.json", content)?;

        // Update cache immediately
        let cache_mutex = WHITELIST_CACHE.get_or_init(|| Mutex::new(None));
        if let Ok(mut lock) = cache_mutex.lock()
            && let Ok(metadata) = std::fs::metadata("whitelist.json")
            && let Ok(mtime) = metadata.modified()
        {
            *lock = Some((mtime, whitelist.clone()));
        }
    }
    Ok(())
}

/// Removes an item (file path, domain, or IP) from whitelist.json and updates cache
pub fn remove_from_whitelist(item: &str) -> std::io::Result<bool> {
    let mut whitelist = load_whitelist();
    let initial_len = whitelist.len();
    let trimmed = item.trim();
    whitelist.retain(|x| x.trim() != trimmed);
    if whitelist.len() != initial_len {
        let content = serde_json::to_string_pretty(&whitelist)?;
        std::fs::write("whitelist.json", content)?;

        let cache_mutex = WHITELIST_CACHE.get_or_init(|| Mutex::new(None));
        if let Ok(mut lock) = cache_mutex.lock()
            && let Ok(metadata) = std::fs::metadata("whitelist.json")
            && let Ok(mtime) = metadata.modified()
        {
            *lock = Some((mtime, whitelist.clone()));
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Checks if an item (path, domain, IP) is in the whitelist (case-insensitive with subdomain support)
pub fn is_whitelisted(item: &str) -> bool {
    let whitelist = load_whitelist();
    let item_clean = item.trim().trim_end_matches('.').to_lowercase();
    if item_clean.is_empty() {
        return false;
    }
    whitelist.iter().any(|entry| {
        let entry_clean = entry.trim().trim_end_matches('.').to_lowercase();
        if entry_clean.is_empty() {
            return false;
        }
        if entry_clean == item_clean {
            return true;
        }
        // Subdomain matching: if entry is "example.com", matches "sub.example.com"
        if entry_clean.contains('.') && item_clean.ends_with(&format!(".{}", entry_clean)) {
            return true;
        }
        false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_wib_timestamp() {
        // 2026-08-18 04:45:00 UTC (1787028300) -> 2026-08-18 11:45:00 WIB
        let formatted = format_wib_timestamp(1787028300);
        assert!(formatted.contains("2026-08-18 11:45:00 WIB"));

        // 2024-01-01 00:00:00 UTC (1704067200) -> 2024-01-01 07:00:00 WIB
        let formatted_2024 = format_wib_timestamp(1704067200);
        assert_eq!(formatted_2024, "2024-01-01 07:00:00 WIB");
    }
}
