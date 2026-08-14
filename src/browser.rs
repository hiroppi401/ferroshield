use crate::quarantine::QuarantineManager;
use crate::scanner::Scanner;
use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, RecvTimeoutError};
use std::time::Duration;

/// How often the downloads watcher re-discovers user download folders so that
/// accounts created after the daemon started are picked up automatically.
const DOWNLOADS_RESCAN_INTERVAL: Duration = Duration::from_secs(15);

/// Resolves the home directory for a given username by looking it up in
/// `/etc/passwd`, falling back to `/home/<name>` when the user is not listed.
pub fn get_home_dir_for_user(user: &str) -> Option<PathBuf> {
    get_home_dir_for_user_from("/etc/passwd", user)
}

/// Same as `get_home_dir_for_user` but reads the passwd database from the
/// given path so tests can inject a fixture.
pub fn get_home_dir_for_user_from<P: AsRef<Path>>(passwd_path: P, user: &str) -> Option<PathBuf> {
    if let Ok(file) = std::fs::File::open(passwd_path.as_ref()) {
        let reader = std::io::BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 && parts[0] == user {
                let home = PathBuf::from(parts[5]);
                if home.exists() {
                    return Some(home);
                }
            }
        }
    }
    let fallback = PathBuf::from(format!("/home/{}", user));
    fallback.exists().then_some(fallback)
}

/// Returns a list of home directories for all human users on the system.
pub fn get_all_user_home_dirs() -> Vec<PathBuf> {
    let mut homes = Vec::new();

    // 1. If running under sudo, resolve the sudo user's real home dir
    if let Ok(sudo_user) = std::env::var("SUDO_USER")
        && sudo_user != "root"
        && let Some(path) = get_home_dir_for_user(&sudo_user)
        && !homes.contains(&path)
    {
        homes.push(path);
    }

    // 2. Check HOME env var if it's not root/slash
    if let Ok(home_env) = std::env::var("HOME") {
        let path = PathBuf::from(home_env);
        if path.exists() && path != *"/root" && path != *"/" && !homes.contains(&path) {
            homes.push(path);
        }
    }

    // 3. Scan /etc/passwd for human users (UID >= 1000 and < 60000)
    if let Ok(file) = std::fs::File::open("/etc/passwd") {
        let reader = std::io::BufReader::new(file);
        for line in reader.lines().map_while(Result::ok) {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() >= 6 {
                let uid_str = parts[2];
                let home_dir_str = parts[5];
                if let Ok(uid) = uid_str.parse::<u32>()
                    && (1000..60000).contains(&uid)
                {
                    let path = PathBuf::from(home_dir_str);
                    if path.exists() && !homes.contains(&path) {
                        homes.push(path);
                    }
                }
            }
        }
    }

    // 4. Traversal of /home directory
    if let Ok(entries) = std::fs::read_dir("/home") {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() && !homes.contains(&path) {
                homes.push(path);
            }
        }
    }

    // 5. If still empty, fallback to HOME even if it is root
    if homes.is_empty()
        && let Ok(home_env) = std::env::var("HOME")
    {
        homes.push(PathBuf::from(home_env));
    }

    homes
}

/// Reads `~/.config/user-dirs.dirs` and returns the configured XDG download
/// directory, honoring localized/custom download folder names set up by the
/// desktop environment (e.g. "Descargas", "Téléchargements").
pub fn get_xdg_download_dir(home: &Path) -> Option<PathBuf> {
    let dirs_file = home.join(".config/user-dirs.dirs");
    let content = std::fs::read_to_string(dirs_file).ok()?;
    for line in content.lines() {
        let line = line.trim();
        if !line.starts_with("XDG_DOWNLOAD_DIR=") {
            continue;
        }
        let value = line
            .trim_start_matches("XDG_DOWNLOAD_DIR=")
            .trim()
            .trim_matches('"')
            .trim_matches('\'');
        if value.is_empty() {
            return None;
        }
        let expanded = expand_xdg_home(home, value);
        return expanded.exists().then_some(expanded);
    }
    None
}

/// Expands `$HOME`/`${HOME}` inside a user-dirs value to the given home path.
fn expand_xdg_home(home: &Path, value: &str) -> PathBuf {
    if value == "$HOME" || value == "${HOME}" {
        return home.to_path_buf();
    }
    let home_str = home.to_string_lossy();
    PathBuf::from(
        value
            .replace("${HOME}", &home_str)
            .replace("$HOME", &home_str),
    )
}

/// Returns the Downloads directories for the users on the system.
/// Checks configured custom path, env var, and falls back to scanning all user home directories.
pub fn get_downloads_dirs(custom_path: Option<&str>) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    // 1. Check custom path from settings/argument
    if let Some(path_str) = custom_path {
        let path = PathBuf::from(path_str);
        if path.exists() {
            paths.push(path);
        }
    }

    // 2. Check environment variable DOWNLOADS_DIR
    if let Ok(env_dir) = std::env::var("DOWNLOADS_DIR") {
        let path = PathBuf::from(env_dir);
        if path.exists() && !paths.contains(&path) {
            paths.push(path);
        }
    }

    // 3. Scan all human user home directories
    let user_homes = get_all_user_home_dirs();
    for home in user_homes {
        // 3a. Honor the desktop-environment configured download folder (XDG)
        if let Some(xdg) = get_xdg_download_dir(&home)
            && xdg != home
            && !paths.contains(&xdg)
        {
            paths.push(xdg);
        }
        let downloads = home.join("Downloads");
        if downloads.exists() && !paths.contains(&downloads) {
            paths.push(downloads);
        }
        let unduhan = home.join("Unduhan");
        if unduhan.exists() && !paths.contains(&unduhan) {
            paths.push(unduhan);
        }
    }

    paths
}

/// Returns download directories that are not yet being watched.
pub fn find_unwatched_dirs(
    watched: &HashSet<PathBuf>,
    custom_path: Option<&str>,
) -> Vec<PathBuf> {
    get_downloads_dirs(custom_path)
        .into_iter()
        .filter(|p| !watched.contains(p))
        .collect()
}

/// Watches the downloads directories for new files and scans them immediately.
/// Periodically re-discovers the download directories, so folders belonging to
/// users created after the daemon started are watched automatically.
pub fn watch_downloads_directories(
    initial_paths: &[PathBuf],
    custom_path: Option<&str>,
    scanner: Scanner,
    quarantine_mgr: QuarantineManager,
    action: &str,
) -> notify::Result<()> {
    let (tx, rx) = channel();

    // Create a watcher with default config
    let mut watcher = RecommendedWatcher::new(tx, Config::default())?;

    let mut watched: HashSet<PathBuf> = HashSet::new();
    for path in initial_paths {
        watcher.watch(path, RecursiveMode::NonRecursive)?;
        watched.insert(path.clone());
        println!(
            "[*] Real-time Browser Guard: Watching folder {:?} for new downloads...",
            path
        );
    }

    loop {
        match rx.recv_timeout(DOWNLOADS_RESCAN_INTERVAL) {
            Ok(Ok(event)) => {
                handle_watch_event(event, &scanner, &quarantine_mgr, action);
            }
            Ok(Err(e)) => eprintln!("[-] Watcher error: {:?}", e),
            Err(RecvTimeoutError::Timeout) => {
                for new_path in find_unwatched_dirs(&watched, custom_path) {
                    if let Err(e) = watcher.watch(&new_path, RecursiveMode::NonRecursive) {
                        eprintln!(
                            "[-] Error watching new download folder {:?}: {}",
                            new_path, e
                        );
                    } else {
                        watched.insert(new_path.clone());
                        println!(
                            "[*] Real-time Browser Guard: Watching new folder {:?} for new downloads...",
                            new_path
                        );
                    }
                }
            }
            Err(RecvTimeoutError::Disconnected) => {
                eprintln!("[-] Download watcher channel disconnected, stopping.");
                return Ok(());
            }
        }
    }
}

/// Scans a newly created/modified file in a watched download folder.
fn handle_watch_event(
    event: notify::Event,
    scanner: &Scanner,
    quarantine_mgr: &QuarantineManager,
    action: &str,
) {
    // We are interested in file creations, modifications, or renames (browsers rename temp files after download)
    if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
        return;
    }

    for path in event.paths {
        // Skip temporary files (Chrome uses .crdownload, Firefox uses .part)
        if let Some(ext) = path.extension()
            && (ext == "crdownload" || ext == "part" || ext == "tmp")
        {
            continue;
        }

        if path.is_file() {
            // Give the browser a split second to finish writing the file handle
            std::thread::sleep(Duration::from_millis(500));
            println!("[*] Browser Guard: Detecting new file: {:?}", path);

            if let Some(scan_res) = scanner.scan_file(&path) {
                for rule in &scan_res.triggered_rules {
                    crate::utils::log_detection(&format!(
                        "[!] MALWARE DETECTED in downloaded file: {:?} -> Rule: {} (Severity: {})",
                        scan_res.file_path, rule.name, rule.severity
                    ));
                }

                if action == "delete" {
                    match fs::remove_file(&path) {
                        Ok(_) => println!(
                            "[+] Successfully deleted malicious file permanently: {}",
                            scan_res.file_path
                        ),
                        Err(e) => eprintln!(
                            "[-] Error deleting malicious file {}: {}",
                            scan_res.file_path, e
                        ),
                    }
                } else {
                    // Get the sha256 to use as an identifier in quarantine
                    if let Ok((sha256, _)) = scanner.calculate_hashes(&path) {
                        let rule_id = scan_res
                            .triggered_rules
                            .first()
                            .map(|r| r.id.as_str())
                            .unwrap_or("BROWSER-GUARD");
                        match quarantine_mgr
                            .quarantine_file(&path, &sha256, rule_id)
                        {
                            Ok(q_id) => println!(
                                "[+] Successfully quarantined file: {} -> ID: {}",
                                scan_res.file_path, q_id
                            ),
                            Err(e) => eprintln!(
                                "[-] Error quarantining downloaded file {}: {}",
                                scan_res.file_path, e
                            ),
                        }
                    }
                }
            }
        }
    }
}

/// Scans installed extensions in Google Chrome and Firefox for blacklisted extension IDs.
pub fn scan_browser_extensions(blacklisted_ids: &[String]) -> Vec<String> {
    let mut detected = Vec::new();
    let home_paths = get_all_user_home_dirs();

    for home_path in home_paths {
        // Chrome standard extension path
        let chrome_paths = vec![
            home_path.join(".config/google-chrome/Default/Extensions"),
            home_path.join(".config/chromium/Default/Extensions"),
        ];

        for path in chrome_paths {
            if path.exists()
                && let Ok(entries) = fs::read_dir(path)
            {
                for entry in entries.filter_map(Result::ok) {
                    if let Some(ext_id) = entry.file_name().to_str()
                        && blacklisted_ids.contains(&ext_id.to_string())
                    {
                        detected.push(format!(
                            "Chrome Extension ID: {} (User: {})",
                            ext_id,
                            home_path.display()
                        ));
                    }
                }
            }
        }

        // Firefox profile extensions scanner
        let firefox_profiles_dir = home_path.join(".mozilla/firefox");
        if firefox_profiles_dir.exists()
            && let Ok(entries) = fs::read_dir(firefox_profiles_dir)
        {
            for entry in entries.filter_map(Result::ok) {
                let profile_path = entry.path();
                if profile_path.is_dir() {
                    let ext_dir = profile_path.join("extensions");
                    if ext_dir.exists()
                        && let Ok(ext_entries) = fs::read_dir(ext_dir)
                    {
                        for ext_entry in ext_entries.filter_map(Result::ok) {
                            if let Some(file_name) = ext_entry.file_name().to_str() {
                                for id in blacklisted_ids {
                                    if file_name.contains(id) {
                                        detected.push(format!(
                                            "Firefox Extension: {} (User: {})",
                                            file_name,
                                            home_path.display()
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    detected
}

/// Appends blacklisted domains to `/etc/hosts` pointing to 127.0.0.1 to sinkhole traffic.
pub fn block_domains_in_hosts(domains: &[String]) -> io::Result<()> {
    let hosts_path = "/etc/hosts";
    if !Path::new(hosts_path).exists() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "hosts file not found",
        ));
    }

    // 1. Read existing hosts to find out what's already blocked
    let file = fs::File::open(hosts_path)?;
    let reader = BufReader::new(file);
    let mut blocked_set = std::collections::HashSet::new();

    for line_res in reader.lines() {
        let line = line_res?;
        if line.contains("# ferroshield-block") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                blocked_set.insert(parts[1].to_string());
            }
        }
    }

    // 2. Open /etc/hosts in append mode
    let mut file = OpenOptions::new().append(true).open(hosts_path)?;

    for domain in domains {
        if !blocked_set.contains(domain) {
            println!("[!] Blocking malicious domain: {} via /etc/hosts", domain);
            writeln!(file, "127.0.0.1\t{}\t# ferroshield-block", domain)?;
        }
    }

    Ok(())
}

/// Removes all ferroshield-blocked domains from `/etc/hosts`
pub fn clean_hosts_file() -> io::Result<()> {
    let hosts_path = "/etc/hosts";
    let file = fs::File::open(hosts_path)?;
    let reader = BufReader::new(file);
    let mut new_lines = Vec::new();
    let mut cleaned_any = false;

    for line_res in reader.lines() {
        let line = line_res?;
        if line.contains("# ferroshield-block") {
            cleaned_any = true;
            continue;
        }
        new_lines.push(line);
    }

    if cleaned_any {
        println!("[*] Cleaning FerroShield blocklists from /etc/hosts...");
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(hosts_path)?;
        for line in new_lines {
            writeln!(file, "{}", line)?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "ferroshield_browser_test_{}_{}_{}",
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

    #[test]
    fn test_get_home_dir_for_user_from_resolves_passwd() {
        let root = temp_dir("passwd");
        let home_foo = root.join("users/foo");
        fs::create_dir_all(&home_foo).unwrap();
        let passwd = root.join("passwd");
        fs::write(
            &passwd,
            format!(
                "foo:x:1000:1000:foo:{}:/bin/bash\n",
                home_foo.display()
            ),
        )
        .unwrap();

        assert_eq!(
            get_home_dir_for_user_from(&passwd, "foo").unwrap(),
            home_foo
        );
        assert!(get_home_dir_for_user_from(&passwd, "missing").is_none());
        assert!(get_home_dir_for_user_from(root.join("no-such-file"), "foo").is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_get_xdg_download_dir_absolute_path() {
        let root = temp_dir("xdg_abs");
        let home = root.join("home/u");
        let download = root.join("custom-downloads");
        fs::create_dir_all(home.join(".config")).unwrap();
        fs::create_dir_all(&download).unwrap();
        fs::write(
            home.join(".config/user-dirs.dirs"),
            format!("# comment line\nXDG_DOWNLOAD_DIR={}\nXDG_DESKTOP_DIR=\"$HOME/Desktop\"\n", download.display()),
        )
        .unwrap();

        assert_eq!(get_xdg_download_dir(&home).unwrap(), download);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_get_xdg_download_dir_expands_home() {
        let root = temp_dir("xdg_home");
        let home = root.join("home/u");
        let download = home.join("Download");
        fs::create_dir_all(home.join(".config")).unwrap();
        fs::create_dir_all(&download).unwrap();
        fs::write(
            home.join(".config/user-dirs.dirs"),
            "XDG_DOWNLOAD_DIR=\"$HOME/Download\"\n",
        )
        .unwrap();

        assert_eq!(get_xdg_download_dir(&home).unwrap(), download);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_get_xdg_download_dir_missing() {
        let root = temp_dir("xdg_missing");
        let home = root.join("home/u");
        fs::create_dir_all(&home).unwrap();

        assert!(get_xdg_download_dir(&home).is_none());

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_get_downloads_dirs_includes_custom_path() {
        let root = temp_dir("dl_custom");
        let download = root.join("Downloads");
        fs::create_dir_all(&download).unwrap();
        let custom = download.to_str().unwrap().to_string();

        let dirs = get_downloads_dirs(Some(&custom));
        assert!(dirs.contains(&download));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn test_find_unwatched_dirs() {
        let root = temp_dir("unwatched");
        let download = root.join("Downloads");
        fs::create_dir_all(&download).unwrap();
        let custom = download.to_str().unwrap().to_string();

        let watched = HashSet::from([download.clone()]);
        let new = find_unwatched_dirs(&watched, Some(&custom));
        assert!(!new.contains(&download), "watched dir must not be returned");

        let fresh = HashSet::new();
        let new2 = find_unwatched_dirs(&fresh, Some(&custom));
        assert!(new2.contains(&download), "unwatched dir must be returned");

        let _ = fs::remove_dir_all(&root);
    }
}
