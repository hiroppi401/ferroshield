use crate::quarantine::QuarantineManager;
use crate::scanner::{ScanResult, Scanner};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

const SKIP_PREFIXES: [&str; 6] = [
    "/proc/",
    "/sys/",
    "/dev/",
    "/run/",
    "/tmp/",
    "/var/lib/ferroshield/quarantine/",
];

fn should_skip(path_str: &str) -> bool {
    SKIP_PREFIXES.iter().any(|p| path_str.starts_with(p))
        || path_str.contains(".quarantine/")
        || path_str.ends_with(".quarantine")
}

#[derive(Serialize, Deserialize, Clone)]
pub struct SimpleScanResult {
    pub file_path: String,
    #[serde(default)]
    pub rule_ids: Vec<String>,
    pub rules: Vec<String>,
}

impl SimpleScanResult {
    fn from_scan_result(res: &ScanResult) -> Self {
        Self {
            file_path: res.file_path.clone(),
            rule_ids: res.triggered_rules.iter().map(|r| r.id.clone()).collect(),
            rules: res.triggered_rules.iter().map(|r| r.name.clone()).collect(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct ScanProgress {
    pub status: String,
    pub target_path: String,
    pub total_files: usize,
    pub scanned_files: usize,
    pub current_file: String,
    pub threats_found: usize,
    pub results: Vec<SimpleScanResult>,
    pub error: Option<String>,
}

impl ScanProgress {
    pub fn idle() -> Self {
        Self {
            status: "idle".to_string(),
            target_path: String::new(),
            total_files: 0,
            scanned_files: 0,
            current_file: String::new(),
            threats_found: 0,
            results: Vec::new(),
            error: None,
        }
    }

    pub fn from_state(state: &ScanState, scanned: usize, total: usize, current: &str) -> Self {
        Self {
            status: state.status.clone(),
            target_path: state.target_path.clone(),
            total_files: total,
            scanned_files: scanned,
            current_file: current.to_string(),
            threats_found: state.threats_found,
            results: state.results.clone(),
            error: state.error.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ScanState {
    pub target_path: String,
    pub delete: bool,
    pub status: String,
    pub total_files: usize,
    pub scanned_files: HashSet<String>,
    pub threats_found: usize,
    pub results: Vec<SimpleScanResult>,
    pub error: Option<String>,
}

impl ScanState {
    pub fn new(target_path: String, delete: bool) -> Self {
        Self {
            target_path,
            delete,
            status: "idle".to_string(),
            total_files: 0,
            scanned_files: HashSet::new(),
            threats_found: 0,
            results: Vec::new(),
            error: None,
        }
    }
}

#[derive(Serialize, Deserialize, Default, Clone)]
struct ScanControl {
    command: String,
}

pub fn state_path(quarantine_dir: &Path) -> PathBuf {
    quarantine_dir
        .parent()
        .unwrap_or(quarantine_dir)
        .join("scan_state.json")
}

pub fn control_path(quarantine_dir: &Path) -> PathBuf {
    quarantine_dir
        .parent()
        .unwrap_or(quarantine_dir)
        .join("scan_control.json")
}

pub fn scan_pid_path(quarantine_dir: &Path) -> PathBuf {
    quarantine_dir
        .parent()
        .unwrap_or(quarantine_dir)
        .join("scan.pid")
}

pub fn save_scan_state(path: &Path, state: &ScanState) {
    if let Ok(json) = serde_json::to_string(state) {
        let _ = fs::write(path, json);
    }
}

pub fn load_scan_state(path: &Path) -> Option<ScanState> {
    let data = fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
}

pub fn write_control(path: &Path, command: &str) {
    let ctl = ScanControl {
        command: command.to_string(),
    };
    if let Ok(json) = serde_json::to_string(&ctl) {
        let _ = fs::write(path, json);
    }
}

pub fn clear_control(path: &Path) {
    let _ = fs::remove_file(path);
}

fn read_control(path: &Path) -> String {
    fs::read_to_string(path)
        .ok()
        .and_then(|data| serde_json::from_str::<ScanControl>(&data).ok())
        .map(|c| c.command)
        .unwrap_or_else(|| "none".to_string())
}

/// Spawns a detached CLI scan process (`ferroshield scan <target> --json [--delete] [--resume]`).
/// The web server reads its JSON progress lines to drive the UI progress bar.
///
/// The scan is launched inside a transient systemd scope (`systemd-run --scope`)
/// so it gets its own cgroup in `/system.slice/` instead of inheriting the
/// daemon's cgroup, which the packaged service limits to `CPUQuota=30%`. Without
/// this, an on-demand UI scan would be throttled to ~1/3 of a core while a plain
/// CLI scan runs at full speed. On non-systemd systems (openrc, etc.) it falls
/// back to spawning the binary directly, exactly as before.
pub fn spawn_scan_process(
    target: &str,
    delete: bool,
    resume: bool,
    quarantine_dir: &Path,
) -> Result<Child, String> {
    let exe =
        std::env::current_exe().map_err(|e| format!("Gagal mendapatkan path binary: {}", e))?;

    let mut args = vec!["scan".to_string(), target.to_string()];
    if delete {
        args.push("--delete".to_string());
    }
    args.push("--json".to_string());
    if resume {
        args.push("--resume".to_string());
    }

    // Stop any stale transient scope from a previous session first, otherwise
    // systemd-run fails because the fixed unit name is still active.
    let _ = Command::new("systemctl")
        .args(["stop", "ferroshield-scan"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();

    let child = match Command::new("systemd-run")
        .args([
            "--scope",
            "--collect",
            "--quiet",
            "--unit=ferroshield-scan",
            "--",
        ])
        .arg(&exe)
        .args(&args)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .stdin(Stdio::null())
        .spawn()
    {
        Ok(c) => c,
        // systemd-run unavailable (non-systemd init): spawn directly.
        Err(_) => {
            let mut cmd = Command::new(&exe);
            cmd.args(&args);
            cmd.stdout(Stdio::piped());
            cmd.stderr(Stdio::inherit());
            cmd.stdin(Stdio::null());
            cmd.spawn()
                .map_err(|e| format!("Gagal memulai proses pemindaian CLI: {}", e))?
        }
    };

    // Clear any leftover stop/pause command from a previous session
    clear_control(&control_path(quarantine_dir));
    let _ = fs::write(scan_pid_path(quarantine_dir), child.id().to_string());
    Ok(child)
}

/// Blocks while the control file says "pause". Returns true to continue, false to abort (stop/reset).
fn wait_through_pause(control: &Path) -> bool {
    loop {
        match read_control(control).as_str() {
            "pause" => thread::sleep(Duration::from_millis(200)),
            "resume" | "none" | "" => return true,
            _ => return false,
        }
    }
}

/// Writes to stdout without panicking if the pipe is closed (e.g. the web daemon
/// that spawned this scan exited). The scan must keep running regardless.
fn emit_stdout(s: &str) {
    let stdout = io::stdout();
    let _ = stdout.lock().write_all(s.as_bytes());
    let _ = stdout.lock().flush();
}

/// Emits a JSON progress line to stdout (used by the web server to follow the scan).
fn print_progress(json: bool, state: &ScanState, scanned: usize, total: usize, current: &str) {
    if !json {
        return;
    }
    let prog = ScanProgress::from_state(state, scanned, total, current);
    if let Ok(line) = serde_json::to_string(&prog) {
        emit_stdout(&format!("{}\n", line));
    }
}

/// Prints the interactive CLI progress line (carriage-return based).
fn print_human_progress(scanned: usize, total: usize, current: &str) {
    let percent = if total > 0 {
        (scanned as f64 / total as f64) * 100.0
    } else {
        0.0
    };
    let char_count = current.chars().count();
    let truncated_path = if char_count > 55 {
        let skipped = char_count - 52;
        let last_chars: String = current.chars().skip(skipped).collect();
        format!("...{}", last_chars)
    } else {
        current.to_string()
    };
    emit_stdout(&format!(
        "\r[*] Memindai [{}/{}] ({:.2}%) | File: {}               ",
        scanned, total, percent, truncated_path
    ));
}

/// Single shared scan engine used by both the CLI and (via spawned process) the web UI.
///
/// * `json`: emit progress/results as JSON lines on stdout (web mode).
/// * `interactive`: prompt the user for an action per detection (terminal mode).
pub fn run_scan(
    scanner: &Scanner,
    quarantine_mgr: &QuarantineManager,
    target: &str,
    delete: bool,
    json: bool,
    resume: bool,
    interactive: bool,
) -> i32 {
    let quarantine_dir = quarantine_mgr.quarantine_dir.clone();
    let sp = state_path(&quarantine_dir);
    let cp = control_path(&quarantine_dir);
    let pp = scan_pid_path(&quarantine_dir);
    let _ = fs::write(&pp, std::process::id().to_string());

    let target_path = Path::new(target);
    if !target_path.exists() {
        let mut state = ScanState::new(target.to_string(), delete);
        state.status = "error".to_string();
        state.error = Some("Path tidak ditemukan".to_string());
        save_scan_state(&sp, &state);
        print_progress(json, &state, 0, 0, "");
        if !json {
            eprintln!("[-] Path tidak valid.");
        }
        let _ = fs::remove_file(&pp);
        return 1;
    }

    let mut state = if resume {
        load_scan_state(&sp).unwrap_or_else(|| ScanState::new(target.to_string(), delete))
    } else {
        ScanState::new(target.to_string(), delete)
    };

    let already_scanned = state.scanned_files.clone();
    let mut scanned_set = state.scanned_files.clone();
    let mut current_results = state.results.clone();
    let mut was_paused = false;

    if !resume {
        state.status = "counting".to_string();
        save_scan_state(&sp, &state);
        print_progress(json, &state, 0, 0, "");
    }

    // ---- Single file scan -------------------------------------------------
    if target_path.is_file() {
        state.total_files = 1;
        state.status = "scanning".to_string();
        save_scan_state(&sp, &state);
        print_progress(json, &state, 0, 1, target);

        if !json {
            println!("[*] Memulai pemindaian pada: {}...", target);
        }

        if let Some(res) = scanner.scan_file(target_path) {
            current_results.push(SimpleScanResult::from_scan_result(&res));
            if delete {
                let _ = fs::remove_file(target_path);
            }
            if !json {
                println!("\n[!] MALWARE DETECTED: {}", res.file_path);
                for rule in &res.triggered_rules {
                    println!(
                        "  - Aturan: {} (ID: {}) [{}]",
                        rule.name, rule.id, rule.severity
                    );
                }
                if delete {
                    println!("[+] File berhasil dihapus secara permanen.");
                } else if interactive {
                    prompt_and_execute_action(&res, quarantine_mgr, scanner);
                }
            }
        } else if !json {
            println!("[+] File aman.");
        }

        scanned_set.insert(target.to_string());
        state.scanned_files = scanned_set;
        state.results = current_results;
        state.threats_found = state.results.len();
        state.status = "completed".to_string();
        save_scan_state(&sp, &state);
        print_progress(json, &state, 1, 1, target);
        clear_control(&cp);
        let _ = fs::remove_file(&pp);
        return 0;
    }

    // ---- Directory scan ----------------------------------------------------
    if !json {
        println!("[*] Memulai pemindaian pada: {}...", target);
        println!("[*] Menghitung total file... Mohon tunggu.");
    }

    // 1. Count files (honours pause/stop control commands)
    let total_files = if resume && state.total_files > 0 {
        state.total_files
    } else {
        let mut count = 0;
        let mut stopped = false;
        for entry in WalkDir::new(target_path).into_iter().filter_map(Result::ok) {
            match read_control(&cp).as_str() {
                "pause" => {
                    if !was_paused {
                        was_paused = true;
                        state.status = "paused".to_string();
                        save_scan_state(&sp, &state);
                    }
                    if !wait_through_pause(&cp) {
                        stopped = true;
                        break;
                    }
                    was_paused = false;
                    state.status = "counting".to_string();
                    save_scan_state(&sp, &state);
                }
                "stop" | "reset" => {
                    state.status = "stopped".to_string();
                    save_scan_state(&sp, &state);
                    stopped = true;
                    break;
                }
                _ => {}
            }

            let p = entry.path();
            let p_str = p.to_string_lossy();
            if p.is_file() && !should_skip(&p_str) {
                count += 1;
            }
        }
        if stopped {
            state.status = "stopped".to_string();
            save_scan_state(&sp, &state);
            print_progress(
                json,
                &state,
                state.scanned_files.len(),
                state.total_files,
                "",
            );
            clear_control(&cp);
            let _ = fs::remove_file(&pp);
            return 1;
        }
        count
    };

    state.total_files = total_files;
    state.status = "scanning".to_string();
    save_scan_state(&sp, &state);
    print_progress(json, &state, 0, total_files, "");

    let mut last_emit = Instant::now();
    let mut last_save = Instant::now();

    let raw_results = scanner.scan_directory(
        target_path,
        &already_scanned,
        Some(total_files),
        |scanned, total, current, threat| {
            // Persist the current progress before aborting on stop/reset so a later
            // resume continues from the right place.
            let save_on_stop = |state: &mut ScanState| {
                state.scanned_files = scanned_set.clone();
                state.results = current_results.clone();
                state.threats_found = current_results.len();
                state.status = "stopped".to_string();
                save_scan_state(&sp, state);
            };

            match read_control(&cp).as_str() {
                "pause" => {
                    if !was_paused {
                        was_paused = true;
                        state.status = "paused".to_string();
                        save_scan_state(&sp, &state);
                    }
                    if !wait_through_pause(&cp) {
                        save_on_stop(&mut state);
                        return false;
                    }
                    was_paused = false;
                    state.status = "scanning".to_string();
                    save_scan_state(&sp, &state);
                }
                "stop" | "reset" => {
                    save_on_stop(&mut state);
                    return false;
                }
                _ => {}
            }

            scanned_set.insert(current.to_string());

            if let Some(t) = threat {
                current_results.push(SimpleScanResult::from_scan_result(t));
                if delete {
                    let _ = fs::remove_file(&t.file_path);
                }
                if !json && delete {
                    println!("    [+] File berhasil dihapus secara permanen.");
                }
            }

            let now = Instant::now();
            let should_emit =
                scanned == total || now.duration_since(last_emit) >= Duration::from_millis(150);
            let should_save =
                scanned == total || now.duration_since(last_save) >= Duration::from_secs(5);

            if should_emit {
                if json {
                    print_progress(true, &state, scanned, total, current);
                } else {
                    print_human_progress(scanned, total, current);
                }
                last_emit = now;
            }
            if should_save {
                state.scanned_files = scanned_set.clone();
                state.results = current_results.clone();
                state.threats_found = current_results.len();
                save_scan_state(&sp, &state);
                last_save = now;
            }
            true
        },
    );

    // 3. Finalize
    let stop_cmd = read_control(&cp);
    let stopped = stop_cmd == "stop" || stop_cmd == "reset";

    state.scanned_files = scanned_set;
    state.results = current_results;
    state.threats_found = state.results.len();
    state.status = if stopped { "stopped" } else { "completed" }.to_string();
    save_scan_state(&sp, &state);

    if json {
        print_progress(true, &state, state.scanned_files.len(), total_files, "");
    } else {
        println!();
        if stopped {
            println!("[*] Pemindaian dihentikan.");
        } else {
            println!("[*] Pemindaian direktori selesai.");
            if raw_results.is_empty() {
                println!("[+] Seluruh file dalam direktori aman.");
            } else {
                println!(
                    "[!] Pemindaian selesai. Ditemukan {} file mencurigakan:",
                    raw_results.len()
                );
                crate::utils::log_detection(&format!(
                    "[!] PEMINDAIAN SELESAI: Ditemukan {} file mencurigakan!",
                    raw_results.len()
                ));
                for res in &raw_results {
                    println!("\n[!] File: {}", res.file_path);
                    for rule in &res.triggered_rules {
                        println!("    -> Aturan: {} [{}]", rule.name, rule.id);
                    }
                }
                if interactive && !delete {
                    for res in &raw_results {
                        prompt_and_execute_action(res, quarantine_mgr, scanner);
                    }
                }
            }
        }
    }

    clear_control(&cp);
    let _ = fs::remove_file(&pp);
    if stopped { 1 } else { 0 }
}

fn prompt_and_execute_action(
    res: &ScanResult,
    quarantine_mgr: &QuarantineManager,
    scanner: &Scanner,
) {
    loop {
        print!(
            "[?] Tindakan untuk {}?\n    [k] Karantina, [h] Hapus, [w] Whitelist, [a] Abaikan/Lewati: ",
            res.file_path
        );
        let _ = io::stdout().flush();
        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            println!("\n[*] Melewati berkas karena error membaca input.");
            break;
        }
        let choice = input.trim().to_lowercase();
        match choice.as_str() {
            "k" | "karantina" => {
                let path = Path::new(&res.file_path);
                if let Ok((sha256, _)) = scanner.calculate_hashes(path) {
                    let rule_id = res
                        .triggered_rules
                        .first()
                        .map(|r| r.id.as_str())
                        .unwrap_or("HEURISTIC-ENTROPY");
                    match quarantine_mgr.quarantine_file(path, &sha256, rule_id) {
                        Ok(q_id) => {
                            println!("[+] File berhasil dikarantina. (ID Karantina: {})", q_id)
                        }
                        Err(e) => eprintln!("[-] Gagal mengkarantina file: {}", e),
                    }
                } else {
                    eprintln!("[-] Gagal menghitung hash file untuk karantina.");
                }
                break;
            }
            "h" | "hapus" => {
                let path = Path::new(&res.file_path);
                match std::fs::remove_file(path) {
                    Ok(_) => println!("[+] File berhasil dihapus secara permanen."),
                    Err(e) => eprintln!("[-] Gagal menghapus file: {}", e),
                }
                break;
            }
            "w" | "whitelist" => {
                match crate::utils::add_to_whitelist(&res.file_path) {
                    Ok(_) => println!("[+] File berhasil dimasukkan ke whitelist."),
                    Err(e) => eprintln!("[-] Gagal memasukkan file ke whitelist: {}", e),
                }
                break;
            }
            "a" | "abaikan" | "" => {
                println!("[*] File diabaikan.");
                break;
            }
            _ => {
                println!("[-] Pilihan tidak valid. Silakan pilih k, h, w, atau a.");
            }
        }
    }
}
