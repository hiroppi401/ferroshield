mod browser;
mod config;
mod contain;
mod feed;
mod network;
mod quarantine;
mod scanjob;
mod scanner;
mod utils;
mod web;

use config::load_rules;
use quarantine::QuarantineManager;
use scanner::Scanner;
use utils::{log_detection, log_message};

use std::collections::HashSet;
use std::env;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

fn print_usage() {
    println!("FerroShield - Pemindai Malware, Karantina, Jaringan & UI Dashboard (Linux Only)");
    println!("Penggunaan:");
    println!(
        "  ferroshield scan <path> [--delete]    Memindai file atau direktori (tambahkan --delete untuk langsung menghapus, --json untuk output progress JSON)"
    );
    println!(
        "  ferroshield monitor                   Menjalankan monitor real-time & UI Dashboard (port 8686)"
    );
    println!("  ferroshield web [--port <port>]       Menjalankan UI Dashboard Konsol Web saja");
    println!("  ferroshield quarantine list           Melihat daftar file yang sedang dikarantina");
    println!(
        "  ferroshield quarantine restore <id>   Memulihkan file dari karantina ke posisi semula"
    );
    println!("  ferroshield quarantine delete <id>    Menghapus file karantina secara permanen");
    println!(
        "  ferroshield block-hosts               Menambahkan blacklist domain ke /etc/hosts (butuh root)"
    );
    println!(
        "  ferroshield clean-hosts               Membersihkan blacklist domain dari /etc/hosts (butuh root)"
    );
    println!(
        "  ferroshield gen-keys [dir]            Membuat keypair Ed25519 baru (rules.key + rules.pub)"
    );
    println!(
        "  ferroshield sign-rules                Menandatangani rules.json memakai rules.key (mekanisme resmi)"
    );
    println!(
        "  ferroshield update-feed               Memperbarui threat feed (IP & Domain blacklist) secara manual"
    );
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        print_usage();
        return;
    }

    let command = args[1].as_str();

    // Set quarantine path (local .quarantine folder if non-root, or /var/lib/ferroshield/quarantine if root)
    let quarantine_path = if sudo::check() == sudo::RunningAs::Root {
        PathBuf::from("/var/lib/ferroshield/quarantine")
    } else {
        env::current_dir().unwrap().join(".quarantine")
    };

    // 1. Handle subcommands that do not require loading verified rules.json
    match command {
        "gen-keys" => {
            let dir = args.get(2).map(String::as_str).unwrap_or(".");
            println!("[*] Membuat keypair Ed25519 baru di direktori: {}...", dir);
            match config::gen_rules_keypair(dir) {
                Ok((key_path, pub_path)) => {
                    println!("[+] Keypair berhasil dibuat!");
                    println!("[+] Kunci privat : {}", key_path.display());
                    println!("[+] Kunci publik : {}", pub_path.display());
                    println!(
                        "[*] Gunakan: ferroshield sign-rules untuk menandatangani rules.json."
                    );
                }
                Err(e) => eprintln!("[-] Gagal membuat keypair: {}", e),
            }
            return;
        }
        "sign-rules" => {
            sign_rules_with_ebpf_hash();
            return;
        }
        "update-feed" => {
            println!("[*] Memulai pembaruan threat feed secara manual...");
            match feed::update_threat_feed() {
                Ok(_) => println!("[+] Pembaruan threat feed selesai dengan sukses!"),
                Err(e) => eprintln!("[-] Gagal memperbarui threat feed: {}", e),
            }
            return;
        }
        "clean-hosts" => {
            if let Err(e) = browser::clean_hosts_file() {
                eprintln!("[-] Gagal membersihkan /etc/hosts: {}", e);
                eprintln!("[-] Anda perlu menjalankan perintah ini sebagai root/sudo.");
            } else {
                println!("[+] Semua entry blocklist FerroShield berhasil dibersihkan.");
            }
            return;
        }
        "quarantine" => {
            if args.len() < 3 {
                println!("[-] Gunakan: ferroshield quarantine [list|restore|delete]");
                return;
            }
            let quarantine_mgr = match QuarantineManager::new(&quarantine_path) {
                Ok(mgr) => mgr,
                Err(e) => {
                    eprintln!("[-] Gagal inisialisasi folder karantina: {}", e);
                    return;
                }
            };
            let sub = args[2].as_str();
            match sub {
                "list" => match quarantine_mgr.list_quarantined() {
                    Ok(list) => {
                        if list.is_empty() {
                            println!("[+] Tidak ada file dalam karantina.");
                        } else {
                            println!("[*] Daftar File Terkarantina:");
                            for item in list {
                                println!(
                                    "ID: {}\n  Asal: {}\n  SHA-256: {}\n  Aturan: {}\n",
                                    item.id,
                                    item.original_path,
                                    item.hash_sha256,
                                    item.triggered_rule_id
                                );
                            }
                        }
                    }
                    Err(e) => eprintln!("[-] Gagal membaca daftar karantina: {}", e),
                },
                "restore" => {
                    if args.len() < 4 {
                        println!("[-] Gunakan: ferroshield quarantine restore <id>");
                        return;
                    }
                    let id = &args[3];
                    match quarantine_mgr.restore_file(id) {
                        Ok(_) => println!("[+] Berhasil memulihkan file dengan ID: {}", id),
                        Err(e) => eprintln!("[-] Gagal memulihkan file: {}", e),
                    }
                }
                "delete" => {
                    if args.len() < 4 {
                        println!("[-] Gunakan: ferroshield quarantine delete <id>");
                        return;
                    }
                    let id = &args[3];
                    let q_file = quarantine_mgr
                        .quarantine_dir
                        .join(format!("{}.quarantined", id));
                    let m_file = quarantine_mgr
                        .quarantine_dir
                        .join(format!("{}.metadata", id));

                    if q_file.exists() && m_file.exists() {
                        let _ = std::fs::remove_file(q_file);
                        let _ = std::fs::remove_file(m_file);
                        println!(
                            "[+] File karantina ID {} telah dihapus secara permanen.",
                            id
                        );
                    } else {
                        println!("[-] File karantina dengan ID tersebut tidak ditemukan.");
                    }
                }
                _ => println!("[-] Subcommand karantina tidak valid."),
            }
            return;
        }
        _ => {}
    }

    // 2. Handle subcommands that require loading verified rules.json
    let quarantine_mgr = match QuarantineManager::new(&quarantine_path) {
        Ok(mgr) => mgr,
        Err(e) => {
            eprintln!("[-] Gagal inisialisasi folder karantina: {}", e);
            return;
        }
    };

    let config_path = "rules.json";
    let rules_config = match load_rules(config_path) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("[-] Gagal memuat rules.json: {}", e);
            eprintln!("[-] Pastikan file rules.json berada di direktori yang sama.");
            return;
        }
    };

    let runtime_config = config::load_runtime_config();
    let default_action = config::effective_default_action(&runtime_config, &rules_config);
    let downloads_dir = config::effective_downloads_dir(&runtime_config, &rules_config);
    let contain_strategy = config::effective_contain_strategy(&runtime_config);

    let scanner = Scanner::new(
        rules_config.rules.clone(),
        10,
        rules_config.rules_yar_sha256.as_deref(),
    );

    match command {
        "scan" => {
            if args.len() < 3 {
                println!("[-] Gunakan: ferroshield scan <path> [--delete]");
                return;
            }
            let target = args[2].clone();
            let delete_flag = args.iter().any(|a| a == "--delete");
            let json_flag = args.iter().any(|a| a == "--json");
            let resume_flag = args.iter().any(|a| a == "--resume");
            let interactive = !json_flag && std::io::stdin().is_terminal();
            let code = scanjob::run_scan(
                &scanner,
                &quarantine_mgr,
                &target,
                delete_flag,
                json_flag,
                resume_flag,
                interactive,
            );
            std::process::exit(code);
        }
        "monitor" => {
            log_message("[*] Memulai FerroShield Background Guard Daemon...");

            if let Err(e) = utils::drop_capabilities() {
                log_message(&format!(
                    "[-] Gagal menurunkan capability: {}. Melanjutkan dengan privilege penuh.",
                    e
                ));
            }

            // Shared components for threads
            let scanner_arc = Arc::new(scanner);
            let quarantine_arc = Arc::new(quarantine_mgr.clone());
            let rules_config_arc = Arc::new(rules_config.clone());

            // 0. Start Web UI Dashboard server automatically in background (on port 8686)
            web::start_web_server(
                "127.0.0.1",
                8686,
                (*scanner_arc).clone(),
                quarantine_mgr.clone(),
                rules_config.clone(),
                default_action.clone(),
            );

            // 1. Thread Jaringan (Network connection monitor)
            let net_scanner = scanner_arc.clone();
            let net_quarantine = quarantine_arc.clone();
            let net_config = rules_config_arc.clone();
            let net_action = default_action.clone();
            let net_handle = thread::spawn(move || {
                log_message("[*] Monitor Jaringan: Menginisialisasi eBPF...");
                let run_fallback = || {
                    log_message(
                        "[*] Monitor Jaringan: Memulai pemantauan koneksi keluar (procfs polling fallback)...",
                    );
                    loop {
                        if let Ok(conns) = network::get_active_connections() {
                            for conn in conns {
                                // Check if remote IP is in blacklist
                                if net_config.network_blacklist.ips.contains(&conn.remote_ip) {
                                    log_detection(&format!(
                                        "[!] DETEKSI JARINGAN: Koneksi keluar ke IP terlarang {} dideteksi!",
                                        conn.remote_ip
                                    ));

                                    // 1. Freeze the whole process tree FIRST so the running
                                    //    malware cannot mutate, spawn children, or react to
                                    //    the on-disk cleanup (anti-mutation / anti-respawn).
                                    let containment = conn.pid.and_then(|pid| {
                                        log_detection(&format!(
                                            "[!] Proses berbahaya terdeteksi: PID {} ({:?})",
                                            pid, conn.process_name
                                        ));
                                        contain::contain_process(pid, contain_strategy)
                                    });

                                    // 2. Quarantine/delete the binary (safe now: process is frozen)
                                    if conn.pid.is_some()
                                        && let Some(ref proc_name) = conn.process_name
                                    {
                                        let proc_path = Path::new(proc_name);
                                        if proc_path.exists() && proc_path.is_file() {
                                            if net_action == "delete" {
                                                if let Err(e) = std::fs::remove_file(proc_path) {
                                                    log_message(&format!(
                                                        "[-] Gagal menghapus file proses berbahaya: {}",
                                                        e
                                                    ));
                                                } else {
                                                    log_message(
                                                        "[+] File eksekusi proses berbahaya berhasil dihapus permanen.",
                                                    );
                                                }
                                            } else {
                                                if let Ok((sha, _)) =
                                                    net_scanner.calculate_hashes(proc_path)
                                                {
                                                    let _ = net_quarantine.quarantine_file(
                                                        proc_path,
                                                        &sha,
                                                        "NETWORK-BREACH-PID",
                                                    );
                                                }
                                            }
                                        }
                                    }

                                    // 3. Block the remote IP via firewall
                                    if let Err(e) = network::block_ip(&conn.remote_ip) {
                                        log_message(&format!(
                                            "[-] Gagal memblokir IP {} di firewall: {}",
                                            conn.remote_ip, e
                                        ));
                                    } else {
                                        log_message(&format!(
                                            "[+] IP {} berhasil diblokir di iptables.",
                                            conn.remote_ip
                                        ));
                                    }

                                    // 4. Kill the (frozen) process tree LAST
                                    if let Some(pid) = conn.pid {
                                        match &containment {
                                            Some(c) => {
                                                if let Err(e) = contain::kill_contained(c) {
                                                    log_message(&format!(
                                                        "[-] Gagal menghentikan PID {}: {}",
                                                        pid, e
                                                    ));
                                                } else {
                                                    log_message(&format!(
                                                        "[+] Berhasil menghentikan PID {}",
                                                        pid
                                                    ));
                                                }
                                            }
                                            None => {
                                                if let Err(e) = network::kill_process(pid) {
                                                    log_message(&format!(
                                                        "[-] Gagal menghentikan PID {}: {}",
                                                        pid, e
                                                    ));
                                                } else {
                                                    log_message(&format!(
                                                        "[+] Berhasil menghentikan PID {}",
                                                        pid
                                                    ));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        thread::sleep(Duration::from_secs(2));
                    }
                };

                match network::init_ebpf_monitor(
                    &net_config.network_blacklist.ips,
                    &net_config.network_blacklist.domains,
                    (*net_scanner).clone(),
                    (*net_quarantine).clone(),
                    &net_action,
                    net_config.ebpf_sha256.as_deref(),
                    contain_strategy,
                ) {
                    Ok(mut ebpf_monitor) => {
                        log_message("[+] Monitor Jaringan: eBPF aktif secara real-time!");
                        if let Err(e) = ebpf_monitor.run() {
                            log_message(&format!(
                                "[-] Gagal menjalankan eBPF: {}. Menggunakan fallback polling procfs.",
                                e
                            ));
                            run_fallback();
                        } else {
                            // Keep the thread alive while eBPF runs in spawned threads
                            loop {
                                thread::sleep(Duration::from_secs(3600));
                            }
                        }
                    }
                    Err(e) => {
                        log_message(&format!(
                            "[-] Gagal memuat eBPF: {}. Menggunakan fallback polling procfs.",
                            e
                        ));
                        run_fallback();
                    }
                }
            });

            // 2. Thread Browser Guard - Downloads Watcher
            let watch_scanner = (*scanner_arc).clone();
            let watch_quarantine = (*quarantine_arc).clone();
            let watch_action = default_action.clone();
            let watch_custom_path = downloads_dir.clone();
            let watch_handle = thread::spawn(move || {
                let mut logged_not_found = false;
                loop {
                    let custom_path = watch_custom_path.as_deref();
                    let downloads_dirs = browser::get_downloads_dirs(custom_path);

                    if !downloads_dirs.is_empty() {
                        logged_not_found = false;
                        if let Err(e) = browser::watch_downloads_directories(
                            &downloads_dirs,
                            custom_path,
                            watch_scanner.clone(),
                            watch_quarantine.clone(),
                            &watch_action,
                        ) {
                            log_message(&format!(
                                "[-] Error pada real-time downloads watcher: {}. Mencoba kembali dalam 15 detik...",
                                e
                            ));
                        }
                    } else {
                        if !logged_not_found {
                            log_message(
                                "[-] Folder unduhan (Downloads/Unduhan) tidak ditemukan. Mencoba mencari secara berkala...",
                            );
                            logged_not_found = true;
                        }
                    }
                    thread::sleep(Duration::from_secs(15));
                }
            });

            // 3. Thread Browser Guard - Extension Scanner (Periodic check)
            let ext_config = rules_config_arc.clone();
            let ext_handle = thread::spawn(move || {
                log_message("[*] Monitor Browser: Memulai pengecekan ekstensi berkala...");
                loop {
                    let blacklist_ids = &ext_config
                        .rules
                        .iter()
                        .filter_map(|r| r.signatures.extension_ids.clone())
                        .flatten()
                        .collect::<Vec<String>>();

                    if !blacklist_ids.is_empty() {
                        let detected = browser::scan_browser_extensions(blacklist_ids);
                        for item in detected {
                            log_detection(&format!(
                                "[!] PERINGATAN BROWSER GUARD: Ekstensi berbahaya terdeteksi: {}",
                                item
                            ));
                        }
                    }
                    // Scan extensions every 60 seconds
                    thread::sleep(Duration::from_secs(60));
                }
            });

            // 4. Thread Cryptominer & Suspicious Process Guard
            let miner_scanner = scanner_arc.clone();
            let miner_quarantine = quarantine_arc.clone();
            let miner_action = default_action.clone();
            let miner_blacklist = rules_config.network_blacklist.ips.clone();
            let miner_require_secondary = runtime_config
                .miner_detection_require_secondary_signal
                .unwrap_or(true);
            let miner_handle = thread::spawn(move || {
                log_message(
                    "[*] Monitor Miner: Memulai perlindungan terhadap malware crypto miner...",
                );

                use std::collections::HashMap;
                use std::time::Instant;

                struct ProcessCpuState {
                    utime: u64,
                    stime: u64,
                    timestamp: Instant,
                    consecutive_high_ticks: u32,
                }

                let mut cpu_history: HashMap<u32, ProcessCpuState> = HashMap::new();
                let num_cores = get_cpu_cores();

                loop {
                    // Check 1: Processes executing from suspicious directories (/tmp, /dev/shm, etc.)
                    let susp_procs = network::find_suspicious_processes();
                    for (pid, path_str) in susp_procs {
                        log_detection(&format!(
                            "[!] MONITOR MINER: Mendeteksi proses mencurigakan berjalan dari folder temp: PID {} -> Path: {}",
                            pid, path_str
                        ));

                        // 0. Freeze the process tree first (anti-mutation): a frozen
                        //    process cannot write new files or fork while we neutralize it.
                        let containment = contain::contain_process(pid, contain_strategy);

                        // 1. Remove or quarantine the malicious executable (safe while frozen)
                        let proc_path = Path::new(&path_str);
                        if proc_path.exists() && proc_path.is_file() {
                            if miner_action == "delete" {
                                if let Err(e) = std::fs::remove_file(proc_path) {
                                    log_message(&format!(
                                        "[-] Gagal menghapus file malware: {}",
                                        e
                                    ));
                                } else {
                                    log_message(&format!(
                                        "[+] File malware {} berhasil dihapus permanen.",
                                        path_str
                                    ));
                                }
                            } else {
                                if let Ok((sha, _)) = miner_scanner.calculate_hashes(proc_path) {
                                    let _ = miner_quarantine.quarantine_file(
                                        proc_path,
                                        &sha,
                                        "SUSPICIOUS-TEMP-PATH",
                                    );
                                    log_message(&format!(
                                        "[+] File malware {} dipindahkan ke folder karantina.",
                                        path_str
                                    ));
                                }
                            }
                        }

                        // 2. Kill the frozen process tree SECOND
                        match &containment {
                            Some(c) => {
                                if let Err(e) = contain::kill_contained(c) {
                                    log_message(&format!(
                                        "[-] Gagal menghentikan PID {}: {}",
                                        pid, e
                                    ));
                                } else {
                                    log_message(&format!(
                                        "[+] Berhasil menghentikan PID {} untuk mencegah eksploitasi.",
                                        pid
                                    ));
                                }
                            }
                            None => {
                                if let Err(e) = network::kill_process(pid) {
                                    log_message(&format!(
                                        "[-] Gagal menghentikan PID {}: {}",
                                        pid, e
                                    ));
                                } else {
                                    log_message(&format!(
                                        "[+] Berhasil menghentikan PID {} untuk mencegah eksploitasi.",
                                        pid
                                    ));
                                }
                            }
                        }
                    }

                    // Check 2: Active connections to mining ports
                    if let Ok(conns) = network::get_active_connections() {
                        let whitelist: HashSet<String> =
                            crate::utils::load_whitelist().into_iter().collect();
                        for conn in conns {
                            if network::is_mining_port(conn.remote_port) {
                                log_detection(&format!(
                                    "[!] DETEKSI MINING POOL: Koneksi aktif ke port Stratum Mining {} dideteksi!",
                                    conn.remote_port
                                ));

                                // A port match alone only alerts. Destructive
                                // actions require a second signal (blacklisted IP
                                // or a binary running from a suspicious temp dir)
                                // unless explicitly disabled in config.json.
                                let exe_path =
                                    conn.pid.and_then(network::get_process_executable_path);
                                let should_act = miner_connection_warrants_action(
                                    &conn.remote_ip,
                                    exe_path.as_deref(),
                                    &miner_blacklist,
                                    &whitelist,
                                    miner_require_secondary,
                                );
                                if !should_act {
                                    log_message(&format!(
                                        "[*] Koneksi port mining {} hanya diberi alert (tanpa sinyal kedua), PID {:?} ({:?}).",
                                        conn.remote_port, conn.pid, conn.process_name
                                    ));
                                    continue;
                                }

                                // 0. Freeze the process tree first (anti-mutation)
                                let containment = conn.pid.and_then(|pid| {
                                    contain::contain_process(pid, contain_strategy)
                                });

                                // 1. Quarantine or delete binary (safe while frozen)
                                if let Some(ref proc_name) = conn.process_name {
                                    let proc_path = Path::new(proc_name);
                                    if proc_path.exists() && proc_path.is_file() {
                                        if miner_action == "delete" {
                                            let _ = std::fs::remove_file(proc_path);
                                        } else {
                                            if let Ok((sha, _)) =
                                                miner_scanner.calculate_hashes(proc_path)
                                            {
                                                let _ = miner_quarantine.quarantine_file(
                                                    proc_path,
                                                    &sha,
                                                    "CRYPTO-MINER-PORT",
                                                );
                                            }
                                        }
                                    }
                                }

                                // 2. Block the mining pool IP address
                                let _ = network::block_ip(&conn.remote_ip);

                                // 3. Kill the frozen process tree (after binary isolation & IP block)
                                if let Some(pid) = conn.pid {
                                    match &containment {
                                        Some(c) => {
                                            if let Err(e) = contain::kill_contained(c) {
                                                log_message(&format!(
                                                    "[-] Gagal menghentikan proses miner PID {}: {}",
                                                    pid, e
                                                ));
                                            } else {
                                                log_message(&format!(
                                                    "[+] Berhasil menghentikan proses miner PID {}",
                                                    pid
                                                ));
                                            }
                                        }
                                        None => {
                                            if let Err(e) = network::kill_process(pid) {
                                                log_message(&format!(
                                                    "[-] Gagal menghentikan proses miner PID {}: {}",
                                                    pid, e
                                                ));
                                            } else {
                                                log_message(&format!(
                                                    "[+] Berhasil menghentikan proses miner PID {}",
                                                    pid
                                                ));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // Check 3: Behavioral CPU Mining Detection
                    let proc_dir = Path::new("/proc");
                    let mut current_pids = Vec::new();
                    if let Ok(entries) = std::fs::read_dir(proc_dir) {
                        for entry in entries.filter_map(Result::ok) {
                            if entry.path().is_dir()
                                && let Some(pid_str) = entry.file_name().to_str()
                                && let Ok(pid) = pid_str.parse::<u32>()
                            {
                                current_pids.push(pid);
                            }
                        }
                    }

                    let now = Instant::now();
                    for &pid in &current_pids {
                        if let Some((utime, stime)) = get_process_cpu_time(pid) {
                            if let Some(state) = cpu_history.get_mut(&pid) {
                                let elapsed = now.duration_since(state.timestamp).as_secs_f64();
                                if elapsed > 0.1 {
                                    let delta_proc =
                                        (utime + stime).saturating_sub(state.utime + state.stime);
                                    // Total CPU usage percentage normalized by cores count
                                    let usage = (delta_proc as f64 / 100.0)
                                        / (elapsed * num_cores as f64)
                                        * 100.0;

                                    state.utime = utime;
                                    state.stime = stime;
                                    state.timestamp = now;

                                    if usage > 80.0 {
                                        state.consecutive_high_ticks += 1;
                                        if state.consecutive_high_ticks >= 3
                                            && let Some(exe_path) =
                                                network::get_process_executable_path(pid)
                                        {
                                            let is_whitelisted = exe_path.starts_with("/usr/bin/")
                                                || exe_path.starts_with("/bin/")
                                                || exe_path.starts_with("/usr/sbin/")
                                                || exe_path.starts_with("/sbin/")
                                                || exe_path.starts_with("/usr/lib/")
                                                || exe_path.starts_with("/lib/")
                                                || exe_path.contains("ferroshield");

                                            if !is_whitelisted {
                                                log_detection(&format!(
                                                    "[!] HEURISTIC-MINER: Perilaku cryptomining terdeteksi! PID {} ({}) menggunakan CPU sangat tinggi ({:.2}%) secara konsisten.",
                                                    pid, exe_path, usage
                                                ));

                                                // 0. Freeze the process tree first (anti-mutation)
                                                let containment =
                                                    contain::contain_process(pid, contain_strategy);

                                                // 1. Quarantine/Delete process binary (safe while frozen)
                                                let proc_path = Path::new(&exe_path);
                                                if proc_path.exists() && proc_path.is_file() {
                                                    if miner_action == "delete" {
                                                        let _ = std::fs::remove_file(proc_path);
                                                    } else if let Ok((sha, _)) =
                                                        miner_scanner.calculate_hashes(proc_path)
                                                    {
                                                        let _ = miner_quarantine.quarantine_file(
                                                            proc_path,
                                                            &sha,
                                                            "BEHAVIORAL-MINER-CPU",
                                                        );
                                                    }
                                                }

                                                // 2. Terminate the frozen process tree SECOND
                                                match &containment {
                                                    Some(c) => {
                                                        let _ = contain::kill_contained(c);
                                                    }
                                                    None => {
                                                        let _ = network::kill_process(pid);
                                                    }
                                                }
                                            }
                                        }
                                    } else {
                                        state.consecutive_high_ticks = 0;
                                    }
                                }
                            } else {
                                cpu_history.insert(
                                    pid,
                                    ProcessCpuState {
                                        utime,
                                        stime,
                                        timestamp: now,
                                        consecutive_high_ticks: 0,
                                    },
                                );
                            }
                        }
                    }

                    // Clean up dead processes from history
                    cpu_history.retain(|pid, _| current_pids.contains(pid));

                    thread::sleep(Duration::from_secs(5));
                }
            });

            // 5. Thread Rules Integrity Guard
            let rules_file_path = config_path.to_string();
            let mut last_modified = std::fs::metadata(&rules_file_path)
                .and_then(|m| m.modified())
                .unwrap_or_else(|_| std::time::SystemTime::now());

            let integrity_handle = thread::spawn(move || {
                log_message("[*] Monitor Integritas: Memulai pemantauan rules.json...");
                loop {
                    thread::sleep(Duration::from_secs(5));
                    if let Ok(meta) = std::fs::metadata(&rules_file_path)
                        && let Ok(modified) = meta.modified()
                        && modified != last_modified
                    {
                        log_message(
                            "[*] Terdeteksi perubahan pada rules.json. Memverifikasi tanda tangan...",
                        );
                        match config::verify_rules_signature(&rules_file_path) {
                            Ok(_) => {
                                log_message(
                                    "[+] Tanda tangan rules.json valid. Memuat ulang rules...",
                                );
                                last_modified = modified;
                            }
                            Err(e) => {
                                log_detection(&format!(
                                    "[!] PERINGATAN KEBOCORAN/INTEGRITAS: rules.json diubah secara tidak sah! Kesalahan: {}. Perubahan ditolak.",
                                    e
                                ));
                                last_modified = modified;
                            }
                        }
                    }
                }
            });

            // 6. Thread Auto Update Threat Feed
            let feed_handle = thread::spawn(move || {
                log_message(
                    "[*] Auto Update Threat Feed: Memulai pembaharuan otomatis berkala (setiap 24 jam)...",
                );
                loop {
                    // Sleep 30s before first run to let main daemon launch completely
                    thread::sleep(Duration::from_secs(30));
                    if let Err(e) = feed::update_threat_feed() {
                        log_message(&format!("[-] Gagal memperbarui threat feed: {}", e));
                    }
                    // Wait 24 hours
                    thread::sleep(Duration::from_secs(24 * 3600));
                }
            });

            // 7. Graceful shutdown listener (SIGTERM/SIGINT)
            thread::spawn(utils::wait_for_shutdown_signal);

            // Let daemon run indefinitely
            let _ = net_handle.join();
            let _ = watch_handle.join();
            let _ = ext_handle.join();
            let _ = miner_handle.join();
            let _ = integrity_handle.join();
            let _ = feed_handle.join();
        }
        "web" => {
            let mut port = 8686;
            if args.len() >= 4
                && args[2] == "--port"
                && let Ok(p) = args[3].parse::<u16>()
            {
                port = p;
            }

            println!("[*] Memulai FerroShield Web Dashboard Mandiri...");
            web::start_web_server(
                "127.0.0.1",
                port,
                scanner,
                quarantine_mgr,
                rules_config,
                default_action,
            );

            // Graceful shutdown listener (SIGTERM/SIGINT)
            thread::spawn(utils::wait_for_shutdown_signal);

            // Keep the main thread alive for the web server thread
            loop {
                thread::sleep(Duration::from_secs(3600));
            }
        }
        "block-hosts" => {
            println!("[*] Memproses blacklist domain ke /etc/hosts...");
            let domains = &rules_config.network_blacklist.domains;
            if let Err(e) = browser::block_domains_in_hosts(domains) {
                eprintln!("[-] Gagal menulis ke /etc/hosts: {}", e);
                eprintln!("[-] Anda perlu menjalankan perintah ini sebagai root/sudo.");
            } else {
                println!("[+] Semua domain berbahaya berhasil dialihkan ke 127.0.0.1.");
            }
        }
        "clean-hosts" => {
            if let Err(e) = browser::clean_hosts_file() {
                eprintln!("[-] Gagal membersihkan /etc/hosts: {}", e);
                eprintln!("[-] Anda perlu menjalankan perintah ini sebagai root/sudo.");
            } else {
                println!("[+] Semua entry blocklist FerroShield berhasil dibersihkan.");
            }
        }
        "sign-rules" => {
            sign_rules_with_ebpf_hash();
        }
        "update-feed" => {
            println!("[*] Memulai pembaruan threat feed secara manual...");
            match feed::update_threat_feed() {
                Ok(_) => println!("[+] Pembaruan threat feed selesai dengan sukses!"),
                Err(e) => eprintln!("[-] Gagal memperbarui threat feed: {}", e),
            }
        }
        _ => {
            print_usage();
        }
    }
}

// Simple module to check if running as root
mod sudo {
    #[derive(Debug, PartialEq, Eq)]
    pub enum RunningAs {
        Root,
        User,
    }

    pub fn check() -> RunningAs {
        if let Ok(uid) = std::env::var("UID")
            && uid == "0"
        {
            return RunningAs::Root;
        }
        // Fallback check using libc or nix if needed, or by executing `id -u`
        if let Ok(output) = std::process::Command::new("id").arg("-u").output() {
            let uid_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if uid_str == "0" {
                return RunningAs::Root;
            }
        }
        RunningAs::User
    }
}

fn sign_rules_with_ebpf_hash() {
    println!("[*] Menandatangani rules.json memakai rules.key...");
    let rules_path = "rules.json";
    let key_path = "rules.key";
    if !Path::new(key_path).exists() {
        eprintln!("[-] Gagal: rules.key tidak ditemukan. Silakan buat keypair terlebih dahulu.");
        return;
    }
    // Record the SHA-256 of the installed eBPF module and of rules.yar in the
    // signed rules.json so both the kernel module and the YARA ruleset cannot be
    // replaced undetected. Candidate paths are tried in order: installed location,
    // then in-tree / packaged object files.
    match config::update_ebpf_sha256_in_rules(
        rules_path,
        &[
            PathBuf::from("/usr/lib/ferroshield/ferroshield_ebpf.o"),
            PathBuf::from("src/ebpf/ferroshield_ebpf.o"),
            PathBuf::from("ferroshield_ebpf.o"),
        ],
    ) {
        Ok(_) => println!("[+] Hash eBPF dicatat di rules.json (ebpf_sha256)."),
        Err(e) => eprintln!("[-] Gagal mencatat hash eBPF: {}", e),
    }
    match config::update_rules_yar_sha256_in_rules(
        rules_path,
        &[
            PathBuf::from("/etc/ferroshield/rules.yar"),
            PathBuf::from("rules.yar"),
        ],
    ) {
        Ok(_) => println!("[+] Hash rules.yar dicatat di rules.json (rules_yar_sha256)."),
        Err(e) => eprintln!("[-] Gagal mencatat hash rules.yar: {}", e),
    }
    match config::sign_rules(rules_path, key_path) {
        Ok(_) => println!(
            "[+] rules.json berhasil ditandatangani! Berkas rules.json.sig telah diperbarui."
        ),
        Err(e) => eprintln!("[-] Gagal menandatangani rules: {}", e),
    }
}

fn get_cpu_cores() -> usize {
    if let Ok(content) = std::fs::read_to_string("/proc/cpuinfo") {
        content
            .lines()
            .filter(|line| line.starts_with("processor"))
            .count()
            .max(1)
    } else {
        1
    }
}

fn get_process_cpu_time(pid: u32) -> Option<(u64, u64)> {
    let stat_path = format!("/proc/{}/stat", pid);
    let content = std::fs::read_to_string(stat_path).ok()?;
    let rparen_idx = content.rfind(')')?;
    let post_paren = &content[rparen_idx + 1..];
    let parts: Vec<&str> = post_paren.split_whitespace().collect();
    if parts.len() < 13 {
        return None;
    }
    let utime = parts[11].parse::<u64>().ok()?;
    let stime = parts[12].parse::<u64>().ok()?;
    Some((utime, stime))
}

/// True when an executable path lives in a suspicious temp/shared-memory dir.
fn is_suspicious_temp_path(path: &str) -> bool {
    let lower = path.to_lowercase();
    lower.starts_with("/tmp/")
        || lower.starts_with("/var/tmp/")
        || lower.starts_with("/dev/shm/")
        || lower.starts_with("/run/user/")
}

/// Decides whether a mining-port connection warrants a destructive response
/// (delete/quarantine binary, block IP, kill process). A port match alone only
/// alerts; a second signal (blacklisted remote IP or binary running from a
/// suspicious temp path) is required before any destructive action, unless
/// `require_secondary_signal` is disabled. Whitelisted executables never trigger.
fn miner_connection_warrants_action(
    remote_ip: &str,
    exe_path: Option<&str>,
    blacklist_ips: &[String],
    whitelist: &HashSet<String>,
    require_secondary_signal: bool,
) -> bool {
    if !require_secondary_signal {
        return true;
    }
    let ip_blacklisted = blacklist_ips.iter().any(|ip| ip == remote_ip);
    let suspicious_path = exe_path.map(is_suspicious_temp_path).unwrap_or(false);
    let whitelisted = exe_path.map(|p| whitelist.contains(p)).unwrap_or(false);
    (ip_blacklisted || suspicious_path) && !whitelisted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn whitelist_of(paths: &[&str]) -> HashSet<String> {
        paths.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn test_miner_port_only_connection_is_alert_only() {
        // A connection to a mining port with no second signal (no blacklisted IP,
        // no suspicious path) must NOT trigger destructive actions by default.
        let whitelist = HashSet::new();
        let blacklist: Vec<String> = vec![];
        assert!(network::is_mining_port(3333));
        assert!(!miner_connection_warrants_action(
            "203.0.113.1",
            None,
            &blacklist,
            &whitelist,
            true
        ));
        assert!(!miner_connection_warrants_action(
            "203.0.113.1",
            Some("/usr/bin/legit-daemon"),
            &blacklist,
            &whitelist,
            true
        ));
    }

    #[test]
    fn test_miner_blacklisted_ip_triggers_action() {
        let blacklist = vec!["185.112.146.12".to_string()];
        assert!(miner_connection_warrants_action(
            "185.112.146.12",
            None,
            &blacklist,
            &HashSet::new(),
            true
        ));
    }

    #[test]
    fn test_miner_suspicious_temp_path_triggers_action() {
        for path in [
            "/tmp/xmrig",
            "/var/tmp/xmrig",
            "/dev/shm/xmrig",
            "/run/user/1000/xmrig",
        ] {
            assert!(
                is_suspicious_temp_path(path),
                "{path} should be a suspicious temp path"
            );
            assert!(miner_connection_warrants_action(
                "203.0.113.1",
                Some(path),
                &[],
                &HashSet::new(),
                true
            ));
        }
    }

    #[test]
    fn test_miner_action_respects_whitelist() {
        // Even with a secondary signal, an explicitly whitelisted executable is spared.
        let whitelist = whitelist_of(&["/tmp/xmrig"]);
        assert!(!miner_connection_warrants_action(
            "203.0.113.1",
            Some("/tmp/xmrig"),
            &[],
            &whitelist,
            true
        ));
    }

    #[test]
    fn test_miner_disabled_secondary_signal_acts_on_port() {
        // Opt-out via config.json restores the legacy port-only behavior.
        assert!(miner_connection_warrants_action(
            "203.0.113.1",
            None,
            &[],
            &HashSet::new(),
            false
        ));
    }
}
