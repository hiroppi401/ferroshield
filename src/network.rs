use serde::Serialize;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader};
use std::path::Path;
use std::process::Command;
use std::sync::OnceLock;

#[derive(Debug, Clone, Serialize)]
pub struct ActiveConnection {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub state: String,
    pub inode: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

/// Helper to parse little-endian hex IP to standard IPv4 string
fn parse_hex_ipv4(hex_str: &str) -> Option<String> {
    if hex_str.len() != 8 {
        return None;
    }
    let b1 = u8::from_str_radix(&hex_str[6..8], 16).ok()?;
    let b2 = u8::from_str_radix(&hex_str[4..6], 16).ok()?;
    let b3 = u8::from_str_radix(&hex_str[2..4], 16).ok()?;
    let b4 = u8::from_str_radix(&hex_str[0..2], 16).ok()?;
    Some(format!("{}.{}.{}.{}", b1, b2, b3, b4))
}

/// Parse hex port string (e.g. "0050" -> 80)
fn parse_hex_port(hex_str: &str) -> Option<u16> {
    u16::from_str_radix(hex_str, 16).ok()
}

/// Scans `/proc` to build a map of Socket Inode -> Process ID (PID)
pub fn get_socket_pid_map() -> HashMap<String, u32> {
    let mut map = HashMap::new();
    let proc_dir = Path::new("/proc");

    if let Ok(entries) = fs::read_dir(proc_dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir() {
                // Check if directory name is a valid PID (number)
                if let Some(pid_str) = path.file_name().and_then(|s| s.to_str())
                    && let Ok(pid) = pid_str.parse::<u32>()
                {
                    let fd_dir = path.join("fd");
                    if let Ok(fd_entries) = fs::read_dir(fd_dir) {
                        for fd_entry in fd_entries.filter_map(Result::ok) {
                            if let Ok(link) = fs::read_link(fd_entry.path()) {
                                let link_str = link.to_string_lossy();
                                if link_str.starts_with("socket:[") && link_str.ends_with(']') {
                                    // Extract inode
                                    let inode = &link_str["socket:[".len()..link_str.len() - 1];
                                    map.insert(inode.to_string(), pid);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

/// Returns process command line or executable name for a given PID
pub fn get_process_name(pid: u32) -> Option<String> {
    let comm_path = format!("/proc/{}/comm", pid);
    if let Ok(name) = fs::read_to_string(comm_path) {
        return Some(name.trim().to_string());
    }
    let cmdline_path = format!("/proc/{}/cmdline", pid);
    if let Ok(cmdline) = fs::read_to_string(cmdline_path) {
        let parts: Vec<&str> = cmdline.split('\0').collect();
        if !parts.is_empty() && !parts[0].is_empty() {
            return Some(parts[0].to_string());
        }
    }
    None
}

/// Reads active TCP connections from `/proc/net/tcp`
pub fn get_active_connections() -> io::Result<Vec<ActiveConnection>> {
    let file = File::open("/proc/net/tcp")?;
    let reader = BufReader::new(file);
    let socket_to_pid = get_socket_pid_map();
    let mut connections = Vec::new();

    // Skip the header line
    for line_res in reader.lines().skip(1) {
        let line = line_res?;
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 10 {
            continue;
        }

        // Parse Local Address (IP:Port)
        let local_addr_parts: Vec<&str> = parts[1].split(':').collect();
        if local_addr_parts.len() != 2 {
            continue;
        }
        let local_ip = match parse_hex_ipv4(local_addr_parts[0]) {
            Some(ip) => ip,
            None => continue,
        };
        let local_port = match parse_hex_port(local_addr_parts[1]) {
            Some(p) => p,
            None => continue,
        };

        // Parse Remote Address (IP:Port)
        let rem_addr_parts: Vec<&str> = parts[2].split(':').collect();
        if rem_addr_parts.len() != 2 {
            continue;
        }
        let remote_ip = match parse_hex_ipv4(rem_addr_parts[0]) {
            Some(ip) => ip,
            None => continue,
        };
        let remote_port = match parse_hex_port(rem_addr_parts[1]) {
            Some(p) => p,
            None => continue,
        };

        let state_hex = parts[3];
        let state = match state_hex {
            "01" => "ESTABLISHED",
            "02" => "SYN_SENT",
            "03" => "SYN_RECV",
            "04" => "FIN_WAIT1",
            "05" => "FIN_WAIT2",
            "06" => "TIME_WAIT",
            "07" => "CLOSE",
            "08" => "CLOSE_WAIT",
            "09" => "LAST_ACK",
            "0A" => "LISTEN",
            "0B" => "CLOSING",
            _ => state_hex,
        }
        .to_string();
        let inode = parts[9].to_string();

        let pid = socket_to_pid.get(&inode).copied();
        let process_name = pid.and_then(get_process_name);

        connections.push(ActiveConnection {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            state,
            inode,
            pid,
            process_name,
        });
    }

    Ok(connections)
}

/// Kills a process by PID
pub fn kill_process(pid: u32) -> io::Result<()> {
    println!("[!] Attempting to terminate malicious process PID: {}", pid);
    let status = Command::new("kill")
        .args(["-9", &pid.to_string()])
        .status()?;

    if status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "Failed to kill process with PID {}",
            pid
        )))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nft,
    Iptables,
}

/// Detects the available firewall backend once: nftables preferred, iptables fallback.
pub fn detect_firewall_backend() -> Option<FirewallBackend> {
    static BACKEND: OnceLock<Option<FirewallBackend>> = OnceLock::new();
    *BACKEND.get_or_init(|| {
        if command_available("nft") {
            Some(FirewallBackend::Nft)
        } else if command_available("iptables") {
            Some(FirewallBackend::Iptables)
        } else {
            None
        }
    })
}

fn command_available(name: &str) -> bool {
    let path = std::env::var("PATH").unwrap_or_default();
    path.split(':')
        .any(|dir| Path::new(dir).join(name).is_file())
}

fn run_cmd(cmd: &str, args: &[&str]) -> io::Result<std::process::Output> {
    Command::new(cmd).args(args).output()
}

/// Ensures the nftables `ip filter` table and `OUTPUT` chain exist.
fn ensure_nft_chain() -> io::Result<()> {
    let check = run_cmd("nft", &["list", "chain", "ip", "filter", "OUTPUT"]);
    if check.map(|o| o.status.success()).unwrap_or(false) {
        return Ok(());
    }
    // Table and/or chain missing; create them, ignoring "already exists" errors.
    let _ = run_cmd("nft", &["add", "table", "ip", "filter"]);
    let _ = run_cmd(
        "nft",
        &[
            "add",
            "chain",
            "ip",
            "filter",
            "OUTPUT",
            "{ type filter hook output priority 0; }",
        ],
    );
    let recheck = run_cmd("nft", &["list", "chain", "ip", "filter", "OUTPUT"]);
    if recheck.map(|o| o.status.success()).unwrap_or(false) {
        Ok(())
    } else {
        Err(io::Error::other(
            "Failed to create nftables OUTPUT chain. Are you running as root/sudo?",
        ))
    }
}

fn block_ip_nft(ip: &str) -> io::Result<()> {
    ensure_nft_chain()?;
    let listed = run_cmd("nft", &["list", "chain", "ip", "filter", "OUTPUT"])?;
    let content = String::from_utf8_lossy(&listed.stdout);
    if content
        .lines()
        .any(|l| l.contains("daddr") && l.contains(ip) && l.contains("drop"))
    {
        println!("[*] IP {} is already blocked in nftables.", ip);
        return Ok(());
    }
    println!("[!] Blocking outgoing traffic to IP: {} using nftables", ip);
    let status = run_cmd(
        "nft",
        &[
            "add", "rule", "ip", "filter", "OUTPUT", "ip", "daddr", ip, "drop",
        ],
    )?;
    if status.status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Failed to run nft. Are you running as root/sudo?",
        ))
    }
}

fn unblock_ip_nft(ip: &str) -> io::Result<()> {
    let listed = run_cmd("nft", &["-a", "list", "chain", "ip", "filter", "OUTPUT"])?;
    let content = String::from_utf8_lossy(&listed.stdout);
    for line in content.lines() {
        if line.contains("daddr")
            && line.contains(ip)
            && line.contains("drop")
            && let Some(handle) = parse_nft_handle(line)
        {
            println!("[*] Unblocking IP: {} using nftables", ip);
            let status = run_cmd(
                "nft",
                &[
                    "delete", "rule", "ip", "filter", "OUTPUT", "handle", &handle,
                ],
            )?;
            if status.status.success() {
                return Ok(());
            }
            return Err(io::Error::other(format!("Failed to unblock IP {}", ip)));
        }
    }
    println!("[*] IP {} is not currently blocked in nftables.", ip);
    Ok(())
}

fn get_blocked_ips_nft() -> Vec<String> {
    let mut blocked = Vec::new();
    if let Ok(output) = run_cmd("nft", &["-a", "list", "chain", "ip", "filter", "OUTPUT"]) {
        let content = String::from_utf8_lossy(&output.stdout);
        for line in content.lines() {
            if line.contains("daddr") && line.contains("drop") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                for (i, &part) in parts.iter().enumerate() {
                    if part == "daddr" && i + 1 < parts.len() {
                        blocked.push(parts[i + 1].to_string());
                    }
                }
            }
        }
    }
    blocked
}

/// Parses the `# handle <n>` suffix from an nftables rule listing line.
fn parse_nft_handle(line: &str) -> Option<String> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    let mut seen_handle = false;
    for &part in parts.iter() {
        if part == "handle" {
            seen_handle = true;
        } else if seen_handle {
            return Some(part.to_string());
        }
    }
    None
}

fn block_ip_iptables(ip: &str) -> io::Result<()> {
    // 1. Check if rule already exists to avoid duplicates
    let check_status = run_cmd("iptables", &["-C", "OUTPUT", "-d", ip, "-j", "DROP"])?;

    if check_status.status.success() {
        println!("[*] IP {} is already blocked in iptables.", ip);
        return Ok(());
    }

    // 2. Add the block rule
    println!("[!] Blocking outgoing traffic to IP: {} using iptables", ip);
    let add_status = run_cmd("iptables", &["-A", "OUTPUT", "-d", ip, "-j", "DROP"])?;

    if add_status.status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Failed to run iptables. Are you running as root/sudo?",
        ))
    }
}

/// Blocks an IP address using the detected firewall backend (nftables or iptables).
pub fn block_ip(ip: &str) -> io::Result<()> {
    match detect_firewall_backend() {
        Some(FirewallBackend::Nft) => block_ip_nft(ip),
        Some(FirewallBackend::Iptables) => block_ip_iptables(ip),
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No firewall backend available (neither nft nor iptables found)",
        )),
    }
}

/// Unblocks an IP address using the detected firewall backend.
pub fn unblock_ip(ip: &str) -> io::Result<()> {
    match detect_firewall_backend() {
        Some(FirewallBackend::Nft) => unblock_ip_nft(ip),
        Some(FirewallBackend::Iptables) => {
            println!("[*] Unblocking IP: {} using iptables", ip);
            let status = Command::new("iptables")
                .args(["-D", "OUTPUT", "-d", ip, "-j", "DROP"])
                .status()?;

            if status.success() {
                Ok(())
            } else {
                Err(io::Error::other(format!("Failed to unblock IP {}", ip)))
            }
        }
        None => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "No firewall backend available (neither nft nor iptables found)",
        )),
    }
}

/// Lists currently blocked IP addresses from the active firewall backend.
pub fn get_blocked_ips() -> io::Result<Vec<String>> {
    match detect_firewall_backend() {
        Some(FirewallBackend::Nft) => Ok(get_blocked_ips_nft()),
        Some(FirewallBackend::Iptables) => {
            let output = run_cmd("iptables", &["-S", "OUTPUT"])?;

            if !output.status.success() {
                return Err(io::Error::other(
                    "Failed to execute iptables -S OUTPUT. Make sure you have sudo/root privileges.",
                ));
            }

            let content = String::from_utf8_lossy(&output.stdout);
            let mut blocked = Vec::new();

            for line in content.lines() {
                // Example: -A OUTPUT -d 185.112.144.110/32 -j DROP
                if line.contains("-A OUTPUT") && line.contains("-j DROP") {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    for (i, &part) in parts.iter().enumerate() {
                        if part == "-d" && i + 1 < parts.len() {
                            let mut ip = parts[i + 1].to_string();
                            if ip.ends_with("/32") {
                                ip = ip.replace("/32", "");
                            }
                            blocked.push(ip);
                        }
                    }
                }
            }

            Ok(blocked)
        }
        None => Ok(Vec::new()),
    }
}

/// Identifies processes running from temporary directories like /tmp, /var/tmp, /dev/shm
pub fn find_suspicious_processes() -> Vec<(u32, String)> {
    let mut susp = Vec::new();
    let proc_dir = Path::new("/proc");
    if let Ok(entries) = fs::read_dir(proc_dir) {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            if path.is_dir()
                && let Some(pid_str) = path.file_name().and_then(|s| s.to_str())
                && let Ok(pid) = pid_str.parse::<u32>()
            {
                let exe_link = path.join("exe");
                if let Ok(target) = fs::read_link(exe_link) {
                    let target_str = target.to_string_lossy();
                    if target_str.starts_with("/tmp/")
                        || target_str.starts_with("/var/tmp/")
                        || target_str.starts_with("/dev/shm/")
                        || target_str.starts_with("/run/user/")
                    {
                        susp.push((pid, target_str.into_owned()));
                    }
                }
            }
        }
    }
    susp
}

/// Returns true if the remote port matches a known cryptominer stratum protocol port
pub fn is_mining_port(port: u16) -> bool {
    matches!(port, 3333 | 4444 | 5555 | 7777 | 8888 | 14444)
}

use crate::quarantine::QuarantineManager;
use crate::scanner::Scanner;
use crate::utils::{log_detection, log_message};
use aya::Bpf;
use aya::maps::perf::PerfEventArray;
use aya::programs::TracePoint;
use aya::util::online_cpus;
use bytes::BytesMut;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConnectEvent {
    pub pid: u32,
    pub saddr: u32,
    pub sport: u16,
    pub dport: u16,
    pub comm: [u8; 16],
}

pub struct EbpfMonitor {
    bpf: Bpf,
    _blacklist_ips: Vec<String>,
    scanner: Scanner,
    quarantine: QuarantineManager,
    action: String,
}

pub fn get_process_executable_path(pid: u32) -> Option<String> {
    let exe_link = format!("/proc/{}/exe", pid);
    std::fs::read_link(exe_link)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

impl EbpfMonitor {
    pub fn new(
        ips: &[String],
        domains: &[String],
        scanner: Scanner,
        quarantine: QuarantineManager,
        action: &str,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let bpf_path = "/usr/lib/ferroshield/ferroshield_ebpf.o";
        if !Path::new(bpf_path).exists() {
            return Err("eBPF object file not found at /usr/lib/ferroshield/ferroshield_ebpf.o. Silakan pasang modul kernel FerroShield.".into());
        }
        let data = std::fs::read(bpf_path)?;
        let mut bpf = Bpf::load(&data)?;

        // Populate BLACKLIST_IPS map
        if let Some(m) = bpf.map_mut("BLACKLIST_IPS") {
            let mut hash_map = aya::maps::HashMap::try_from(m)?;
            for ip in ips {
                if let Ok(addr) = ip.parse::<std::net::Ipv4Addr>() {
                    let val: u8 = 1;
                    let ip_u32 = u32::from_ne_bytes(addr.octets());
                    hash_map.insert(ip_u32, val, 0)?;
                }
            }
        }

        // Populate BLACKLIST_DOMAINS map
        if let Some(m) = bpf.map_mut("BLACKLIST_DOMAINS") {
            let mut hash_map: aya::maps::HashMap<_, [u8; 64], u8> =
                aya::maps::HashMap::try_from(m)?;
            for domain in domains {
                let mut domain_bytes = [0u8; 64];
                let bytes = domain.as_bytes();
                let len = bytes.len().min(63);
                domain_bytes[..len].copy_from_slice(&bytes[..len]);
                let val: u8 = 1;
                hash_map.insert(domain_bytes, val, 0)?;
            }
        }

        Ok(Self {
            bpf,
            _blacklist_ips: ips.to_vec(),
            scanner,
            quarantine,
            action: action.to_string(),
        })
    }

    pub fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let program: &mut TracePoint = self
            .bpf
            .program_mut("sys_enter_connect")
            .ok_or("sys_enter_connect program not found in eBPF object")?
            .try_into()?;
        program.load()?;
        program.attach("syscalls", "sys_enter_connect")?;

        // Load and attach UProbe for DNS monitoring on getaddrinfo
        use aya::programs::UProbe;
        if let Some(program_mut) = self.bpf.program_mut("getaddrinfo") {
            let uprobe_res: Result<&mut UProbe, _> = program_mut.try_into();
            if let Ok(uprobe) = uprobe_res {
                let libc_paths = [
                    "/lib/x86_64-linux-gnu/libc.so.6",
                    "/lib/libc.so.6",
                    "/usr/lib/libc.so.6",
                    "/usr/lib64/libc.so.6",
                    "/lib64/libc.so.6",
                ];
                let mut attached = false;
                for path in &libc_paths {
                    if Path::new(path).exists()
                        && uprobe.load().is_ok()
                        && uprobe.attach(Some("getaddrinfo"), 0, path, None).is_ok()
                    {
                        log_message(&format!(
                            "[+] eBPF: UProbe getaddrinfo terpasang pada {}",
                            path
                        ));
                        attached = true;
                        break;
                    }
                }
                if !attached {
                    log_message("[-] eBPF: Gagal memasang UProbe getaddrinfo.");
                }
            }
        }

        let mut perf_array =
            PerfEventArray::try_from(self.bpf.map_mut("EVENTS").ok_or("EVENTS map not found")?)?;
        let online_cpus = online_cpus()?;

        let mut buffers = Vec::new();
        for cpu_id in online_cpus {
            let buf = perf_array.open(cpu_id, None)?;
            buffers.push(buf);
        }

        let net_scanner = self.scanner.clone();
        let net_quarantine = self.quarantine.clone();
        let net_action = self.action.clone();

        std::thread::scope(|s| {
            for mut buf in buffers {
                let net_scanner = net_scanner.clone();
                let net_quarantine = net_quarantine.clone();
                let net_action = net_action.clone();

                s.spawn(move || {
                    let mut read_bufs = vec![BytesMut::with_capacity(4096); 10];
                    loop {
                        match buf.read_events(&mut read_bufs) {
                            Ok(events) => {
                                for event in read_bufs.iter_mut().take(events.read) {
                                    if event.len() >= std::mem::size_of::<ConnectEvent>() {
                                        let ev = unsafe { &*(event.as_ptr() as *const ConnectEvent) };
                                        let remote_ip = format!(
                                            "{}.{}.{}.{}",
                                            (ev.saddr & 0xFF) as u8,
                                            ((ev.saddr >> 8) & 0xFF) as u8,
                                            ((ev.saddr >> 16) & 0xFF) as u8,
                                            ((ev.saddr >> 24) & 0xFF) as u8
                                        );
                                        let proc_name = std::str::from_utf8(&ev.comm)
                                            .unwrap_or("unknown")
                                            .trim_end_matches('\0')
                                            .to_string();

                                        log_detection(&format!(
                                            "[!] DETEKSI eBPF: Percobaan koneksi dari proses {} (PID {}) ke IP blacklist {} berhasil diblokir!",
                                            proc_name, ev.pid, remote_ip
                                        ));

                                        // 1. Quarantine or delete binary FIRST (isolates file before process kill)
                                        if let Some(proc_path) = get_process_executable_path(ev.pid) {
                                            let proc_path_ref = Path::new(&proc_path);
                                            if proc_path_ref.exists() && proc_path_ref.is_file() {
                                                if net_action == "delete" {
                                                    let _ = std::fs::remove_file(proc_path_ref);
                                                } else if let Ok((sha, _)) = net_scanner.calculate_hashes(proc_path_ref) {
                                                    let _ = net_quarantine.quarantine_file(proc_path_ref, &sha, "EBPF-BLOCK-PID");
                                                }
                                            }
                                        }

                                        // 2. Block IP via iptables SECOND
                                        let _ = block_ip(&remote_ip);

                                        // 3. Kill process PID THIRD
                                        let _ = kill_process(ev.pid);
                                    }
                                }
                            }
                            Err(_) => {
                                std::thread::sleep(std::time::Duration::from_millis(100));
                            }
                        }
                    }
                });
            }
        });

        Ok(())
    }
}

pub fn init_ebpf_monitor(
    ips: &[String],
    domains: &[String],
    scanner: Scanner,
    quarantine: QuarantineManager,
    action: &str,
) -> Result<EbpfMonitor, Box<dyn std::error::Error>> {
    EbpfMonitor::new(ips, domains, scanner, quarantine, action)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_ipv4() {
        // 127.0.0.1 stored little-endian as "0100007F"
        assert_eq!(parse_hex_ipv4("0100007F").as_deref(), Some("127.0.0.1"));
        // 185.112.146.12
        assert_eq!(
            parse_hex_ipv4("0C9270B9").as_deref(),
            Some("185.112.146.12")
        );
        assert_eq!(parse_hex_ipv4("0C9270"), None);
        assert_eq!(parse_hex_ipv4("zzz"), None);
    }

    #[test]
    fn test_parse_hex_port() {
        assert_eq!(parse_hex_port("0050"), Some(80));
        assert_eq!(parse_hex_port("1F90"), Some(8080));
        assert_eq!(parse_hex_port("xyz"), None);
    }

    #[test]
    fn test_is_mining_port() {
        assert!(is_mining_port(3333));
        assert!(is_mining_port(14444));
        assert!(!is_mining_port(443));
        assert!(!is_mining_port(80));
    }

    #[test]
    fn test_parse_nft_handle() {
        assert_eq!(
            parse_nft_handle("        ip daddr 185.112.146.12 drop # handle 7"),
            Some("7".to_string())
        );
        assert_eq!(parse_nft_handle("table ip filter {"), None);
        assert_eq!(parse_nft_handle(""), None);
    }

    #[test]
    fn test_backend_detection_is_stable() {
        // Detection is cached; both values must simply be consistent with commands available.
        let first = detect_firewall_backend();
        let second = detect_firewall_backend();
        assert_eq!(first, second);
    }
}
