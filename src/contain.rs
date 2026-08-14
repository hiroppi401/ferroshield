use crate::utils::{log_detection, log_message};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

/// How detected malicious processes should be contained (frozen) before the
/// on-disk binary is neutralized and the process is killed. Freezing first
/// stops the process from executing any code, so it cannot mutate itself,
/// write new files, or fork watchdog children while we clean up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContainStrategy {
    /// Try the cgroup v2 freezer (robust, atomic, catches orphans), falling
    /// back to SIGSTOP on the whole descendant tree when unavailable.
    Auto,
    /// Force the cgroup v2 freezer; do not fall back.
    Cgroup,
    /// SIGSTOP the whole descendant tree only.
    Sigstop,
    /// Disable containment entirely (legacy immediate-kill behavior).
    Off,
}

impl ContainStrategy {
    pub fn from_str(s: &str) -> ContainStrategy {
        match s {
            "cgroup" => ContainStrategy::Cgroup,
            "sigstop" => ContainStrategy::Sigstop,
            "off" => ContainStrategy::Off,
            _ => ContainStrategy::Auto,
        }
    }
}

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
const CGROUP_BASE: &str = "/sys/fs/cgroup/ferroshield";

/// A handle to a frozen (contained) malicious process tree.
pub struct Containment {
    root_pid: u32,
    method: Method,
}

enum Method {
    Cgroup { path: PathBuf },
    Sigstop { pids: Vec<u32> },
}

/// True when the unified cgroup v2 hierarchy (with its `cgroup.freeze` core
/// file) is mounted at /sys/fs/cgroup.
fn cgroup_v2_available() -> bool {
    Path::new(CGROUP_ROOT).join("cgroup.controllers").exists()
}

/// Returns `(state, ppid, pgrp)` for a PID parsed from /proc/<pid>/stat.
fn proc_stat(pid: u32) -> Option<(String, u32, u32)> {
    let content = fs::read_to_string(format!("/proc/{}/stat", pid)).ok()?;
    let rparen = content.rfind(')')?;
    let mut it = content[rparen + 1..].split_whitespace();
    let state = it.next()?.to_string();
    let ppid = it.next()?.parse().ok()?;
    let pgrp = it.next()?.parse().ok()?;
    Some((state, ppid, pgrp))
}

/// Collects every descendant PID of `pid` (excluding `pid` itself) by walking
/// the /proc parent/child relationship.
pub fn collect_descendants(pid: u32) -> Vec<u32> {
    use std::collections::{HashMap, HashSet};
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    if let Ok(entries) = fs::read_dir("/proc") {
        for entry in entries.filter_map(Result::ok) {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Ok(p) = name.parse::<u32>() else {
                continue;
            };
            if let Some((_, ppid, _)) = proc_stat(p) {
                children.entry(ppid).or_default().push(p);
            }
        }
    }
    let mut result = Vec::new();
    let mut queue = vec![pid];
    let mut seen = HashSet::new();
    seen.insert(pid);
    while let Some(p) = queue.pop() {
        if let Some(kids) = children.get(&p) {
            for &k in kids {
                if seen.insert(k) {
                    result.push(k);
                    queue.push(k);
                }
            }
        }
    }
    result
}

/// Never freeze or kill the daemon itself, PID 0/1, or any FerroShield process.
fn is_protected(pid: u32) -> bool {
    if pid <= 1 || pid == std::process::id() {
        return true;
    }
    if let Some(exe) = crate::network::get_process_executable_path(pid)
        && exe.contains("ferroshield")
    {
        return true;
    }
    false
}

/// Freezes `pid` (and every current descendant) with the cgroup v2 freezer and
/// returns the created cgroup path.
fn freeze_cgroup(pid: u32) -> io::Result<PathBuf> {
    if !cgroup_v2_available() {
        return Err(io::Error::other("cgroup v2 tidak tersedia"));
    }
    fs::create_dir_all(CGROUP_BASE)?;

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let dir = PathBuf::from(format!("{}/pid{}-{}", CGROUP_BASE, pid, nanos));
    fs::create_dir(&dir)?;

    // Move the root PID and all current descendants into the cgroup. Children
    // inherit membership, so anything forked later stays frozen too.
    let mut pids = collect_descendants(pid);
    pids.push(pid);
    let mut moved = 0;
    {
        use std::io::Write;
        let mut proc_file = fs::OpenOptions::new()
            .append(true)
            .open(dir.join("cgroup.procs"))?;
        for p in &pids {
            if writeln!(proc_file, "{}", p).is_ok() {
                moved += 1;
            }
        }
    }

    if moved == 0 {
        let _ = fs::remove_dir(&dir);
        return Err(io::Error::other(
            "tidak ada proses yang bisa dipindahkan ke cgroup",
        ));
    }

    // Freeze the cgroup. Frozen processes cannot execute any code (no fork,
    // no file writes, no signal handling), which closes the mutation window.
    fs::write(dir.join("cgroup.freeze"), "1")?;
    // Give the kernel a moment to make the freeze effective.
    std::thread::sleep(std::time::Duration::from_millis(50));
    Ok(dir)
}

/// Sends SIGSTOP to every PID in `pids`.
fn stop_pids(pids: &[u32]) {
    for pid in pids {
        let _ = Command::new("kill")
            .args(["-STOP", &pid.to_string()])
            .status();
    }
}

/// Sends SIGKILL to every PID in `pids`.
fn kill_pids(pids: &[u32]) {
    for pid in pids {
        let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
    }
}

/// Freezes a detected malicious process together with its whole descendant
/// tree. Returns `None` when the process no longer exists, is protected, or
/// containment is disabled (the caller then falls back to a plain kill).
pub fn contain_process(pid: u32, strategy: ContainStrategy) -> Option<Containment> {
    if is_protected(pid) || !Path::new(&format!("/proc/{}", pid)).exists() {
        return None;
    }

    let use_cgroup = match strategy {
        ContainStrategy::Cgroup => true,
        ContainStrategy::Sigstop | ContainStrategy::Off => false,
        ContainStrategy::Auto => cgroup_v2_available(),
    };

    if use_cgroup {
        match freeze_cgroup(pid) {
            Ok(path) => {
                log_detection(&format!(
                    "[+] PID {} dan seluruh keturunannya DIBEKUKAN via cgroup freezer ({}).",
                    pid,
                    path.display()
                ));
                return Some(Containment {
                    root_pid: pid,
                    method: Method::Cgroup { path },
                });
            }
            Err(e) => {
                log_message(&format!(
                    "[-] Gagal membekukan PID {} via cgroup freezer: {}. Mencoba SIGSTOP...",
                    pid, e
                ));
            }
        }
    }

    if strategy == ContainStrategy::Off {
        return None;
    }

    // SIGSTOP fallback: stop the root PID and every current descendant.
    let mut pids = collect_descendants(pid);
    pids.push(pid);
    stop_pids(&pids);
    log_detection(&format!(
        "[+] PID {} dan {} keturunannya DIBEKUKAN via SIGSTOP (anti-mutasi).",
        pid,
        pids.len().saturating_sub(1)
    ));
    Some(Containment {
        root_pid: pid,
        method: Method::Sigstop { pids },
    })
}

/// Kills a frozen (contained) process tree with SIGKILL and cleans up any
/// leftover cgroup. SIGKILL is not blocked by the freezer, so a frozen
/// process cannot escape.
pub fn kill_contained(containment: &Containment) -> io::Result<()> {
    match &containment.method {
        Method::Cgroup { path } => {
            let mut pids = collect_descendants(containment.root_pid);
            pids.push(containment.root_pid);
            kill_pids(&pids);

            // Enumerate any PID still listed in the cgroup and kill it too.
            if let Ok(procs) = fs::read_to_string(path.join("cgroup.procs")) {
                for line in procs.lines() {
                    if let Ok(p) = line.trim().parse::<u32>()
                        && !pids.contains(&p)
                    {
                        let _ = Command::new("kill").args(["-9", &p.to_string()]).status();
                    }
                }
            }

            // Unfreeze then remove the cgroup (fails silently if still busy).
            let _ = fs::write(path.join("cgroup.freeze"), "0");
            let _ = fs::remove_dir(path);
            log_message(&format!(
                "[+] PID {} beserta keturunannya dibunuh (SIGKILL) dan cgroup dibersihkan.",
                containment.root_pid
            ));
            Ok(())
        }
        Method::Sigstop { pids } => {
            let mut all = pids.clone();
            for extra in collect_descendants(containment.root_pid) {
                if !all.contains(&extra) {
                    all.push(extra);
                }
            }
            kill_pids(&all);
            log_message(&format!(
                "[+] PID {} beserta keturunannya dibunuh (SIGKILL).",
                containment.root_pid
            ));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proc_stat_parses_fields() {
        // The test process itself must parse back to itself as ppid and the
        // shell process group.
        let self_pid = std::process::id();
        let (state, ppid, _pgrp) = proc_stat(self_pid).expect("stat should parse");
        assert!(!state.is_empty());
        assert!(ppid > 0);
    }

    #[test]
    fn test_collect_descendants_finds_children() {
        // sh -c spawns two background sleeps; both must be found as children.
        let mut child = Command::new("sh")
            .args(["-c", "sleep 5 & sleep 5 & wait"])
            .spawn()
            .expect("spawn sh");
        std::thread::sleep(std::time::Duration::from_millis(300));
        let pids = collect_descendants(child.id());
        assert!(
            pids.len() >= 2,
            "expected at least 2 children, got {:?}",
            pids
        );
        let _ = Command::new("kill")
            .args(["-9", &child.id().to_string()])
            .status();
        let _ = child.wait();
    }

    #[test]
    fn test_contain_and_kill_sigstop_roundtrip() {
        // Works without root: SIGSTOP on our own child is permitted.
        let mut child = Command::new("sleep").arg("30").spawn().expect("sleep");
        std::thread::sleep(std::time::Duration::from_millis(100));

        let containment = contain_process(child.id(), ContainStrategy::Sigstop);
        assert!(containment.is_some(), "containment should succeed");

        let (state, _, _) = proc_stat(child.id()).expect("stat should parse");
        assert!(
            state.starts_with('T'),
            "process should be stopped, got state {}",
            state
        );

        kill_contained(containment.as_ref().unwrap()).expect("kill_contained");
        // Reap the zombie so /proc/<pid> disappears.
        let _ = child.wait();
        assert!(
            !Path::new(&format!("/proc/{}", child.id())).exists(),
            "child should be gone after kill"
        );
    }

    #[test]
    fn test_contain_process_off_returns_none() {
        let mut child = Command::new("sleep").arg("5").spawn().expect("sleep");
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert!(contain_process(child.id(), ContainStrategy::Off).is_none());
        let _ = Command::new("kill")
            .args(["-9", &child.id().to_string()])
            .status();
        let _ = child.wait();
    }
}
