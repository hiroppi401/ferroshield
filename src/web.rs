use crate::config::RulesConfig;
use crate::quarantine::QuarantineManager;
use crate::scanjob;
use crate::scanjob::ScanProgress;
use crate::scanner::Scanner;
use crate::utils::{get_logs, log_message};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, BufRead};
use std::path::Path;
use std::process::Child;
use std::thread;
use std::time::Duration;
use tiny_http::{Header, Method, Response, Server, StatusCode};

use std::sync::Mutex;
use std::sync::OnceLock;

use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
pub static SCAN_THREAD_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static SCAN_STATUS: AtomicU8 = AtomicU8::new(0); // 0: Idle, 1: Counting, 2: Scanning, 3: Paused, 4: Stopped, 5: Completed, 6: Error
static SCAN_GENERATION: AtomicU64 = AtomicU64::new(0);

static SCAN_PROGRESS: OnceLock<Mutex<ScanProgress>> = OnceLock::new();
static SCAN_CHILD: OnceLock<Mutex<Option<Child>>> = OnceLock::new();

fn progress_mutex() -> &'static Mutex<ScanProgress> {
    SCAN_PROGRESS.get_or_init(|| Mutex::new(ScanProgress::idle()))
}

fn scan_child() -> &'static Mutex<Option<Child>> {
    SCAN_CHILD.get_or_init(|| Mutex::new(None))
}

fn terminate_scan_child() {
    if let Some(mut child) = scan_child().lock().ok().and_then(|mut g| g.take()) {
        let _ = child.kill();
        let _ = child.wait();
    }
}

/// Spawns the CLI scan process (`ferroshield scan <target> --json`) and follows its
/// JSON progress lines, feeding them into the shared progress state so the UI progress
/// bar mirrors the actual CLI scan. The scan runs as a separate process, so it keeps
/// running (and keeps progressing) even if the UI is closed.
fn start_scan_process(
    quarantine_mgr: &QuarantineManager,
    target: &str,
    delete: bool,
    resume: bool,
    generation: u64,
) -> Result<(), String> {
    let quarantine_dir = quarantine_mgr.quarantine_dir.clone();

    let mut child = scanjob::spawn_scan_process(target, delete, resume, &quarantine_dir)?;
    let stdout = child.stdout.take().expect("piped stdout");
    *scan_child().lock().map_err(|e| e.to_string())? = Some(child);

    thread::spawn(move || {
        let reader = io::BufReader::new(stdout);
        for line in reader.lines() {
            // A newer scan was started; stop touching any shared state.
            if SCAN_GENERATION.load(Ordering::SeqCst) != generation {
                return;
            }
            let Ok(line) = line else { continue };
            if let Ok(prog) = serde_json::from_str::<ScanProgress>(&line) {
                let status_str = prog.status.clone();
                let is_terminal = matches!(status_str.as_str(), "completed" | "stopped" | "error");
                if let Ok(mut progress) = progress_mutex().lock() {
                    *progress = prog;
                }
                let atomic_status = match status_str.as_str() {
                    "counting" => 1,
                    "paused" => 3,
                    "stopped" => 4,
                    "completed" => 5,
                    "error" => 6,
                    _ => 2,
                };
                SCAN_STATUS.store(atomic_status, Ordering::SeqCst);
                if is_terminal {
                    SCAN_THREAD_ACTIVE.store(false, Ordering::SeqCst);
                    terminate_scan_child();
                    let _ = fs::remove_file(scanjob::scan_pid_path(&quarantine_dir));
                    let _ = fs::remove_file(scanjob::control_path(&quarantine_dir));
                }
            }
        }
        // EOF: child process exited without emitting a terminal status line
        if SCAN_GENERATION.load(Ordering::SeqCst) != generation {
            return;
        }
        if let Ok(mut progress) = progress_mutex().lock()
            && matches!(progress.status.as_str(), "counting" | "scanning" | "paused")
        {
            progress.status = "stopped".to_string();
            SCAN_STATUS.store(4, Ordering::SeqCst);
        }
        SCAN_THREAD_ACTIVE.store(false, Ordering::SeqCst);
        terminate_scan_child();
        let _ = fs::remove_file(scanjob::scan_pid_path(&quarantine_dir));
    });

    Ok(())
}

#[derive(Deserialize)]
struct ScanRequest {
    path: String,
    delete: bool,
    resume: Option<bool>,
}

#[derive(Serialize)]
struct StatusResponse {
    status: String,
    rules_count: usize,
    quarantine_count: usize,
    log_count: usize,
    action: String,
}

const DASHBOARD_TOKEN_FILE: &str = "dashboard.token";
const TOKEN_PLACEHOLDER: &str = "__FERROSHIELD_TOKEN__";

/// Loads the dashboard token from disk or generates a fresh 64-hex-char token
/// (32 random bytes) persisted with 0600 permissions. The token is required in
/// the `Authorization: Bearer <token>` header of every `/api/*` request so that
/// local non-browser processes cannot drive destructive actions (scan + delete,
/// quarantine, whitelist, network block) against the root daemon.
fn load_or_create_dashboard_token() -> String {
    load_or_create_dashboard_token_at(Path::new(DASHBOARD_TOKEN_FILE))
}

/// Loads the dashboard token from `path` or generates a fresh 64-hex-char token
/// (32 random bytes) persisted with 0600 permissions. The token is required in
/// the `Authorization: Bearer <token>` header of every `/api/*` request so that
/// local non-browser processes cannot drive destructive actions (scan + delete,
/// quarantine, whitelist, network block) against the root daemon.
fn load_or_create_dashboard_token_at<P: AsRef<Path>>(path: P) -> String {
    let path = path.as_ref();
    if let Ok(existing) = std::fs::read_to_string(path) {
        let existing = existing.trim().to_string();
        if existing.len() == 64 && existing.chars().all(|c| c.is_ascii_hexdigit()) {
            return existing;
        }
    }
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let token = bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();
    if std::fs::write(path, &token).is_ok() {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::metadata(path).map(|m| {
            let mut perms = m.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)
        });
    } else {
        eprintln!("[-] Gagal menulis file token dashboard: {}", path.display());
    }
    token
}

/// True when the request carries a valid `Authorization: Bearer <token>` header.
fn is_authorized(request: &tiny_http::Request, token: &str) -> bool {
    let expected = format!("Bearer {}", token);
    request.headers().iter().any(|h| {
        h.field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("authorization")
            && h.value.as_str().trim().eq_ignore_ascii_case(&expected)
    })
}

fn json_response(status: u16, body: &str) -> Response<std::io::Cursor<Vec<u8>>> {
    Response::from_string(body.to_string())
        .with_status_code(StatusCode(status))
        .with_header(Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap())
}

/// Applies the request guards for every request. Returns `Some(response)` when
/// the request must be rejected, `None` when it may proceed. This is the single
/// enforcement point exercised by the auth integration tests.
fn enforce_request_guards(
    request: &tiny_http::Request,
    method: &Method,
    token: &str,
) -> Option<Response<std::io::Cursor<Vec<u8>>>> {
    if !is_allowed_host(request) {
        return Some(json_response(403, "{\"error\": \"Forbidden\"}"));
    }
    if method == &Method::Post && !is_same_site(request) {
        return Some(json_response(
            403,
            "{\"error\": \"Cross-site request rejected\"}",
        ));
    }
    if request.url().starts_with("/api/") && !is_authorized(request, token) {
        return Some(json_response(401, "{\"error\": \"Unauthorized\"}"));
    }
    None
}

/// Starts the built-in HTTP server serving Web UI and API
pub fn start_web_server(
    host: &str,
    port: u16,
    scanner: Scanner,
    quarantine_mgr: QuarantineManager,
    rules_config: RulesConfig,
    default_action: String,
) {
    let addr = format!("{}:{}", host, port);

    // 2. Initialize HTTP/HTTPS server
    let crt_path = "dashboard.crt";
    let key_path = "dashboard.key";

    let server = if Path::new(crt_path).exists() && Path::new(key_path).exists() {
        if let (Ok(crt_bytes), Ok(key_bytes)) = (fs::read(crt_path), fs::read(key_path)) {
            let ssl_config = tiny_http::SslConfig {
                certificate: crt_bytes,
                private_key: key_bytes,
            };
            match Server::https(&addr, ssl_config) {
                Ok(s) => {
                    log_message(&format!(
                        "[+] Web UI Dashboard berjalan di HTTPS: https://{}",
                        addr
                    ));
                    log_message(&format!("[+] Tautan dashboard: https://{}", addr));
                    s
                }
                Err(e) => {
                    log_message(&format!(
                        "[-] Gagal memulai HTTPS server pada {}: {}. Mencoba HTTP fallback...",
                        addr, e
                    ));
                    match Server::http(&addr) {
                        Ok(s) => {
                            log_message(&format!(
                                "[+] Web UI Dashboard berjalan di HTTP fallback: http://{}",
                                addr
                            ));
                            log_message(&format!("[+] Tautan dashboard: http://{}", addr));
                            s
                        }
                        Err(err) => {
                            log_message(&format!(
                                "[-] Gagal memulai HTTP fallback server pada {}: {}",
                                addr, err
                            ));
                            return;
                        }
                    }
                }
            }
        } else {
            log_message("[-] Gagal membaca file sertifikat TLS. Mencoba HTTP fallback...");
            match Server::http(&addr) {
                Ok(s) => {
                    log_message(&format!(
                        "[+] Web UI Dashboard berjalan di HTTP: http://{}",
                        addr
                    ));
                    log_message(&format!("[+] Tautan dashboard: http://{}", addr));
                    s
                }
                Err(e) => {
                    log_message(&format!(
                        "[-] Gagal memulai HTTP fallback server pada {}: {}",
                        addr, e
                    ));
                    return;
                }
            }
        }
    } else {
        match Server::http(&addr) {
            Ok(s) => {
                log_message(&format!(
                    "[+] Web UI Dashboard berjalan di HTTP: http://{}",
                    addr
                ));
                log_message(&format!("[+] Tautan dashboard: http://{}", addr));
                s
            }
            Err(e) => {
                log_message(&format!(
                    "[-] Gagal memulai HTTP server pada {}: {}",
                    addr, e
                ));
                return;
            }
        }
    };

    // Dashboard auth token. Required as `Authorization: Bearer <token>` on every
    // /api/* request (see `enforce_request_guards`); it is injected into the
    // served index.html so the browser works without manual entry. The token
    // file is written with 0600 permissions so only the daemon user can read it.
    let dashboard_token = load_or_create_dashboard_token();
    log_message(&format!(
        "[+] Token dashboard aktif. Berkas token: {} (0600). Semua endpoint /api/* memerlukan header Authorization: Bearer <token>.",
        DASHBOARD_TOKEN_FILE
    ));

    // Check if there is an interrupted scan state to resume
    let state_path = scanjob::state_path(&quarantine_mgr.quarantine_dir);

    if let Some(state) = scanjob::load_scan_state(&state_path) {
        if matches!(state.status.as_str(), "scanning" | "counting" | "paused") {
            // A scan process may still be running (e.g. daemon restarted while the CLI
            // scan process continued). If so, keep following its progress via scan_state.json.
            let pid = fs::read_to_string(scanjob::scan_pid_path(&quarantine_mgr.quarantine_dir))
                .ok()
                .and_then(|s| s.trim().parse::<u32>().ok());
            let alive = pid
                .map(|p| Path::new(&format!("/proc/{}", p)).exists())
                .unwrap_or(false);
            let generation = SCAN_GENERATION.load(Ordering::SeqCst);

            if alive {
                log_message(&format!(
                    "[+] Pemindaian masih berjalan (PID {}). Melanjutkan pemantauan progress dari scan_state.json...",
                    pid.unwrap_or(0)
                ));
                SCAN_THREAD_ACTIVE.store(true, Ordering::SeqCst);
                let sp_watch = state_path.clone();
                let qd_watch = quarantine_mgr.quarantine_dir.clone();
                thread::spawn(move || {
                    let mut last_seen = String::new();
                    loop {
                        if SCAN_GENERATION.load(Ordering::SeqCst) != generation {
                            return;
                        }
                        if let Some(st) = scanjob::load_scan_state(&sp_watch) {
                            if st.status != last_seen {
                                last_seen = st.status.clone();
                                if let Ok(mut progress) = progress_mutex().lock() {
                                    *progress = ScanProgress::from_state(
                                        &st,
                                        st.scanned_files.len(),
                                        st.total_files,
                                        "",
                                    );
                                }
                                let atomic_status = match st.status.as_str() {
                                    "counting" => 1,
                                    "paused" => 3,
                                    "stopped" => 4,
                                    "completed" => 5,
                                    "error" => 6,
                                    _ => 2,
                                };
                                SCAN_STATUS.store(atomic_status, Ordering::SeqCst);
                            }
                            if matches!(st.status.as_str(), "completed" | "stopped" | "error") {
                                SCAN_THREAD_ACTIVE.store(false, Ordering::SeqCst);
                                let _ = fs::remove_file(scanjob::scan_pid_path(&qd_watch));
                                break;
                            }
                        }
                        thread::sleep(Duration::from_millis(500));
                    }
                });
            } else {
                log_message(&format!(
                    "[+] Mendeteksi pemindaian terganggu pada: {}. Melanjutkan pemindaian...",
                    state.target_path
                ));
                SCAN_THREAD_ACTIVE.store(true, Ordering::SeqCst);
                let generation = SCAN_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
                if let Err(e) = start_scan_process(
                    &quarantine_mgr,
                    &state.target_path,
                    state.delete,
                    true,
                    generation,
                ) {
                    log_message(&format!("[-] Gagal melanjutkan pemindaian: {}", e));
                }
            }
        } else if let Ok(mut progress) = progress_mutex().lock() {
            *progress =
                ScanProgress::from_state(&state, state.scanned_files.len(), state.total_files, "");
        }
    }

    thread::spawn(move || {
        for mut request in server.incoming_requests() {
            let method = request.method().clone();
            let url = request.url().to_string();

            // Localhost-only access guard: reject foreign Host headers (DNS rebinding),
            // cross-site state-changing requests (CSRF from malicious websites), and any
            // /api/* request that lacks the dashboard bearer token (local non-browser
            // processes, e.g. curl, do not send Origin/Sec-Fetch-Site by default).
            if let Some(rejected) = enforce_request_guards(&request, &method, &dashboard_token) {
                let _ = request.respond(rejected);
                continue;
            }

            let response = match handle_request(
                &mut request,
                &WebContext {
                    scanner: &scanner,
                    quarantine_mgr: &quarantine_mgr,
                    rules_config: &rules_config,
                    default_action: &default_action,
                    dashboard_token: &dashboard_token,
                },
                &method,
                &url,
            ) {
                Ok(res) => res,
                Err(err_msg) => {
                    let body = format!("{{\"error\": \"{}\"}}", err_msg);
                    Response::from_string(body)
                        .with_status_code(StatusCode(500))
                        .with_header(
                            Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                                .unwrap(),
                        )
                }
            };

            // Add security headers (no CORS allow-all: cross-origin reads are blocked,
            // which is enforced together with the Origin/Sec-Fetch-Site guard above)
            let response = response
                .with_header(
                    Header::from_bytes(&b"Referrer-Policy"[..], &b"no-referrer"[..]).unwrap(),
                )
                .with_header(
                    Header::from_bytes(&b"X-Content-Type-Options"[..], &b"nosniff"[..]).unwrap(),
                )
                .with_header(Header::from_bytes(&b"X-Frame-Options"[..], &b"DENY"[..]).unwrap());

            // Send the response
            let _ = request.respond(response);
        }
    });
}

/// Shared references needed by `handle_request`, grouped so the function keeps a
/// manageable argument list.
struct WebContext<'a> {
    scanner: &'a Scanner,
    quarantine_mgr: &'a QuarantineManager,
    rules_config: &'a RulesConfig,
    default_action: &'a str,
    dashboard_token: &'a str,
}

fn handle_request(
    request: &mut tiny_http::Request,
    ctx: &WebContext<'_>,
    method: &Method,
    url: &str,
) -> Result<Response<std::io::Cursor<Vec<u8>>>, String> {
    // Content-Type headers
    let html_header =
        Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap();
    let json_header = Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();

    // Serve Frontend
    if (method == &Method::Get) && (url == "/" || url == "/index.html" || url == "/index") {
        let html_content =
            include_str!("../web/index.html").replace(TOKEN_PLACEHOLDER, ctx.dashboard_token);
        return Ok(Response::from_string(html_content)
            .with_status_code(StatusCode(200))
            .with_header(html_header));
    }

    if (method == &Method::Get) && (url == "/favicon.svg" || url == "/favicon.ico") {
        let svg_content = include_str!("../web/favicon.svg");
        let svg_header = Header::from_bytes(&b"Content-Type"[..], &b"image/svg+xml"[..]).unwrap();
        return Ok(Response::from_string(svg_content)
            .with_status_code(StatusCode(200))
            .with_header(svg_header));
    }

    // Serve APIs
    match (method, url) {
        (&Method::Get, "/api/status") => {
            let q_count = ctx
                .quarantine_mgr
                .list_quarantined()
                .map(|l| l.len())
                .unwrap_or(0);

            let res = StatusResponse {
                status: "active".to_string(),
                rules_count: ctx.rules_config.rules.len(),
                quarantine_count: q_count,
                log_count: get_logs().len(),
                action: ctx.default_action.to_string(),
            };
            let body = serde_json::to_string(&res).map_err(|e| e.to_string())?;
            Ok(Response::from_string(body)
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Get, "/api/quarantine") => {
            let list = ctx
                .quarantine_mgr
                .list_quarantined()
                .map_err(|e| e.to_string())?;
            let body = serde_json::to_string(&list).map_err(|e| e.to_string())?;
            Ok(Response::from_string(body)
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Get, "/api/logs") => {
            let logs = get_logs();
            let body = serde_json::to_string(&logs).map_err(|e| e.to_string())?;
            Ok(Response::from_string(body)
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Get, "/api/network/connections") => {
            let list = crate::network::get_active_connections().map_err(|e| e.to_string())?;
            let body = serde_json::to_string(&list).map_err(|e| e.to_string())?;
            Ok(Response::from_string(body)
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Get, "/api/network/blocked") => {
            let list = crate::network::get_blocked_ips().unwrap_or_default();
            let body = serde_json::to_string(&list).map_err(|e| e.to_string())?;
            Ok(Response::from_string(body)
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Post, "/api/scan") => {
            let mut content = String::new();
            request
                .as_reader()
                .read_to_string(&mut content)
                .map_err(|e| e.to_string())?;
            let req: ScanRequest = serde_json::from_str(&content).map_err(|e| e.to_string())?;

            let target_path = req.path.clone();
            let p = Path::new(&target_path);
            if !p.exists() {
                return Ok(
                    Response::from_string("{\"error\": \"Path tidak ditemukan\"}")
                        .with_status_code(StatusCode(400))
                        .with_header(json_header),
                );
            }

            let is_resume = req.resume.unwrap_or(false);

            {
                let mut progress = progress_mutex().lock().map_err(|e| e.to_string())?;
                if SCAN_THREAD_ACTIVE.load(Ordering::SeqCst)
                    || progress.status == "scanning"
                    || progress.status == "counting"
                    || progress.status == "paused"
                {
                    return Ok(Response::from_string("{\"error\": \"Pemindaian sedang berjalan atau dijeda. Hentikan (stop) terlebih dahulu sebelum memulai pemindaian baru.\"}")
                        .with_status_code(StatusCode(400))
                        .with_header(json_header));
                }

                SCAN_THREAD_ACTIVE.store(true, Ordering::SeqCst);

                if is_resume {
                    SCAN_STATUS.store(2, Ordering::SeqCst); // Scanning
                    progress.status = "scanning".to_string();
                } else {
                    SCAN_STATUS.store(1, Ordering::SeqCst); // Counting
                    progress.status = "counting".to_string();
                }
                progress.target_path = target_path.clone();
                if !is_resume {
                    progress.total_files = 0;
                    progress.scanned_files = 0;
                    progress.current_file = "".to_string();
                    progress.threats_found = 0;
                    progress.results = Vec::new();
                    progress.error = None;
                }
            }

            // Clean stale state before starting a fresh CLI scan process
            let quarantine_dir = ctx.quarantine_mgr.quarantine_dir.clone();
            if !is_resume {
                let _ = fs::remove_file(scanjob::state_path(&quarantine_dir));
            }
            // Start the scan in a separate CLI process; the UI follows its JSON output.
            // Bump the generation first so any lingering threads of a previous scan
            // stop touching shared state.
            let generation = SCAN_GENERATION.fetch_add(1, Ordering::SeqCst) + 1;
            terminate_scan_child();
            start_scan_process(
                ctx.quarantine_mgr,
                &target_path,
                req.delete,
                is_resume,
                generation,
            )
            .inspect_err(|_| {
                SCAN_THREAD_ACTIVE.store(false, Ordering::SeqCst);
                SCAN_STATUS.store(6, Ordering::SeqCst);
            })?;

            Ok(Response::from_string("{\"status\": \"started\"}")
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Post, "/api/scan/action/quarantine") => {
            let mut content = String::new();
            request
                .as_reader()
                .read_to_string(&mut content)
                .map_err(|e| e.to_string())?;

            #[derive(Deserialize)]
            struct QuarantineRequest {
                path: String,
                rule_id: Option<String>,
            }

            let req: QuarantineRequest =
                serde_json::from_str(&content).map_err(|e| e.to_string())?;
            let path = Path::new(&req.path);

            if !path.exists() {
                return Ok(
                    Response::from_string("{\"error\": \"Berkas tidak ditemukan\"}")
                        .with_status_code(StatusCode(400))
                        .with_header(json_header),
                );
            }

            let (sha256, _) = ctx
                .scanner
                .calculate_hashes(path)
                .map_err(|e| e.to_string())?;
            let rule_id = req
                .rule_id
                .unwrap_or_else(|| "HEURISTIC-ENTROPY".to_string());

            ctx.quarantine_mgr
                .quarantine_file(path, &sha256, &rule_id)
                .map_err(|e| e.to_string())?;
            log_message(&format!(
                "[+] Web API: Karantina manual berkas: {}",
                req.path
            ));

            // Perbarui progress in-memory
            if let Ok(mut progress) = progress_mutex().lock() {
                progress.results.retain(|r| r.file_path != req.path);
                progress.threats_found = progress.results.len();
            }

            // Perbarui state di disk
            let state_path = scanjob::state_path(&ctx.quarantine_mgr.quarantine_dir);
            if let Some(mut state) = scanjob::load_scan_state(&state_path) {
                state.results.retain(|r| r.file_path != req.path);
                state.threats_found = state.results.len();
                scanjob::save_scan_state(&state_path, &state);
            }

            Ok(Response::from_string("{\"success\": true}")
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Post, "/api/scan/action/whitelist") => {
            let mut content = String::new();
            request
                .as_reader()
                .read_to_string(&mut content)
                .map_err(|e| e.to_string())?;

            #[derive(Deserialize)]
            struct WhitelistRequest {
                path: String,
            }

            let req: WhitelistRequest =
                serde_json::from_str(&content).map_err(|e| e.to_string())?;

            crate::utils::add_to_whitelist(&req.path).map_err(|e| e.to_string())?;
            log_message(&format!(
                "[+] Web API: Whitelist manual berkas: {}",
                req.path
            ));

            // Perbarui progress in-memory
            if let Ok(mut progress) = progress_mutex().lock() {
                progress.results.retain(|r| r.file_path != req.path);
                progress.threats_found = progress.results.len();
            }

            // Perbarui state di disk
            let state_path = scanjob::state_path(&ctx.quarantine_mgr.quarantine_dir);
            if let Some(mut state) = scanjob::load_scan_state(&state_path) {
                state.results.retain(|r| r.file_path != req.path);
                state.threats_found = state.results.len();
                scanjob::save_scan_state(&state_path, &state);
            }

            Ok(Response::from_string("{\"success\": true}")
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Post, "/api/scan/action/delete") => {
            let mut content = String::new();
            request
                .as_reader()
                .read_to_string(&mut content)
                .map_err(|e| e.to_string())?;

            #[derive(Deserialize)]
            struct DeleteRequest {
                path: String,
            }

            let req: DeleteRequest = serde_json::from_str(&content).map_err(|e| e.to_string())?;
            let path = Path::new(&req.path);

            if !path.exists() {
                return Ok(
                    Response::from_string("{\"error\": \"Berkas tidak ditemukan\"}")
                        .with_status_code(StatusCode(400))
                        .with_header(json_header),
                );
            }

            fs::remove_file(path).map_err(|e| e.to_string())?;
            log_message(&format!("[+] Web API: Hapus manual berkas: {}", req.path));

            // Perbarui progress in-memory
            if let Ok(mut progress) = progress_mutex().lock() {
                progress.results.retain(|r| r.file_path != req.path);
                progress.threats_found = progress.results.len();
            }

            // Perbarui state di disk
            let state_path = scanjob::state_path(&ctx.quarantine_mgr.quarantine_dir);
            if let Some(mut state) = scanjob::load_scan_state(&state_path) {
                state.results.retain(|r| r.file_path != req.path);
                state.threats_found = state.results.len();
                scanjob::save_scan_state(&state_path, &state);
            }

            Ok(Response::from_string("{\"success\": true}")
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Post, "/api/scan/pause") => {
            let mut progress = progress_mutex().lock().map_err(|e| e.to_string())?;

            if progress.status != "scanning" && progress.status != "counting" {
                return Ok(
                    Response::from_string("{\"error\": \"Scan tidak sedang berjalan\"}")
                        .with_status_code(StatusCode(400))
                        .with_header(json_header),
                );
            }

            progress.status = "paused".to_string();
            SCAN_STATUS.store(3, Ordering::SeqCst); // 3: Paused

            // Instruct the CLI scan process to pause
            let quarantine_dir = ctx.quarantine_mgr.quarantine_dir.clone();
            scanjob::write_control(&scanjob::control_path(&quarantine_dir), "pause");

            // Save state to disk
            let state_path = scanjob::state_path(&quarantine_dir);
            if let Some(mut state) = scanjob::load_scan_state(&state_path) {
                state.status = "paused".to_string();
                scanjob::save_scan_state(&state_path, &state);
            }

            Ok(Response::from_string("{\"status\": \"paused\"}")
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Post, "/api/scan/resume") => {
            let mut progress = progress_mutex().lock().map_err(|e| e.to_string())?;

            if progress.status != "paused" {
                return Ok(Response::from_string(
                    "{\"error\": \"Scan tidak dalam keadaan dijeda\"}",
                )
                .with_status_code(StatusCode(400))
                .with_header(json_header));
            }

            progress.status = "scanning".to_string();
            SCAN_STATUS.store(2, Ordering::SeqCst); // 2: Scanning

            // Instruct the CLI scan process to resume
            let quarantine_dir = ctx.quarantine_mgr.quarantine_dir.clone();
            scanjob::write_control(&scanjob::control_path(&quarantine_dir), "resume");

            // Save state to disk
            let state_path = scanjob::state_path(&quarantine_dir);
            if let Some(mut state) = scanjob::load_scan_state(&state_path) {
                state.status = "scanning".to_string();
                scanjob::save_scan_state(&state_path, &state);
            }

            Ok(Response::from_string("{\"status\": \"scanning\"}")
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Post, "/api/scan/stop") => {
            let mut progress = progress_mutex().lock().map_err(|e| e.to_string())?;

            if progress.status != "scanning"
                && progress.status != "counting"
                && progress.status != "paused"
            {
                return Ok(
                    Response::from_string("{\"error\": \"Scan tidak sedang berjalan\"}")
                        .with_status_code(StatusCode(400))
                        .with_header(json_header),
                );
            }

            progress.status = "stopped".to_string();
            SCAN_STATUS.store(4, Ordering::SeqCst); // 4: Stopped
            SCAN_THREAD_ACTIVE.store(false, Ordering::SeqCst);

            // Instruct the CLI scan process to stop. It exits gracefully (saving
            // accurate progress so a later resume continues from the right file),
            // but force-kill it if it does not exit promptly.
            let quarantine_dir = ctx.quarantine_mgr.quarantine_dir.clone();
            scanjob::write_control(&scanjob::control_path(&quarantine_dir), "stop");

            // Save state to disk
            let state_path = scanjob::state_path(&quarantine_dir);
            if let Some(mut state) = scanjob::load_scan_state(&state_path) {
                state.status = "stopped".to_string();
                scanjob::save_scan_state(&state_path, &state);
            }

            let generation = SCAN_GENERATION.load(Ordering::SeqCst);
            thread::spawn(move || {
                thread::sleep(Duration::from_secs(3));
                if SCAN_GENERATION.load(Ordering::SeqCst) != generation {
                    return;
                }
                terminate_scan_child();
                let _ = fs::remove_file(scanjob::scan_pid_path(&quarantine_dir));
            });

            Ok(Response::from_string("{\"status\": \"stopped\"}")
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Post, "/api/scan/reset") => {
            terminate_scan_child();
            SCAN_THREAD_ACTIVE.store(false, Ordering::SeqCst);
            SCAN_STATUS.store(0, Ordering::SeqCst); // 0: Idle / Reset

            if let Ok(mut progress) = progress_mutex().lock() {
                *progress = ScanProgress::idle();
            }

            // Delete state/control files from disk
            let quarantine_dir = ctx.quarantine_mgr.quarantine_dir.clone();
            scanjob::clear_control(&scanjob::control_path(&quarantine_dir));
            let _ = fs::remove_file(scanjob::state_path(&quarantine_dir));
            let _ = fs::remove_file(scanjob::scan_pid_path(&quarantine_dir));

            Ok(Response::from_string("{\"status\": \"idle\"}")
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        (&Method::Get, "/api/scan/progress") => {
            let body = {
                let progress = progress_mutex().lock().map_err(|e| e.to_string())?;
                serde_json::to_string(&*progress).map_err(|e| e.to_string())?
            };
            Ok(Response::from_string(body)
                .with_status_code(StatusCode(200))
                .with_header(json_header))
        }
        _ => {
            // Check query params endpoints like /api/quarantine/restore?id=xxx
            if url.starts_with("/api/quarantine/restore") && method == &Method::Post {
                let id =
                    get_query_param(url, "id").ok_or_else(|| "Missing id parameter".to_string())?;
                ctx.quarantine_mgr
                    .restore_file(&id)
                    .map_err(|e| e.to_string())?;
                log_message(&format!(
                    "[+] Web API: Memulihkan file karantina ID: {}",
                    id
                ));
                return Ok(Response::from_string("{\"success\": true}")
                    .with_status_code(StatusCode(200))
                    .with_header(json_header));
            }

            if url.starts_with("/api/quarantine/delete") && method == &Method::Post {
                let id =
                    get_query_param(url, "id").ok_or_else(|| "Missing id parameter".to_string())?;
                let q_file = ctx
                    .quarantine_mgr
                    .quarantine_dir
                    .join(format!("{}.quarantined", id));
                let m_file = ctx
                    .quarantine_mgr
                    .quarantine_dir
                    .join(format!("{}.metadata", id));
                if q_file.exists() && m_file.exists() {
                    let _ = fs::remove_file(q_file);
                    let _ = fs::remove_file(m_file);
                    log_message(&format!(
                        "[+] Web API: Menghapus permanen file karantina ID: {}",
                        id
                    ));
                    return Ok(Response::from_string("{\"success\": true}")
                        .with_status_code(StatusCode(200))
                        .with_header(json_header));
                } else {
                    return Ok(Response::from_string(
                        "{\"error\": \"ID karantina tidak ditemukan\"}",
                    )
                    .with_status_code(StatusCode(404))
                    .with_header(json_header));
                }
            }

            if url.starts_with("/api/network/block") && method == &Method::Post {
                let ip =
                    get_query_param(url, "ip").ok_or_else(|| "Missing ip parameter".to_string())?;
                if let Err(e) = crate::network::block_ip(&ip) {
                    return Ok(Response::from_string(format!("{{\"error\": \"{}\"}}", e))
                        .with_status_code(StatusCode(500))
                        .with_header(json_header));
                }
                log_message(&format!("[+] Web API: Memblokir IP: {}", ip));
                return Ok(Response::from_string("{\"success\": true}")
                    .with_status_code(StatusCode(200))
                    .with_header(json_header));
            }

            if url.starts_with("/api/network/unblock") && method == &Method::Post {
                let ip =
                    get_query_param(url, "ip").ok_or_else(|| "Missing ip parameter".to_string())?;
                if let Err(e) = crate::network::unblock_ip(&ip) {
                    return Ok(Response::from_string(format!("{{\"error\": \"{}\"}}", e))
                        .with_status_code(StatusCode(500))
                        .with_header(json_header));
                }
                log_message(&format!("[+] Web API: Membuka blokir IP: {}", ip));
                return Ok(Response::from_string("{\"success\": true}")
                    .with_status_code(StatusCode(200))
                    .with_header(json_header));
            }

            if url.starts_with("/api/shutdown") && method == &Method::Post {
                log_message("[!] Web API: Menerima permintaan shutdown. Mematikan FerroShield...");
                thread::spawn(|| {
                    thread::sleep(std::time::Duration::from_millis(500));
                    std::process::exit(0);
                });
                return Ok(Response::from_string(
                    "{\"success\": true, \"message\": \"FerroShield shutting down...\"}",
                )
                .with_status_code(StatusCode(200))
                .with_header(json_header));
            }

            Ok(Response::from_string("{\"error\": \"Not Found\"}")
                .with_status_code(StatusCode(404))
                .with_header(json_header))
        }
    }
}

/// Simple helper to parse a query param from url string (e.g. ?id=xyz)
fn get_query_param(url: &str, param_name: &str) -> Option<String> {
    let parts: Vec<&str> = url.split('?').collect();
    if parts.len() < 2 {
        return None;
    }
    let query_string = parts[1];
    for pair in query_string.split('&') {
        let kv: Vec<&str> = pair.split('=').collect();
        if kv.len() == 2 && kv[0] == param_name {
            return Some(kv[1].to_string());
        }
    }
    None
}

/// Returns the `Host` header value without the port, lowercased.
fn request_host(request: &tiny_http::Request) -> Option<String> {
    request
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("host"))
        .map(|h| {
            h.value
                .as_str()
                .split(':')
                .next()
                .unwrap_or("")
                .trim()
                .to_lowercase()
        })
}

/// True when the hostname is an allowed localhost alias. IPv6 `[::1]` accepted too.
fn host_allowed(host: &str) -> bool {
    host == "127.0.0.1" || host == "localhost" || host == "[::1]"
}

/// True when the request Host header is 127.0.0.1 or localhost.
fn is_allowed_host(request: &tiny_http::Request) -> bool {
    match request_host(request) {
        Some(host) => host_allowed(&host),
        None => false,
    }
}

/// True when the origin header is empty/absent or points back at localhost.
fn origin_allowed(origin: &str) -> bool {
    let value = origin.trim().to_lowercase();
    value.starts_with("http://127.0.0.1")
        || value.starts_with("http://localhost")
        || value == "null"
        || value.is_empty()
}

/// True when the fetch-site header is absent or not cross-site.
fn fetch_site_allowed(fetch_site: &str) -> bool {
    !fetch_site.trim().eq_ignore_ascii_case("cross-site")
}

/// True when the request comes from the same site (no foreign Origin / not cross-site).
fn is_same_site(request: &tiny_http::Request) -> bool {
    let origin_ok = match request
        .headers()
        .iter()
        .find(|h| h.field.as_str().as_str().eq_ignore_ascii_case("origin"))
    {
        Some(origin) => origin_allowed(origin.value.as_str()),
        None => true,
    };
    let fetch_site_ok = match request.headers().iter().find(|h| {
        h.field
            .as_str()
            .as_str()
            .eq_ignore_ascii_case("sec-fetch-site")
    }) {
        Some(fetch_site) => fetch_site_allowed(fetch_site.value.as_str()),
        None => true,
    };
    origin_ok && fetch_site_ok
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::os::unix::fs::PermissionsExt;

    const TEST_TOKEN: &str = "abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234abcd1234";

    fn raw_http_status(addr: &str, raw: &str) -> u16 {
        let mut stream = TcpStream::connect(addr).expect("connect to test server");
        stream.write_all(raw.as_bytes()).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).unwrap();
        let head = String::from_utf8_lossy(&buf[..n]);
        head.lines()
            .next()
            .unwrap_or("")
            .split_whitespace()
            .nth(1)
            .unwrap_or("0")
            .parse()
            .unwrap_or(0)
    }

    #[test]
    fn test_api_requests_without_token_are_rejected() {
        // Simulates curl-style requests: no Origin and no Sec-Fetch-Site headers,
        // which previously sailed through the CSRF checks (None => allowed).
        let server = Server::http("127.0.0.1:0").expect("bind test server");
        let addr = server.server_addr().to_string();
        let handle = thread::spawn(move || {
            for _ in 0..4 {
                if let Ok(request) = server.recv() {
                    let method = request.method().clone();
                    let response = match enforce_request_guards(&request, &method, TEST_TOKEN) {
                        Some(rejected) => rejected,
                        None => json_response(200, "{\"ok\": true}"),
                    };
                    let _ = request.respond(response);
                }
            }
        });

        // 1. No token at all -> 401 (was 200 before the fix)
        let status = raw_http_status(
            &addr,
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status, 401, "tokenless /api request must be rejected");

        // 2. Wrong token -> 401
        let status = raw_http_status(
            &addr,
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer wrong\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status, 401, "wrong token must be rejected");

        // 3. Correct token, still no Origin/Sec-Fetch-Site -> allowed
        let with_token = format!(
            "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            TEST_TOKEN
        );
        assert_eq!(raw_http_status(&addr, &with_token), 200);

        // 4. Non-API paths (the dashboard page itself) remain accessible
        let status = raw_http_status(
            &addr,
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
        );
        assert_eq!(status, 200);

        handle.join().unwrap();
    }

    #[test]
    fn test_token_file_is_created_with_0600_perms() {
        let dir = std::env::temp_dir().join(format!(
            "ferroshield_token_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("dashboard.token");

        let token = load_or_create_dashboard_token_at(&path);
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "token file must be 0600");

        // Re-loading reuses the same token (stable across restarts).
        let reloaded = load_or_create_dashboard_token_at(&path);
        assert_eq!(reloaded, token);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_index_html_token_injection() {
        let html = "abc __FERROSHIELD_TOKEN__ def";
        assert_eq!(
            html.replace(TOKEN_PLACEHOLDER, TEST_TOKEN),
            format!("abc {} def", TEST_TOKEN)
        );
    }

    #[test]
    fn test_host_allowed() {
        assert!(host_allowed("127.0.0.1"));
        assert!(host_allowed("localhost"));
        assert!(host_allowed("[::1]"));
        assert!(!host_allowed("evil.com"));
        assert!(!host_allowed("127.0.0.2"));
        assert!(!host_allowed(""));
    }

    #[test]
    fn test_origin_allowed() {
        assert!(origin_allowed("http://127.0.0.1"));
        assert!(origin_allowed("http://127.0.0.1:8686"));
        assert!(origin_allowed("http://localhost:8686"));
        assert!(origin_allowed("null"));
        assert!(origin_allowed(""));
        assert!(!origin_allowed("https://evil.com"));
        assert!(!origin_allowed("http://evil.com"));
    }

    #[test]
    fn test_fetch_site_allowed() {
        assert!(fetch_site_allowed("same-origin"));
        assert!(fetch_site_allowed("none"));
        assert!(fetch_site_allowed(""));
        assert!(!fetch_site_allowed("cross-site"));
        assert!(!fetch_site_allowed("Cross-Site"));
    }

    #[test]
    fn test_get_query_param() {
        assert_eq!(
            get_query_param("/api/x?id=abc", "id").as_deref(),
            Some("abc")
        );
        assert_eq!(get_query_param("/api/x", "id"), None);
        assert_eq!(
            get_query_param("/api/x?a=1&id=zz", "id").as_deref(),
            Some("zz")
        );
        assert_eq!(get_query_param("/api/x?id=abc&a=1", "nope"), None);
    }
}
