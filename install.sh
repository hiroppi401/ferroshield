#!/bin/sh
# FerroShield - distro-agnostic installer / uninstaller
# Usage:
#   sudo ./install.sh                                       build, install, generate keys, start service
#   sudo ./install.sh --api-token <TOKEN>                   install with AlienVault OTX API key
#   sudo ./install.sh --otx-api-key <K> --threatfox-auth-key <K> install with specific API keys
#   sudo ./install.sh --uninstall                           stop service and remove all FerroShield files
#   ./install.sh --help                                     show help message

set -e

BIN_DIR=/usr/local/bin
LIB_DIR=/usr/lib/ferroshield
CONF_DIR=/etc/ferroshield
VAR_DIR=/var/lib/ferroshield
QUARANTINE_DIR="$VAR_DIR/quarantine"
SERVICE_NAME=ferroshield
BINARY="$BIN_DIR/ferroshield"

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

# Build mode: "source" compiles from Cargo.toml/src; "binary" installs prebuilt
# artifacts shipped alongside install.sh (no source code, no toolchain needed).
if [ -f "$PROJECT_DIR/Cargo.toml" ] && [ -d "$PROJECT_DIR/src" ]; then
    BUILD_MODE=source
else
    BUILD_MODE=binary
fi

msg()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[-]\033[0m %s\n' "$*"; }

have() { command -v "$1" >/dev/null 2>&1; }

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        err "Installer harus dijalankan sebagai root/sudo."
        exit 1
    fi
}

# --- Build -----------------------------------------------------------------
build_binary() {
    if [ "$BUILD_MODE" = "binary" ]; then
        if [ -f "$PROJECT_DIR/ferroshield" ]; then
            ok "Mode binary: biner prebuilt ditemukan, melewati kompilasi."
            return 0
        fi
        err "Mode binary: biner prebuilt tidak ditemukan di $PROJECT_DIR/ferroshield."
        exit 1
    fi
    if ! have cargo; then
        err "Rust toolchain (cargo) tidak ditemukan. Install dari https://rustup.rs lalu jalankan ulang."
        exit 1
    fi
    msg "Mengompilasi biner release (cargo build --release)..."
    (cd "$PROJECT_DIR" && cargo build --release)
}

# --- eBPF (optional) -------------------------------------------------------
bpf_arch() {
    case "$(uname -m)" in
        x86_64) echo x86 ;;
        aarch64) echo arm64 ;;
        armv7l|armv6l|arm) echo arm ;;
        riscv64) echo riscv64 ;;
        s390x) echo s390x ;;
        *) echo unsupported ;;
    esac
}

bpf_include_flags() {
    local flags=""
    if have pkg-config && pkg-config --exists libbpf 2>/dev/null; then
        flags=$(pkg-config --cflags libbpf 2>/dev/null || true)
    fi
    for d in /usr/include /usr/include/x86_64-linux-gnu /usr/include/aarch64-linux-gnu; do
        if [ -f "$d/bpf/bpf_helpers.h" ]; then
            case "$flags" in
                *"$d"*) ;;
                *) flags="$flags -I$d" ;;
            esac
        fi
    done
    echo "$flags"
}

compile_ebpf() {
    if [ -f "$LIB_DIR/ferroshield_ebpf.o" ]; then
        ok "Modul eBPF sudah terpasang, melewati kompilasi."
        return 0
    fi

    if [ "$BUILD_MODE" = "binary" ]; then
        for cand in "$PROJECT_DIR/ferroshield_ebpf.o" "$PROJECT_DIR/src/ebpf/ferroshield_ebpf.o"; do
            if [ -f "$cand" ]; then
                mkdir -p "$LIB_DIR"
                cp "$cand" "$LIB_DIR/ferroshield_ebpf.o"
                chmod 0644 "$LIB_DIR/ferroshield_ebpf.o"
                ok "Modul eBPF dipasang dari paket binary."
                return 0
            fi
        done
        warn "Modul eBPF tidak disertakan dalam paket (daemon memakai fallback procfs)."
        return 0
    fi

    if ! have clang || ! have llvm-strip; then
        warn "clang/llvm-strip tidak ditemukan. Melewati modul eBPF (daemon memakai fallback procfs)."
        return 0
    fi

    arch=$(bpf_arch)
    if [ "$arch" = "unsupported" ]; then
        warn "Arsitektur $(uname -m) tidak didukung untuk eBPF. Melewati (fallback procfs)."
        return 0
    fi

    include_flags=$(bpf_include_flags)
    if [ -z "$include_flags" ]; then
        warn "Header libbpf (bpf/bpf_helpers.h) tidak ditemukan. Melewati modul eBPF (fallback procfs)."
        warn "Install paket libbpf-dev/libbpf-devel untuk mengaktifkan dukungan kernel."
        return 0
    fi

    printf 'Pasang dukungan eBPF (pemantauan jaringan level kernel)? [y/N] '
    read -r answer
    case "$answer" in
        y|Y|yes|Yes) ;;
        *)
            warn "Melewati modul eBPF (fallback procfs)."
            return 0
            ;;
    esac

    msg "Mengompilasi modul eBPF untuk arsitektur $arch..."
    mkdir -p "$LIB_DIR"
    if clang -g -O2 -target bpf -D__TARGET_ARCH_$arch \
        -c "$PROJECT_DIR/src/ebpf/ferroshield_ebpf.c" \
        -o "$LIB_DIR/ferroshield_ebpf.o" $include_flags \
        && llvm-strip -g "$LIB_DIR/ferroshield_ebpf.o"; then
        ok "Modul eBPF berhasil dikompilasi ke $LIB_DIR/ferroshield_ebpf.o"
        chmod 0644 "$LIB_DIR/ferroshield_ebpf.o"
    else
        warn "Kompilasi eBPF gagal. Melewati (fallback procfs)."
        rm -f "$LIB_DIR/ferroshield_ebpf.o"
    fi
}

# --- Keypair & rules -------------------------------------------------------
generate_keys() {
    if [ -f "$CONF_DIR/rules.key" ] && [ -f "$CONF_DIR/rules.pub" ]; then
        ok "Keypair Ed25519 sudah ada, melewati pembuatan."
        return 0
    fi
    msg "Membuat keypair Ed25519 baru..."
    if ! "$BINARY" gen-keys "$CONF_DIR"; then
        err "Gagal membuat keypair."
        exit 1
    fi
    ok "Keypair dibuat: rules.key (privat) + rules.pub (publik)"
}

install_rules() {
    mkdir -p "$CONF_DIR"
    if [ -f "$CONF_DIR/rules.json" ]; then
        ok "rules.json sudah ada, melewati instalasi."
    else
        if [ -f "$PROJECT_DIR/rules.json" ]; then
            cp "$PROJECT_DIR/rules.json" "$CONF_DIR/rules.json"
        else
            warn "rules.json tidak ditemukan di proyek. Buat rules.json terlebih dahulu."
        fi
    fi
    [ -f "$CONF_DIR/whitelist.json" ] || printf '[]\n' > "$CONF_DIR/whitelist.json"

    if [ -f "$PROJECT_DIR/rules.yar" ] && [ ! -f "$CONF_DIR/rules.yar" ]; then
        cp "$PROJECT_DIR/rules.yar" "$CONF_DIR/rules.yar"
        ok "rules.yar (YARA ruleset) dipasang."
    fi

    msg "Menandatangani rules.json dengan kunci baru..."
    if (cd "$CONF_DIR" && "$BINARY" sign-rules); then
        ok "rules.json ditandatangani."
    else
        err "Gagal menandatangani rules.json. Pastikan rules.key ada."
        exit 1
    fi
}

escape_json() {
    printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

write_config() {
    mkdir -p "$CONF_DIR"
    local cfg_file="$CONF_DIR/config.json"
    local otx_val="${OTX_API_KEY:-}"
    local tf_val="${THREATFOX_AUTH_KEY:-}"
    local otx_esc
    local tf_esc
    otx_esc=$(escape_json "$otx_val")
    tf_esc=$(escape_json "$tf_val")

    if [ -f "$cfg_file" ]; then
        if [ -n "$otx_val" ] || [ -n "$tf_val" ]; then
            msg "Memperbarui API token pada $cfg_file..."
            cat > "$cfg_file" <<EOF
{
  "default_action": "quarantine",
  "downloads_dir": null,
  "miner_detection_require_secondary_signal": true,
  "process_containment": "auto",
  "otx_api_key": "$otx_esc",
  "threatfox_auth_key": "$tf_esc"
}
EOF
            chmod 0600 "$cfg_file"
            ok "config.json diperbarui dengan API token baru."
        else
            ok "config.json sudah ada, melewati pembuatan."
        fi
        return 0
    fi

    cat > "$cfg_file" <<EOF
{
  "default_action": "quarantine",
  "downloads_dir": null,
  "miner_detection_require_secondary_signal": true,
  "process_containment": "auto",
  "otx_api_key": "$otx_esc",
  "threatfox_auth_key": "$tf_esc"
}
EOF
    chmod 0600 "$cfg_file"
    ok "config.json dibuat (default_action=quarantine, process_containment=auto, token dikonfigurasi)."
}

# --- Service installation --------------------------------------------------
install_init_service() {
    if [ -d /run/systemd/system ] || [ -f /run/systemd/system ]; then
        install_systemd
    elif have openrc || have rc-update; then
        install_openrc
    else
        install_sysvinit
    fi
}

install_systemd() {
    msg "Menginstal unit systemd..."
    cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=FerroShield Malware Scanner & Browser Guard Daemon
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=30s
StartLimitBurst=5

[Service]
Type=simple
WorkingDirectory=$CONF_DIR
TimeoutStartSec=90s
ExecStartPre=$BINARY block-hosts
ExecStart=$BINARY monitor
User=root
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal
SyslogIdentifier=ferroshield
MemoryMax=512M
CPUQuota=30%
TasksMax=50
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_KILL CAP_DAC_OVERRIDE CAP_BPF CAP_PERFMON CAP_SYS_ADMIN
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_KILL CAP_DAC_OVERRIDE CAP_BPF CAP_PERFMON CAP_SYS_ADMIN
NoNewPrivileges=true
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=/etc/hosts $CONF_DIR $VAR_DIR
PrivateTmp=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
    chmod 0644 "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME" 2>/dev/null || true
    systemctl restart "$SERVICE_NAME"
    ok "Layanan systemd diaktifkan dan dijalankan."
}

install_openrc() {
    msg "Menginstal skrip init OpenRC..."
    mkdir -p /etc/init.d
    cat > "/etc/init.d/$SERVICE_NAME" <<EOF
#!/sbin/openrc-run
description="FerroShield Malware Scanner & Browser Guard Daemon"
command="$BINARY"
command_args="monitor"
command_background="yes"
pidfile="/run/$SERVICE_NAME.pid"
EOF
    chmod 0755 "/etc/init.d/$SERVICE_NAME"
    rc-update add "$SERVICE_NAME" default 2>/dev/null || true
    rc-service "$SERVICE_NAME" start 2>/dev/null || true
    ok "Layanan OpenRC diaktifkan dan dijalankan."
}

install_sysvinit() {
    msg "Menginstal skrip init sysvinit..."
    mkdir -p /etc/init.d
    cat > "/etc/init.d/$SERVICE_NAME" <<EOF
#!/bin/sh
### BEGIN INIT INFO
# Provides:          ferroshield
# Required-Start:    \$network \$remote_fs
# Required-Stop:     \$network \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Description:       FerroShield Malware Scanner & Browser Guard Daemon
### END INIT INFO

BINARY=$BINARY
CONF_DIR=$CONF_DIR
PIDFILE=/run/ferroshield.pid

case "\$1" in
    start)
        echo "Starting FerroShield..."
        cd "\$CONF_DIR" || exit 1
        \$BINARY block-hosts
        start-stop-daemon --start --background --make-pidfile \
            --pidfile "\$PIDFILE" --exec "\$BINARY" -- monitor
        ;;
    stop)
        echo "Stopping FerroShield..."
        start-stop-daemon --stop --pidfile "\$PIDFILE" 2>/dev/null || true
        rm -f "\$PIDFILE"
        ;;
    restart)
        "\$0" stop
        sleep 1
        "\$0" start
        ;;
    status)
        if [ -f "\$PIDFILE" ] && kill -0 "\$(cat "\$PIDFILE")" 2>/dev/null; then
            echo "FerroShield is running."
        else
            echo "FerroShield is not running."
            exit 3
        fi
        ;;
    *)
        echo "Usage: \$0 {start|stop|restart|status}"
        exit 1
        ;;
esac
exit 0
EOF
    chmod 0755 "/etc/init.d/$SERVICE_NAME"
    if have update-rc.d; then
        update-rc.d "$SERVICE_NAME" defaults 2>/dev/null || true
    elif have rc-update; then
        rc-update add "$SERVICE_NAME" default 2>/dev/null || true
    fi
    "/etc/init.d/$SERVICE_NAME" start 2>/dev/null || true
    ok "Layanan sysvinit diinstal dan dijalankan."
}

# --- Uninstall -------------------------------------------------------------
stop_service() {
    if [ -d /run/systemd/system ] || [ -f /run/systemd/system ]; then
        systemctl stop "$SERVICE_NAME" 2>/dev/null || true
        systemctl disable "$SERVICE_NAME" 2>/dev/null || true
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload 2>/dev/null || true
    elif [ -f "/etc/init.d/$SERVICE_NAME" ]; then
        if have rc-service; then
            rc-service "$SERVICE_NAME" stop 2>/dev/null || true
            rc-update del "$SERVICE_NAME" 2>/dev/null || true
        else
            "/etc/init.d/$SERVICE_NAME" stop 2>/dev/null || true
        fi
        rm -f "/etc/init.d/$SERVICE_NAME"
    fi
}

purge_firewall_rules() {
    msg "Membersihkan aturan firewall FerroShield..."
    if have nft; then
        nft -a list chain ip filter OUTPUT 2>/dev/null | while IFS= read -r line; do
            case "$line" in
                *"ip daddr"*" drop"*)
                    handle=$(printf '%s' "$line" | sed -n 's/.*# handle \([0-9][0-9]*\).*/\1/p')
                    [ -n "$handle" ] && nft delete rule ip filter OUTPUT handle "$handle" 2>/dev/null || true
                    ;;
            esac
        done
    fi
    if have iptables; then
        iptables -S OUTPUT 2>/dev/null | while IFS= read -r rule; do
            case "$rule" in
                "-A OUTPUT -d"*" -j DROP")
                    ip=$(printf '%s' "$rule" | awk '{print $4}' | sed 's#/32##')
                    [ -n "$ip" ] && iptables -D OUTPUT -d "$ip" -j DROP 2>/dev/null || true
                    ;;
            esac
        done
    fi
}

clean_hosts() {
    msg "Membersihkan blocklist dari /etc/hosts..."
    "$BINARY" clean-hosts 2>/dev/null || true
}

uninstall() {
    check_root
    stop_service
    clean_hosts
    purge_firewall_rules
    rm -rf "$LIB_DIR" "$CONF_DIR" "$VAR_DIR"
    rm -f "$BINARY"
    rm -rf /sys/fs/cgroup/ferroshield
    ok "FerroShield berhasil dihapus."
}

show_help() {
    cat <<EOF
FerroShield - Skrip Instalasi & Konfigurasi Distro-Agnostik

Penggunaan:
  sudo ./install.sh [OPSI...]

Opsi:
  install                       Instalasi FerroShield (default)
  --api-token <TOKEN>           API token umum / AlienVault OTX API key
  --otx-api-key <KEY>           API key untuk AlienVault OTX (otx.alienvault.com)
  --threatfox-auth-key <KEY>    Auth-Key untuk ThreatFox API (threatfox.abuse.ch)
  --uninstall, -u               Hapus seluruh instalasi dan layanan FerroShield
  --help, -h                    Tampilkan panduan ini

Variabel Lingkungan:
  API_TOKEN                     API token umum
  OTX_API_KEY                   AlienVault OTX API key
  THREATFOX_AUTH_KEY            ThreatFox Auth-Key

Contoh:
  sudo ./install.sh --api-token "otx_secret_key_123"
  sudo ./install.sh --otx-api-key "xyz" --threatfox-auth-key "abc"
  sudo ./install.sh --uninstall
EOF
}

# --- Main ------------------------------------------------------------------
ACTION=install
API_TOKEN="${API_TOKEN:-}"
OTX_API_KEY="${OTX_API_KEY:-}"
THREATFOX_AUTH_KEY="${THREATFOX_AUTH_KEY:-${THREATFOX_API_KEY:-}}"

while [ $# -gt 0 ]; do
    case "$1" in
        install)
            ACTION=install
            ;;
        --uninstall|-u|uninstall)
            ACTION=uninstall
            ;;
        --help|-h|help)
            ACTION=help
            ;;
        --api-token)
            shift
            [ $# -gt 0 ] || { err "Opsi --api-token membutuhkan nilai."; exit 1; }
            API_TOKEN="$1"
            ;;
        --api-token=*)
            API_TOKEN="${1#*=}"
            ;;
        --otx-api-key|--otx-key)
            shift
            [ $# -gt 0 ] || { err "Opsi $1 membutuhkan nilai."; exit 1; }
            OTX_API_KEY="$1"
            ;;
        --otx-api-key=*|--otx-key=*)
            OTX_API_KEY="${1#*=}"
            ;;
        --threatfox-auth-key|--threatfox-key)
            shift
            [ $# -gt 0 ] || { err "Opsi $1 membutuhkan nilai."; exit 1; }
            THREATFOX_AUTH_KEY="$1"
            ;;
        --threatfox-auth-key=*|--threatfox-key=*)
            THREATFOX_AUTH_KEY="${1#*=}"
            ;;
        *)
            err "Argumen tidak dikenal: $1 (Gunakan $0 --help untuk melihat panduan)"
            exit 1
            ;;
    esac
    shift
done

# If generic API_TOKEN is given but specific OTX key is empty, set OTX key
if [ -n "$API_TOKEN" ] && [ -z "$OTX_API_KEY" ]; then
    OTX_API_KEY="$API_TOKEN"
fi

case "$ACTION" in
    help)
        show_help
        exit 0
        ;;
    uninstall)
        uninstall
        ;;
    install)
        check_root
        msg "Memulai instalasi FerroShield..."
        if [ -n "$OTX_API_KEY" ]; then
            ok "AlienVault OTX API key dikonfigurasi."
        fi
        if [ -n "$THREATFOX_AUTH_KEY" ]; then
            ok "ThreatFox Auth-Key dikonfigurasi."
        fi
        if [ -f "$BINARY" ] || [ -d "$LIB_DIR" ] || [ -d "$CONF_DIR" ]; then
            warn "Instalasi FerroShield yang sudah ada terdeteksi, membersihkan terlebih dahulu..."
            stop_service
            clean_hosts
            purge_firewall_rules
            rm -rf "$LIB_DIR" "$CONF_DIR" "$VAR_DIR"
            rm -rf /sys/fs/cgroup/ferroshield
            ok "Instalasi lama dibersihkan."
        fi
        build_binary

        mkdir -p "$BIN_DIR" "$LIB_DIR" "$CONF_DIR" "$QUARANTINE_DIR"
        chmod 0700 "$QUARANTINE_DIR" 2>/dev/null || true
        chmod 0700 "$CONF_DIR" 2>/dev/null || true

        msg "Memasang biner ke $BINARY..."
        if [ "$BUILD_MODE" = "binary" ]; then
            SRC_BIN="$PROJECT_DIR/ferroshield"
        else
            SRC_BIN="$PROJECT_DIR/target/release/ferroshield"
        fi
        cp "$SRC_BIN" "$BINARY"
        chmod 0755 "$BINARY"

        compile_ebpf

        msg "Menyiapkan direktori data..."
        mkdir -p "$VAR_DIR"
        chmod 0700 "$VAR_DIR" 2>/dev/null || true

        generate_keys
        install_rules
        write_config

        install_init_service

        ok "Instalasi selesai!"
        msg "Dashboard: http://127.0.0.1:8686"
        if have xdg-open; then
            xdg-open "http://127.0.0.1:8686" >/dev/null 2>&1 || true
        fi
        ;;
esac
