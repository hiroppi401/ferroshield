#!/bin/sh
# FerroShield - distro-agnostic installer / uninstaller
# Usage:
#   sudo ./install.sh            build, install, generate keys, start service
#   sudo ./install.sh --uninstall   stop service and remove all FerroShield files

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

write_config() {
    if [ -f "$CONF_DIR/config.json" ]; then
        ok "config.json sudah ada, melewati pembuatan."
        return 0
    fi
    printf '{\n  "default_action": "quarantine",\n  "downloads_dir": null,\n  "miner_detection_require_secondary_signal": true,\n  "process_containment": "auto"\n}\n' > "$CONF_DIR/config.json"
    chmod 0600 "$CONF_DIR/config.json"
    ok "config.json dibuat (default_action=quarantine, miner secondary signal aktif, process_containment=auto)."
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
    ok "FerroShield berhasil dihapus."
}

# --- Main ------------------------------------------------------------------
case "${1:-install}" in
    install)
        check_root
        msg "Memulai instalasi FerroShield..."
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
    --uninstall|-u|uninstall)
        uninstall
        ;;
    *)
        echo "Penggunaan: $0 {install|--uninstall}"
        exit 1
        ;;
esac
