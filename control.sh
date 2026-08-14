#!/bin/sh
# FerroShield - helper script (POSIX sh) untuk daemon background & Web UI

BINARY=/usr/local/bin/ferroshield
CONF_DIR=/etc/ferroshield
LOG_FILE=/var/log/ferroshield.log
PID_FILE=/var/run/ferroshield.pid
DASHBOARD_URL=http://127.0.0.1:8686

# Dev fallback: jika belum diinstall, gunakan biner lokal
if [ ! -x "$BINARY" ]; then
    BINARY=./target/release/ferroshield
    CONF_DIR=.
    LOG_FILE=ferroshield.log
    PID_FILE=ferroshield.pid
fi

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[!] Harap jalankan script ini menggunakan sudo."
        exit 1
    fi
}

build_if_needed() {
    if [ ! -f "$BINARY" ]; then
        echo "[*] Biner tidak ditemukan. Mengompilasi FerroShield..."
        cargo build --release
    fi
}

start() {
    check_root
    build_if_needed

    # Periksa apakah sudah berjalan
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "[*] FerroShield sudah berjalan dengan PID: $PID."
            return
        fi
    fi

    echo "[*] Memperbarui blacklist domain di /etc/hosts..."
    (cd "$CONF_DIR" && "$BINARY" block-hosts)

    echo "[*] Menjalankan FerroShield Monitor di background..."
    (cd "$CONF_DIR" && nohup "$BINARY" monitor > "$LOG_FILE" 2>&1 &
     echo $! > "$PID_FILE")

    echo "[+] FerroShield berhasil dijalankan (PID: $(cat "$PID_FILE"))."
    echo "[+] Log dapat dilihat di: tail -f $LOG_FILE"
    echo "[+] Web Dashboard dapat diakses di: $DASHBOARD_URL"
    if command -v xdg-open >/dev/null 2>&1; then
        xdg-open "$DASHBOARD_URL" >/dev/null 2>&1 || true
    fi
}

stop() {
    check_root
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "[*] Menghentikan FerroShield (PID: $PID)..."
            kill "$PID"
            sleep 1
            if kill -0 "$PID" 2>/dev/null; then
                kill -9 "$PID"
            fi
            echo "[+] FerroShield dihentikan."
        else
            echo "[-] Berkas PID ditemukan tetapi proses tidak aktif."
        fi
        rm -f "$PID_FILE"
    else
        if pgrep -x ferroshield >/dev/null 2>&1; then
            echo "[*] Menghentikan semua proses FerroShield..."
            pkill -x ferroshield
            echo "[+] FerroShield dihentikan."
        else
            echo "[-] FerroShield tidak sedang berjalan."
        fi
    fi
}

status() {
    if [ -f "$PID_FILE" ]; then
        PID=$(cat "$PID_FILE")
        if kill -0 "$PID" 2>/dev/null; then
            echo "[+] FerroShield SEDANG BERJALAN (PID: $PID)."
            echo "    Dashboard: $DASHBOARD_URL"
            return 0
        fi
    fi

    if pgrep -x ferroshield >/dev/null 2>&1; then
        echo "[+] FerroShield SEDANG BERJALAN (tanpa PID file)."
        return 0
    fi

    echo "[-] FerroShield TIDAK SEDANG BERJALAN."
    return 1
}

logs() {
    if [ -f "$LOG_FILE" ]; then
        tail -f "$LOG_FILE"
    else
        echo "[-] Log file belum dibuat. Jalankan FerroShield terlebih dahulu."
    fi
}

case "$1" in
    start) start ;;
    stop) stop ;;
    status) status ;;
    logs) logs ;;
    *)
        echo "Penggunaan: $0 {start|stop|status|logs}"
        exit 1
        ;;
esac
