# Manual Penggunaan FerroShield

FerroShield adalah aplikasi keamanan Linux modular berkinerja tinggi yang ditulis dalam bahasa Rust. Aplikasi ini dirancang untuk mendeteksi malware (static scanning), memantau folder unduhan browser secara real-time (Browser Guard), memblokir aktivitas Crypto Miner (Cryptomining Prevention), dan membatasi koneksi jaringan berbahaya (Network Mitigation) melalui Web UI Dashboard yang interaktif serta perintah CLI.

---

## 1. Persyaratan Sistem & Instalasi

### Persyaratan
*   **Sistem Operasi**: Linux (spesifik untuk distribusi berbasis Debian/Ubuntu, Arch, Fedora, dsb.).
*   **Dependensi Eksternal**: `iptables` (untuk pemblokiran IP otomatis) dan akses `root/sudo` (untuk membaca `/proc/net/tcp` dan memodifikasi `/etc/hosts` / iptables).
*   **Compiler** (jika ingin kompilasi mandiri): `rustc` dan `cargo` (Rust versi 1.75+).

### Kompilasi Rilis Cepat (Optimasi Performa)
Untuk menghasilkan biner yang sangat kecil dan berjalan dengan memori minimal (< 10MB RAM):
```bash
cargo build --release
```
Biner eksekusi akan tersedia di `./target/release/ferroshield`.

### Kompilasi & Pemasangan Modul Kernel eBPF (Opsional)
Untuk mengaktifkan pemantauan jaringan real-time tingkat kernel menggunakan eBPF (agar lebih efisien dibanding polling procfs):
1. Kompilasi kode eBPF ke file objek ELF menggunakan Clang:
   ```bash
   clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -c src/ebpf/ferroshield_ebpf.c -o src/ebpf/ferroshield_ebpf.o
   llvm-strip -g src/ebpf/ferroshield_ebpf.o
   ```
2. Buat folder library sistem dan pasang modul kernel tersebut:
   ```bash
   sudo mkdir -p /usr/lib/ferroshield
   sudo cp src/ebpf/ferroshield_ebpf.o /usr/lib/ferroshield/ferroshield_ebpf.o
   ```

---

## 2. Struktur Basis Aturan (rules.json)

Semua tanda tangan malware, daftar hitam IP, domain pool pertambangan, dan pengaturan tindakan default didefinisikan dalam file [rules.json](file:///media/D/projek/pribadi/ferroshield/rules.json).

```json
{
  "settings": {
    "default_action": "quarantine" 
  },
  "rules": [
    {
      "id": "RULE-001",
      "name": "Nama Aturan",
      "description": "Deskripsi ancaman...",
      "severity": "High",
      "signatures": {
        "hashes": {
          "sha256": "hash_sha256_malware",
          "md5": "hash_md5_malware"
        },
        "patterns": [
          "regex_pattern_isi_file"
        ]
      }
    }
  ],
  "network_blacklist": {
    "ips": ["185.112.146.12"],
    "domains": ["malicious-domain.xyz"]
  }
}
```

### Opsi Tindakan Karantina (`default_action`)
1.  `"quarantine"`: Mengenkripsi file terinfeksi menggunakan **AES-256-GCM** (dengan verifikasi integritas **HMAC-SHA256**) dan memindahkannya ke folder karantina terisolasi.
2.  `"delete"`: Menghapus file berbahaya secara instan dari disk secara permanen.

### Konfigurasi Runtime (`config.json`)
Pengaturan runtime tidak ditandatangani dan dibaca dari `config.json` (atau `$FERROSHIELD_CONFIG` / `/etc/ferroshield/config.json`):

```json
{
  "default_action": "quarantine",
  "downloads_dir": "/home/user/Downloads",
  "miner_detection_require_secondary_signal": true,
  "process_containment": "auto",
  "otx_api_key": "your_otx_key",
  "threatfox_auth_key": "your_threatfox_key"
}
```

| Kunci | Nilai | Keterangan |
|---|---|---|
| `process_containment` | `auto` (default), `cgroup`, `sigstop`, `off` | Strategi **freeze-first anti-mutasi**: proses berbahaya dibekukan dulu (cgroup v2 freezer, fallback `SIGSTOP`) sebelum binary dinetralkan & dibunuh, sehingga malware tak bisa bermutasi/membuat file baru saat dibunuh. `off` = perilaku lama (langsung `kill -9`). |
| `otx_api_key` | `string` (opsional) | Kunci API AlienVault OTX untuk unduh indikator ancaman komunitas. |
| `threatfox_auth_key` | `string` (opsional) | Auth-Key ThreatFox (abuse.ch) untuk unduh IOC malware terkini. |

---

## 3. Panduan Penggunaan Command Line Interface (CLI)

### A. Pemindaian File & Direktori Manual
Memindai file atau folder tertentu menggunakan aturan static analysis:
```bash
./target/release/ferroshield scan /home/user/Downloads
```
*   **Hapus Instan**: Tambahkan opsi `--delete` untuk langsung menghapus berkas berbahaya yang terdeteksi tanpa masuk ke folder karantina:
    ```bash
    ./target/release/ferroshield scan /home/user/Downloads --delete
    ```

### B. Menjalankan Daemon Pemantauan Latar Belakang
Menjalankan program pemantauan real-time untuk jaringan, browser guard, ekstensi, dan crypto miner, sekaligus mengaktifkan Web UI Dashboard pada port `8686`:
```bash
sudo ./target/release/ferroshield monitor
```

> **Anti-mutasi (freeze-first):** setiap proses yang terdeteksi (IP blacklist, path temp mencurigakan, port mining, heuristik CPU, atau event eBPF) **dibekukan terlebih dahulu** bersama seluruh keturunannya (cgroup v2 freezer, fallback SIGSTOP), lalu binary-nya dikarantina/dihapus, IP diblokir, dan proses dibunuh. Karena proses beku tidak bisa mengeksekusi kode, malware **tidak dapat bermutasi/membuat file baru** saat dibunuh. Lihat `process_containment` di §2.

### C. Menjalankan Web UI Dashboard Saja
Menjalankan konsol web interaktif tanpa thread monitoring aktif di latar belakang:
```bash
./target/release/ferroshield web
```
*   **Kustomisasi Port**: Anda dapat menentukan port HTTP kustom dengan opsi `--port`:
    ```bash
    ./target/release/ferroshield web --port 8989
    ```

### D. Manajemen Folder Karantina
*   **Melihat Daftar File Karantina:**
    ```bash
    ./target/release/ferroshield quarantine list
    ```
*   **Memulihkan File Karantina (Restore):**
    ```bash
    ./target/release/ferroshield quarantine restore <quarantine_id>
    ```
*   **Menghapus File Karantina Secara Permanen:**
    ```bash
    ./target/release/ferroshield quarantine delete <quarantine_id>
    ```

### E. Manajemen Firewall & Domain Sinkholing
*   **Memblokir Domain Blacklist (di /etc/hosts):**
    ```bash
    sudo ./target/release/ferroshield block-hosts
    ```
*   **Membersihkan Blokir Domain:**
    ```bash
    sudo ./target/release/ferroshield clean-hosts
    ```

---

## 4. Cara Menjalankan sebagai Background Service (Systemd)

Untuk memastikan FerroShield memproteksi komputer Anda secara terus-menerus di latar belakang sejak komputer dinyalakan:

1.  **Salin Service Unit File:**
    ```bash
    sudo cp ferroshield.service /etc/systemd/system/
    ```
2.  **Reload Daemon Systemd:**
    ```bash
    sudo systemctl daemon-reload
    ```
3.  **Aktifkan dan Jalankan Layanan:**
    ```bash
    sudo systemctl enable --now ferroshield
    ```
4.  **Memeriksa Status & Log Layanan:**
    ```bash
    sudo systemctl status ferroshield
    ```

---

## 5. Penggunaan Web UI Dashboard

Setelah daemon monitor atau web mode berjalan, buka peramban web Anda dan akses:
👉 **`http://localhost:8686`**

Dashboard dilindungi **token akses** (berlaku untuk semua endpoint `/api/*`):
- Token dibuat otomatis saat daemon pertama kali berjalan dan disimpan di file **`dashboard.token`** (mode `0600`, hanya dapat dibaca oleh user daemon) di direktori kerja (`/etc/ferroshield/dashboard.token` pada instalasi systemd).
- Browser Anda memuat token langsung dari halaman dashboard, jadi **tidak perlu menyalin token secara manual** untuk pemakaian normal.
- Permintaan API tanpa token (mis. `curl` biasa) akan ditolak dengan HTTP `401`. Token harus dikirim sebagai header `Authorization: Bearer <token>`.
- Header `Host`, `Origin`, dan `Sec-Fetch-Site` tetap divalidasi sebagai lapisan tambahan (anti-CSRF/DNS-rebinding).

Di Web UI, Anda dapat melakukan operasi berikut secara visual:
1.  **Dashboard Overview**: Melihat status proteksi, jumlah aturan, total file karantina, dan **Real-time Audit Logs terminal** yang interaktif.
2.  **File Scanner Tab**: Melakukan pemindaian direktori secara interaktif dengan opsi penghapusan permanen.
3.  **Karantina Tab**: Mengelola berkas berbahaya yang terisolasi dengan tombol klik-cepat untuk **Pulihkan (Restore)** atau **Hapus Permanen**.
4.  **Web Guard & Whitelist Tab**: Melihat daftar domain terblokir dan menambahkan domain/IP/path ke whitelist untuk mitigasi false positive.
5.  **Pengaturan Tab**: Mengonfigurasi AlienVault OTX API key & ThreatFox Auth-Key, serta menjalankan sinkronisasi Threat Feed secara manual langsung dari dashboard.
