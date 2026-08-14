# Panduan Teknis FerroShield (untuk Teknisi / Maintainer)

Dokumen ini berisi prosedur teknis: arsitektur basis aturan, cara memperbarui & memverifikasi ruleset YARA, deploy ke daemon yang berjalan, serta troubleshooting. Untuk panduan penggunaan umum, baca [MANUAL.md](file:///media/D/projek/pribadi/ferroshield/MANUAL.md).

---

## 1. Arsitektur Basis Aturan

| Berkas | Fungsi | Tanda tangan | Lokasi |
|---|---|---|---|
| `rules.json` | Rule hash (MD5/SHA-256/TLSH), pola regex, `extension_ids`, blacklist IP/domain, **`ebpf_sha256`**, **`rules_yar_sha256`** | **Ya** — Ed25519 (`rules.json.sig`, diverifikasi `config.rs`) | direktori kerja (biasanya `/etc/ferroshield/`) |
| `rules.yar` | Ruleset YARA-X (12.419 rule) | **Hash SHA-256** dicatat di `rules.json` yang ditandatangani (`rules_yar_sha256`, diverifikasi `src/scanner.rs`) | direktori kerja (`src/scanner.rs:42`) |
| `config.json` | `default_action`, `downloads_dir`, `miner_detection_require_secondary_signal`, `process_containment` (runtime, tidak ditandatangani) | Tidak | `$FERROSHIELD_CONFIG`, `./config.json`, atau `/etc/ferroshield/config.json` |
| `whitelist.json` | Daftar path file yang dikecualikan | Tidak | direktori kerja |
| `dashboard.token` | Token akses Web UI (mode `0600`) untuk semua endpoint `/api/*` | Tidak (dibuat saat startup) | direktori kerja (`/etc/ferroshield/dashboard.token`) |

### Cara kerja pemuatan `rules.yar`
- Dibaca **sekali** saat `Scanner::new()` dijalankan (`src/scanner.rs:42`), dari `Path::new("rules.yar")` **relatif terhadap direktori kerja** biner.
- Sebelum dikompilasi, SHA-256 `rules.yar` diverifikasi terhadap `rules_yar_sha256` di `rules.json` yang sudah diverifikasi Ed25519. Bila tidak cocok → log `[-] PERINGATAN: SHA-256 rules.yar tidak cocok...` dan **YARA dinonaktifkan** (jangan diam-diam terima ruleset yang diubah). Ruleset lama tanpa field `rules_yar_sha256` tetap dimuat (kompatibilitas mundur).
- Bila file tidak ada → dilewati diam-diam (YARA nonaktif). Bila gagal dikompilasi → log `[-] Gagal kompilasi rules.yar` (YARA nonaktif).
- Scan YARA dibatasi waktu **1 detik per file** (`YARA_SCAN_TIMEOUT` di `src/scanner.rs`) agar regex patologis (ReDoS) tidak menghentikan Browser Guard/daemon.
- YARA hanya diterapkan pada file **< 10 MB** (`src/scanner.rs:194`).
- `rules.yar`/`rules.json` otomatis dilewati pada pemindaian direktori (`src/scanner.rs:349`) agar ruleset tidak men-flag dirinya sendiri.

---

## 2. Sumber & Komposisi `rules.yar` (versi saat ini)

- **Sumber**: [Yara-Rules/rules](https://github.com/Yara-Rules/rules) — commit `0f93570194a80d2f2032869055808b0ddcdfb360` (12 Apr 2022)
- **Lisensi**: **GPL-2.0** (catatan lisensi lihat §6)
- **Jumlah**: 12.419 rule, ~5,5 MB
- **SHA-256**: `8a172c4f13d1ed84b974f0e3228070ab64bfdf542120b7eee155fc91b7709c8a` (per 14 Agu 2026, setelah patch ReDoS)
- **Kategori yang disertakan**: `malware`, `webshells`, `packers`, `exploit_kits`, `maldocs`, `email`, `cve_rules`
- **Kategori yang TIDAK disertakan**: `crypto`, `capabilities`, `antidebug_antivm`, `deprecated`, `mobile_malware` (bergantung modul `androguard`), berkas `*.eml` (sampel email asli), dan folder `Operation_Blockbuster/*.yara`/`mastersig`
- **File yang dibuang karena tidak kompatibel `yara-x 0.5`**:
  - `MALW_AZORULT.yar` — `import "cuckoo"` (modul tidak ada)
  - `APT_CrashOverride.yar` — tipe salah: `pe.exports(...) & pe.characteristics`
  - `RAT_PlugX.yar`, `RAT_PoetRATPython.yar`, `Wshell_ChineseSpam.yar` — regex tidak valid

---

## 3. Prosedur Memperbarui `rules.yar`

> Prasyarat: `git`, dan proyek Rust ini sebagai sumber `yara-x` 0.5.0 (sudah ada di `Cargo.lock`).

```bash
# 1. Ambil sumber terbaru (shallow clone ke area kerja)
git clone --depth 1 https://github.com/Yara-Rules/rules /tmp/yara-rules

# 2. Gabungkan kategori terpilih menjadi satu berkas
cd /tmp/yara-rules
: > /tmp/rules.yar
for dir in malware webshells packers exploit_kits maldocs email cve_rules; do
  for f in "$dir"/*.yar; do
    case "$f" in
      */MALW_AZORULT.yar|*/APT_CrashOverride.yar|*/RAT_PlugX.yar|\
      */RAT_PoetRATPython.yar|*/Wshell_ChineseSpam.yar) continue ;;
    esac
    printf '\n// ==================== %s ====================\n' "$f" >> /tmp/rules.yar
    cat "$f" >> /tmp/rules.yar
  done
done

# 3. Validasi kompilasi (lihat §4) — WAJIB lolos sebelum dipakai
# 4. Ganti berkas di proyek
cp /tmp/rules.yar ./rules.yar

# 5. Perbarui hash & tanda tangan (WAJIB, agar verifikasi integritas tidak menolak)
#    Mencatat SHA-256 baru rules.yar (dan modul eBPF bila ada) ke rules.json,
#    lalu menandatangani ulang dengan rules.key.
ferroshield sign-rules
```

**Penting saat menambah kategori/file baru**: pastikan:
- Tidak ada `import` modul yang tidak didukung `yara-x` (`cuckoo`, `magic`, `androguard`, dst).
- Tidak ada duplikasi nama rule antar-file (kompilasi satu namespace akan gagal).
- Periksa kategori baru untuk berkas non-`.yar` (sampel email, skrip mentah) — jangan ikut digabung.

---

## 4. Verifikasi Ruleset

### 4.1 Validasi kompilasi dengan `yara-x`
Jalankan build + scan uji EICAR:

```bash
cargo build --release
mkdir -p /tmp/fscheck
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/fscheck/eicar.txt
./target/release/ferroshield scan /tmp/fscheck/eicar.txt
```

Ekspektasi output — dua aturan tercantum sekaligus:
```
  - Aturan: EICAR Test File (ID: RULE-001) [High]   # dari rules.json
  - Aturan: eicar (ID: YARA-eicar) [High]           # dari rules.yar
```
Jika baris `YARA-eicar` tidak muncul, berarti `rules.yar` tidak terkompilasi/terbaca — periksa §5.

### 4.2 Verifikasi integritas sumber
```bash
cd /tmp/yara-rules && git rev-parse HEAD   # catat SHA, bandingkan dengan catatan §2
```

### 4.3 Uji self-match (regresi)
Ruleset berisi string payload asli, sehingga **dapat men-flag dirinya sendiri**:
```bash
./target/release/ferroshield scan ./rules.yar   # Akan terdeteksi — ini NORMAL
./target/release/ferroshield scan ./            # rules.yar/rules.json HARUS dilewati
```
Jika pemindaian direktori menampilkan `rules.yar` sebagai ancaman, berarti patch skip di `src/scanner.rs` hilang — jangan pakai versi tersebut.

---

## 5. Troubleshooting

| Gejala | Kemungkinan penyebab | Solusi |
|---|---|---|
| Log `[-] Gagal kompilasi rules.yar` | Rule baru tidak kompatibel `yara-x` | Uji setiap file baru secara terpisah; buang file yang gagal (§3). |
| YARA tidak pernah memicu (padahal `rules.yar` ada) | Biner dijalankan dari direktori yang berbeda | Jalankan dari direktori yang memuat `rules.yar` (daemon: `WorkingDirectory=/etc/ferroshield`). |
| Startup daemon lambat | Kompilasi 12.460 rule (±2–3 detik pada build release; debug bisa 30 detik+) | Pakai biner `--release`; jangan jalankan daemon dari biner debug. |
| False positive pada file bersih | Rule komunitas bersifat broad (mis. `IsSuspicious` memicu arsip `.a`/build artifact) | Tambahkan path ke `whitelist.json`: `printf '["/path/ke/file"]' > whitelist.json`, lalu restart. |
| Scan file besar (>5 MB) terasa lambat | YARA memindai seluruh isi (limit <10 MB) | Batasi ukuran di `src/scanner.rs` (konstanta `10 * 1024 * 1024`) bila perlu. |
| `rules.yar` muncul sebagai ancaman saat scan folder | Patch skip hilang / versi biner lama | Gunakan biner terbaru (`src/scanner.rs:349` skip `rules.yar`/`rules.json`). |
| Daemon lama tidak memuat ruleset baru | `rules.yar` di `/etc/ferroshield/` belum diperbarui | `cp rules.yar /etc/ferroshield/rules.yar && sudo systemctl restart ferroshield` |

### Memeriksa log daemon
```bash
sudo journalctl -u ferroshield -f          # systemd
sudo ./control.sh logs                     # via script helper
```

---

## 6. Catatan Keamanan & Lisensi

- Integritas `rules.yar` dilindungi oleh **hash SHA-256** yang dicatat di `rules.json` (yang ditandatangani Ed25519). `ferroshield sign-rules` menghitung ulang hash tersebut; bila `rules.yar` diubah tanpa `sign-rules`, YARA dinonaktifkan dengan peringatan jelas. Modul eBPF `/usr/lib/ferroshield/ferroshield_ebpf.o` dilindungi serupa via `ebpf_sha256`; modul yang diubah akan ditolak dan daemon fallback ke procfs.
- Semua endpoint Web UI `/api/*` mewajibkan token dari `dashboard.token` (mode `0600`), sehingga proses lokal non-browser tidak dapat memicu aksi destruktif terhadap daemon root.
- **Mitigasi proses berbahaya = freeze-first (anti-mutasi)** (`src/contain.rs`). Saat proses terdeteksi (IP blacklist, path temp mencurigakan, port mining, heuristik CPU, atau event eBPF), urutannya: **(1) bekukan seluruh pohon proses** via *cgroup v2 freezer* (`cgroup.freeze`, atomik & mencegah fork; fallback `SIGSTOP` ke seluruh keturunan lewat walk `/proc`), **(2) netralkan binary** (karantina AES-256/delet), **(3) blokir IP** (jika relevan), lalu **(4) SIGKILL** proses yang masih beku dan bersihkan cgroup. Proses yang beku tidak dapat mengeksekusi kode apa pun, sehingga tidak ada jendela untuk mutasi/respawn saat binary dibersihkan. Mode diatur lewat `process_containment` (`auto`/`cgroup`/`sigstop`/`off`); proses ber-pid ≤ 1, daemon sendiri, dan biner yang mengandung "ferroshield" selalu dikecualikan.
- Ruleset ini berasal dari proyek **GPL-2.0**; FerroShield berlisensi **Proprietary** (LICENSE). Menggabungkan rule GPL ke produk proprietary berpotensi bermasalah secara lisensi — evaluasi legal sebelum distribusi publik.
- Beberapa rule memuat potongan skrip berbahaya (PowerShell, JS, PHP webshell, hexdump exploit) **sebagai pola deteksi semata**; FerroShield tidak pernah mengeksekusinya — hanya mencocokkan pola.

---

## 7. Checklist Pasca-Update

- [ ] `rules.yar` baru lolos kompilasi (scan EICAR menampilkan `YARA-eicar`)
- [ ] `ferroshield sign-rules` dijalankan (hash baru `rules.yar` + `ebpf_sha256` dicatat di `rules.json`, lalu ditandatangani ulang)
- [ ] `sha256sum rules.yar` dicatat untuk audit (sinkron dengan §2)
- [ ] Salinan terpasang di `/etc/ferroshield/rules.yar` dan service di-restart
- [ ] `scan <folder berisi file bersih>` tidak menampilkan `rules.yar` sebagai ancaman
- [ ] Tidak ada error `Gagal kompilasi rules.yar` di `journalctl`
- [ ] Commit SHA sumber baru dicatat (jika ada perubahan dari versi §2)
