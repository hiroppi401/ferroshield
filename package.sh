#!/bin/sh
# FerroShield - packaging script (binary-only distribution)
# Builds a tarball containing the prebuilt binary + eBPF module + rules,
# so end users install WITHOUT source code or a Rust toolchain.
#
# Usage:
#   ./package.sh               glibc package for this architecture (with eBPF if possible)
#   ./package.sh --musl        static musl package (runs on any Linux distro/libc)
#   ./package.sh --no-ebpf     build without the eBPF module (procfs fallback only)
#                              (flags can be combined: --musl --no-ebpf)
#
# Requirements:
#   glibc mode: cargo
#   musl mode:  cargo, zig (in PATH) and cargo-zigbuild (cargo install cargo-zigbuild)
#
# Output: dist/ferroshield-<version>-linux-<arch>[-musl].tar.gz (+ .sha256)

set -e

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VERSION=$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$PROJECT_DIR/Cargo.toml" | head -n1)
[ -n "$VERSION" ] || VERSION="0.0.0"

DIST_DIR="$PROJECT_DIR/dist"
DIST_ARCH=$(uname -m)

msg()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[-]\033[0m %s\n' "$*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

MUSL=no
NO_EBPF=no
for arg in "$@"; do
    case "$arg" in
        --musl) MUSL=yes ;;
        --no-ebpf) NO_EBPF=yes ;;
        *) err "Argumen tidak dikenal: $arg (dukungan: --musl, --no-ebpf)";;
    esac
done

[ -f "$PROJECT_DIR/Cargo.toml" ] || err "Cargo.toml tidak ditemukan. Jalankan dari direktori proyek."

musl_triple() {
    case "$(uname -m)" in
        x86_64) echo x86_64-unknown-linux-musl ;;
        aarch64) echo aarch64-unknown-linux-musl ;;
        armv7l|armv6l|arm) echo armv7-unknown-linux-musleabihf ;;
        riscv64) echo riscv64gc-unknown-linux-musl ;;
        *) echo unsupported ;;
    esac
}

# --- Build release binary ---------------------------------------------------
BIN=""
PKG_SUFFIX=""
if [ "$MUSL" = "yes" ]; then
    TRIPLE=$(musl_triple)
    [ "$TRIPLE" != "unsupported" ] || err "Arsitektur $(uname -m) tidak didukung untuk target musl."
    if ! have zig; then
        err "zig tidak ditemukan di PATH. Unduh dari https://ziglang.org/download dan tambahkan ke PATH."
    fi
    if ! have cargo-zigbuild; then
        err "cargo-zigbuild tidak ditemukan. Install: cargo install cargo-zigbuild"
    fi
    msg "Memastikan target Rust $TRIPLE tersedia..."
    rustup target add "$TRIPLE" >/dev/null 2>&1 || true
    msg "Mengompilasi biner statis musl (cargo zigbuild --release --target $TRIPLE)..."
    (cd "$PROJECT_DIR" && cargo zigbuild --release --target "$TRIPLE")
    BIN="$PROJECT_DIR/target/$TRIPLE/release/ferroshield"
    PKG_SUFFIX="-musl"
else
    msg "Mengompilasi biner release (cargo build --release)..."
    (cd "$PROJECT_DIR" && cargo build --release)
    BIN="$PROJECT_DIR/target/release/ferroshield"
fi

[ -f "$BIN" ] || err "Biner tidak ditemukan: $BIN"

PKG_DIR="$DIST_DIR/ferroshield-$VERSION-linux-$DIST_ARCH$PKG_SUFFIX"
TARBALL="$PKG_DIR.tar.gz"

# --- eBPF module (optional, architecture-specific) --------------------------
EBPF_O=""
if [ "$NO_EBPF" != "yes" ]; then
    if [ -f "$PROJECT_DIR/src/ebpf/ferroshield_ebpf.o" ]; then
        EBPF_O="$PROJECT_DIR/src/ebpf/ferroshield_ebpf.o"
        ok "Menggunakan modul eBPF prebuilt: $EBPF_O"
    elif have clang && have llvm-strip; then
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
        arch=$(bpf_arch)
        if [ "$arch" != "unsupported" ]; then
            include_flags=""
            for d in /usr/include /usr/include/x86_64-linux-gnu /usr/include/aarch64-linux-gnu; do
                if [ -f "$d/bpf/bpf_helpers.h" ]; then
                    case "$include_flags" in
                        *"$d"*) ;;
                        *) include_flags="$include_flags -I$d" ;;
                    esac
                fi
            done
            if [ -n "$include_flags" ]; then
                msg "Mengompilasi modul eBPF untuk arsitektur $arch..."
                clang -g -O2 -target bpf -D__TARGET_ARCH_$arch \
                    -c "$PROJECT_DIR/src/ebpf/ferroshield_ebpf.c" \
                    -o "$DIST_DIR/ferroshield_ebpf.o" $include_flags
                llvm-strip -g "$DIST_DIR/ferroshield_ebpf.o"
                EBPF_O="$DIST_DIR/ferroshield_ebpf.o"
                ok "Modul eBPF dikompilasi."
            else
                warn "Header libbpf tidak ditemukan. eBPF dilewati."
            fi
        else
            warn "Arsitektur $(uname -m) tidak didukung eBPF. eBPF dilewati."
        fi
    else
        warn "clang/llvm-strip tidak tersedia. eBPF dilewati."
    fi
fi

# --- Assemble package -------------------------------------------------------
msg "Menyusun paket: $PKG_DIR"
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR"

cp "$BIN" "$PKG_DIR/ferroshield"
chmod 0755 "$PKG_DIR/ferroshield"

if [ -n "$EBPF_O" ]; then
    cp "$EBPF_O" "$PKG_DIR/ferroshield_ebpf.o"
fi

if [ -f "$PROJECT_DIR/rules.json" ]; then
    cp "$PROJECT_DIR/rules.json" "$PKG_DIR/rules.json"
else
    warn "rules.json tidak ditemukan; paket tidak akan berisi basis aturan."
fi

if [ -f "$PROJECT_DIR/rules.yar" ]; then
    cp "$PROJECT_DIR/rules.yar" "$PKG_DIR/rules.yar"
else
    warn "rules.yar tidak ditemukan; paket tidak akan berisi ruleset YARA."
fi

if [ -f "$PROJECT_DIR/LICENSE" ]; then
    cp "$PROJECT_DIR/LICENSE" "$PKG_DIR/LICENSE"
fi

cp "$PROJECT_DIR/install.sh" "$PKG_DIR/install.sh"
printf '%s\n' "$VERSION" > "$PKG_DIR/VERSION"
printf '%s\n' "$DIST_ARCH" > "$PKG_DIR/ARCH"

# --- Archive ----------------------------------------------------------------
msg "Mengompresi paket..."
rm -f "$TARBALL" "$TARBALL.sha256"
(cd "$DIST_DIR" && tar czf "$(basename "$TARBALL")" "$(basename "$PKG_DIR")")
sha256sum "$TARBALL" > "$TARBALL.sha256"

ok "Selesai: $TARBALL"
msg "Distribusikan arsip ini; pengguna cukup menjalankan: sudo ./install.sh"
msg "Checksum: $TARBALL.sha256"
