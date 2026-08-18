#!/bin/sh
# FerroShield - Browser Extension Builder & Packager
# Builds .xpi / .zip packages for Firefox and Chrome/Chromium.
#
# Usage:
#   ./build_extension.sh               # Builds both Firefox (.xpi & .zip) and Chrome (.zip)
#   ./build_extension.sh --firefox     # Builds Firefox only
#   ./build_extension.sh --chrome      # Builds Chrome/Chromium only

set -e

PROJECT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
EXT_DIR="$PROJECT_DIR/extension"
DIST_DIR="$PROJECT_DIR/dist"

msg()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '\033[1;31m[-]\033[0m %s\n' "$*"; exit 1; }

[ -d "$EXT_DIR" ] || err "Direktori extension tidak ditemukan di $EXT_DIR"
command -v zip >/dev/null 2>&1 || err "Perintah 'zip' diperlukan untuk memaketkan ekstensi."

VERSION=$(sed -n 's/.*"version": *"\{0,1\}\([^",]*\)"\{0,1\}.*/\1/p' "$EXT_DIR/manifest.json" | head -n1)
[ -n "$VERSION" ] || VERSION="1.0.1"

TARGET="all"
if [ "$1" = "--firefox" ]; then
    TARGET="firefox"
elif [ "$1" = "--chrome" ]; then
    TARGET="chrome"
fi

mkdir -p "$DIST_DIR"
TMP_DIR=$(mktemp -d /tmp/ferroshield-ext-XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

build_firefox() {
    msg "Membangun ekstensi Firefox (v$VERSION)..."
    BUILD_DIR="$TMP_DIR/firefox"
    mkdir -p "$BUILD_DIR"

    # Salin file ekstensi
    cp "$EXT_DIR/background.js" "$BUILD_DIR/"
    cp "$EXT_DIR/content.js" "$BUILD_DIR/"
    cp "$EXT_DIR/popup.html" "$BUILD_DIR/"
    cp "$EXT_DIR/popup.js" "$BUILD_DIR/"
    cp "$EXT_DIR/warning.html" "$BUILD_DIR/"
    cp "$EXT_DIR/warning.js" "$BUILD_DIR/"
    cp -r "$EXT_DIR/icons" "$BUILD_DIR/"
    cp -r "$EXT_DIR/lib" "$BUILD_DIR/"
    cp -r "$EXT_DIR/rules" "$BUILD_DIR/"

    # Manifest khusus Firefox (menggunakan background.scripts)
    cat << 'EOF' > "$BUILD_DIR/manifest.json"
{
  "manifest_version": 3,
  "name": "FerroShield Browser Guard",
  "version": "__VERSION__",
  "description": "Lapisan keamanan cyber tambahan untuk daemon FerroShield: blokir domain blacklist via daemon lokal, heuristik phishing/scam, dan blokir web miner.",
  "permissions": [
    "storage",
    "tabs",
    "webNavigation",
    "declarativeNetRequest",
    "alarms"
  ],
  "host_permissions": [
    "http://127.0.0.1:8686/*",
    "http://localhost:8686/*",
    "<all_urls>"
  ],
  "background": {
    "scripts": ["lib/phishing.js", "background.js"]
  },
  "action": {
    "default_popup": "popup.html",
    "default_title": "FerroShield Browser Guard",
    "default_icon": {
      "16": "icons/icon16.png",
      "32": "icons/icon32.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  },
  "icons": {
    "16": "icons/icon16.png",
    "32": "icons/icon32.png",
    "48": "icons/icon48.png",
    "128": "icons/icon128.png"
  },
  "content_scripts": [
    {
      "matches": ["http://*/*", "https://*/*"],
      "js": ["content.js"],
      "run_at": "document_start",
      "all_frames": true
    }
  ],
  "declarative_net_request": {
    "rule_resources": [
      {
        "id": "miner_rules",
        "enabled": true,
        "path": "rules/miner.json"
      }
    ]
  },
  "browser_specific_settings": {
    "gecko": {
      "id": "ferroshield-browser-guard@ferroshield.app",
      "strict_min_version": "140.0",
      "data_collection_permissions": {
        "required": ["none"]
      }
    },
    "gecko_android": {
      "strict_min_version": "142.0"
    }
  }
}
EOF
    sed -i "s/__VERSION__/$VERSION/g" "$BUILD_DIR/manifest.json"

    # Package ke .xpi dan .zip
    XPI_OUT="$DIST_DIR/ferroshield-browser-guard-$VERSION-firefox.xpi"
    ZIP_OUT="$DIST_DIR/ferroshield-browser-guard-$VERSION-firefox.zip"
    rm -f "$XPI_OUT" "$ZIP_OUT" "$XPI_OUT.sha256" "$ZIP_OUT.sha256"

    (cd "$BUILD_DIR" && zip -q -r -9 "$XPI_OUT" .)
    cp "$XPI_OUT" "$ZIP_OUT"

    sha256sum "$XPI_OUT" > "$XPI_OUT.sha256"
    sha256sum "$ZIP_OUT" > "$ZIP_OUT.sha256"

    ok "Paket Firefox berhasil dibuat:"
    echo "    - $XPI_OUT"
    echo "    - $ZIP_OUT"
}

build_chrome() {
    msg "Membangun ekstensi Chrome/Chromium (v$VERSION)..."
    BUILD_DIR="$TMP_DIR/chrome"
    mkdir -p "$BUILD_DIR"

    # Salin file ekstensi
    cp "$EXT_DIR/background.js" "$BUILD_DIR/"
    cp "$EXT_DIR/content.js" "$BUILD_DIR/"
    cp "$EXT_DIR/popup.html" "$BUILD_DIR/"
    cp "$EXT_DIR/popup.js" "$BUILD_DIR/"
    cp "$EXT_DIR/warning.html" "$BUILD_DIR/"
    cp "$EXT_DIR/warning.js" "$BUILD_DIR/"
    cp -r "$EXT_DIR/icons" "$BUILD_DIR/"
    cp -r "$EXT_DIR/lib" "$BUILD_DIR/"
    cp -r "$EXT_DIR/rules" "$BUILD_DIR/"

    # Manifest khusus Chrome (menggunakan service_worker tanpa gecko settings)
    cat << 'EOF' > "$BUILD_DIR/manifest.json"
{
  "manifest_version": 3,
  "name": "FerroShield Browser Guard",
  "version": "__VERSION__",
  "description": "Lapisan keamanan cyber tambahan untuk daemon FerroShield: blokir domain blacklist via daemon lokal, heuristik phishing/scam, dan blokir web miner.",
  "permissions": [
    "storage",
    "tabs",
    "webNavigation",
    "declarativeNetRequest",
    "alarms"
  ],
  "host_permissions": [
    "http://127.0.0.1:8686/*",
    "http://localhost:8686/*",
    "<all_urls>"
  ],
  "background": {
    "service_worker": "background.js"
  },
  "action": {
    "default_popup": "popup.html",
    "default_title": "FerroShield Browser Guard",
    "default_icon": {
      "16": "icons/icon16.png",
      "32": "icons/icon32.png",
      "48": "icons/icon48.png",
      "128": "icons/icon128.png"
    }
  },
  "icons": {
    "16": "icons/icon16.png",
    "32": "icons/icon32.png",
    "48": "icons/icon48.png",
    "128": "icons/icon128.png"
  },
  "content_scripts": [
    {
      "matches": ["http://*/*", "https://*/*"],
      "js": ["content.js"],
      "run_at": "document_start",
      "all_frames": true
    }
  ],
  "declarative_net_request": {
    "rule_resources": [
      {
        "id": "miner_rules",
        "enabled": true,
        "path": "rules/miner.json"
      }
    ]
  }
}
EOF
    sed -i "s/__VERSION__/$VERSION/g" "$BUILD_DIR/manifest.json"

    ZIP_OUT="$DIST_DIR/ferroshield-browser-guard-$VERSION-chrome.zip"
    rm -f "$ZIP_OUT" "$ZIP_OUT.sha256"

    (cd "$BUILD_DIR" && zip -q -r -9 "$ZIP_OUT" .)
    sha256sum "$ZIP_OUT" > "$ZIP_OUT.sha256"

    ok "Paket Chrome berhasil dibuat:"
    echo "    - $ZIP_OUT"
}

if [ "$TARGET" = "firefox" ] || [ "$TARGET" = "all" ]; then
    build_firefox
fi

if [ "$TARGET" = "chrome" ] || [ "$TARGET" = "all" ]; then
    build_chrome
fi

ok "Build selesai!"
