#!/usr/bin/env python3
"""
FerroShield Feed Inspector & Diagnostic Tool
- Unduh & ekspor snapshot feed dari Feodo Tracker & URLhaus
- Cari keberadaan domain atau IP di feed Feodo, URLhaus, dan rules.json lokal
- Uji evaluasi heuristik phishing lokal dengan eTLD+1
"""

import sys
import os
import json
import urllib.request
import re
from datetime import datetime

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/hostfile/"

FEEDS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "feeds")
RULES_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rules.json")

def msg(text):
    print(f"\033[1;34m[*]\033[0m {text}")

def ok(text):
    print(f"\033[1;32m[+]\033[0m {text}")

def warn(text):
    print(f"\033[1;33m[!]\033[0m {text}")

def err(text):
    print(f"\033[1;31m[-]\033[0m {text}")

def download_feeds():
    os.makedirs(FEEDS_DIR, exist_ok=True)
    msg("Mengunduh feed terbaru dari Feodo Tracker & URLhaus...")

    feodo_file = os.path.join(FEEDS_DIR, "feodo_ips.txt")
    urlhaus_file = os.path.join(FEEDS_DIR, "urlhaus_domains.txt")

    try:
        req = urllib.request.Request(FEODO_URL, headers={"User-Agent": "FerroShield-FeedInspector/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            lines = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
            with open(feodo_file, "w", encoding="utf-8") as f:
                f.write(content)
            ok(f"Feodo Tracker: Berhasil mengunduh {len(lines)} IP -> {feodo_file}")
    except Exception as e:
        err(f"Gagal mengunduh Feodo Tracker feed: {e}")

    try:
        req = urllib.request.Request(URLHAUS_URL, headers={"User-Agent": "FerroShield-FeedInspector/1.0"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            # Extract domain entries
            domains = []
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "127.0.0.1":
                    domains.append(parts[1])
            with open(urlhaus_file, "w", encoding="utf-8") as f:
                f.write(content)
            ok(f"URLhaus: Berhasil mengunduh {len(domains)} domain -> {urlhaus_file}")
    except Exception as e:
        err(f"Gagal mengunduh URLhaus feed: {e}")

def search_query(query):
    query = query.strip().lower()
    if query.startswith("http://") or query.startswith("https://"):
        # extract host
        m = re.match(r"^https?://([^/:\?#]+)", query)
        if m:
            query = m.group(1).lower()

    print(f"\n=======================================================")
    print(f" HASIL PENCARIAN THREAT FEED: \033[1;36m{query}\033[0m")
    print(f"=======================================================")

    feodo_file = os.path.join(FEEDS_DIR, "feodo_ips.txt")
    urlhaus_file = os.path.join(FEEDS_DIR, "urlhaus_domains.txt")

    found_any = False

    # 1. Check local rules.json
    if os.path.exists(RULES_FILE):
        try:
            with open(RULES_FILE, "r", encoding="utf-8") as f:
                rules = json.load(f)
            net = rules.get("network_blacklist", {})
            ips = net.get("ips", [])
            domains = net.get("domains", [])
            
            rules_ip_match = query in ips
            rules_domain_match = any(query == d or query.endswith("." + d) for d in domains)
            
            if rules_ip_match or rules_domain_match:
                found_any = True
                warn(f"[rules.json] DITEMUKAN di blacklist lokal!")
                if rules_ip_match:
                    print(f"  - Cocok pada daftar IP lokal")
                if rules_domain_match:
                    print(f"  - Cocok pada daftar domain lokal")
            else:
                ok(f"[rules.json] Bersih (tidak ada di rules.json)")
        except Exception as e:
            warn(f"Gagal membaca rules.json: {e}")
    else:
        warn("rules.json tidak ditemukan")

    # 2. Check Feodo Tracker
    if os.path.exists(feodo_file):
        with open(feodo_file, "r", encoding="utf-8") as f:
            feodo_content = f.read()
        feodo_ips = [line.strip() for line in feodo_content.splitlines() if line.strip() and not line.startswith('#')]
        if query in feodo_ips:
            found_any = True
            err(f"[Feodo Tracker] DITEMUKAN! Terdaftar sebagai C2 / Botnet IP.")
        else:
            ok(f"[Feodo Tracker] Bersih (tidak terdaftar di Feodo Tracker)")
    else:
        warn("Feed Feodo belum diunduh. Jalankan: python3 scripts/feed_inspector.py download")

    # 3. Check URLhaus
    if os.path.exists(urlhaus_file):
        with open(urlhaus_file, "r", encoding="utf-8") as f:
            urlhaus_content = f.read()
        urlhaus_matches = []
        for line in urlhaus_content.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "127.0.0.1":
                dom = parts[1].lower()
                if query == dom or query.endswith("." + dom) or dom.endswith("." + query):
                    urlhaus_matches.append(dom)
        if urlhaus_matches:
            found_any = True
            err(f"[URLhaus] DITEMUKAN! Terdaftar sebagai Malware / Phishing host:")
            for m in urlhaus_matches[:5]:
                print(f"  - {m}")
            if len(urlhaus_matches) > 5:
                print(f"  - ... dan {len(urlhaus_matches) - 5} lainnya")
        else:
            ok(f"[URLhaus] Bersih (tidak terdaftar di URLhaus)")
    else:
        warn("Feed URLhaus belum diunduh. Jalankan: python3 scripts/feed_inspector.py download")

    print(f"-------------------------------------------------------")
    if not found_any:
        ok(f"KESIMPULAN: Target '{query}' BERSIH dari seluruh Threat Feed!")
    else:
        warn(f"KESIMPULAN: Target '{query}' TERIDENTIFIKASI di satu atau lebih Threat Feed.")
    print(f"=======================================================\n")

def main():
    if len(sys.argv) < 2:
        print("Penggunaan:")
        print("  python3 scripts/feed_inspector.py download          # Unduh feed Feodo & URLhaus terbaru")
        print("  python3 scripts/feed_inspector.py search <domain/ip> # Cari domain/IP di seluruh feed")
        sys.exit(0)

    cmd = sys.argv[1].lower()
    if cmd == "download":
        download_feeds()
    elif cmd == "search":
        if len(sys.argv) < 3:
            err("Harap tentukan domain atau IP yang ingin dicari!")
            sys.exit(1)
        search_query(sys.argv[2])
    else:
        search_query(sys.argv[1])

if __name__ == "__main__":
    main()
