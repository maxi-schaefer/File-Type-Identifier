#!/usr/bin/env python
# File Type Identifier - Author: Max Schaefer
import os
import re
import sys
import json
import time
import requests
import argparse
from bs4 import BeautifulSoup

WIKI_URL = "https://en.wikipedia.org/wiki/List_of_file_signatures"
HEX_RE = re.compile(r"(?:[0-9A-Fa-f]{2}\s*){2,}")

# Cache File Signatures Constants
CACHE_FILE = os.path.expanduser("~/.filetype_signatures.json")
CACHE_TTL = 60 * 60 * 24 * 30 # 30 Days

# Hex Signatures from wikipedia - https://en.wikipedia.org/wiki/List_of_file_signatures (TODO: Load this using scraping)
BUILTIN_SIGNATURES = [
    # Hex Signature, Offset, Description, Extension
    ( "89504E470D0A1A0A", 0, "PNG Image", "png" ),
    ( "FFD8FFE0", 0, "JPG Image", "jpg" ),
    ( "25504446", 0, "PDF Document", "pdf" ),
    ( "47494638", 0, "GIF image", "gif"),
    ( "4D5A", 0, "Windows executable", "exe" ),
    ( "7F454C46", 0, "ELF executable", ""),
    ( "66747970", 4, "MP4 video", "mp4"),
    ( "2321", 0, "Script or data", ""),
    ( "EFBBBF", 0, "Text files", "txt")
]

BANNER = """
-+====== File Type Identifier ======+-
"""

# scape_file_signatures - Scrapes all the signatures from wikipedia
def scrape_file_signatures():
    signatures = []

    headers = {
        "User-Agent": "filetype/1.0 (https://github.com/maxi-schaefer)"
    }

    try:
        resp = requests.get(WIKI_URL, headers=headers, timeout=10)
        resp.raise_for_status()
    except requests.RequestException as e:
        print(f"[!] Failed to fetch Wikipedia signatures: {e}")
        return signatures

    soup = BeautifulSoup(resp.text, "html.parser")
    tables = soup.find_all("table", class_="wikitable")

    for table in tables:
        for row in table.find_all("tr")[1:]:
            cols = row.find_all("td")
            if len(cols) < 4:
                continue

            raw_hex = cols[0].get_text(" ", strip=True)
            raw_offset = cols[1].get_text(strip=True)
            raw_ext = cols[2].get_text(strip=True)
            description = cols[3].get_text(" ", strip=True)

            # Extract hex signatures
            hex_matches = HEX_RE.findall(raw_hex)
            if not hex_matches:
                continue

            # Offset: use first number if range like "0–3"
            try:
                offset = int(re.split(r"[–\-]", raw_offset)[0])
            except ValueError:
                offset = 0

            extension = raw_ext.split(",")[0].replace(".", "").lower()

            for hex_sig in hex_matches:
                hex_sig = hex_sig.replace(" ", "").upper()

                try:
                    bytes.fromhex(hex_sig)
                except ValueError:
                    continue

                signatures.append(
                    (hex_sig, offset, description, extension)
                )

    return signatures

# hex_to_bytes function - Convert hex to bytes properly
def hex_to_bytes(hex_string: str):
    return bytes.fromhex(hex_string)

# identify_file_type - Read file header and match signatures
def identify_file_type(file_path: str):
    max_len = max(len(sig) for sig, _, _, _ in FILE_SIGNATURES) // 2

    with open(file_path, "rb") as f:
        header = f.read(max_len + 16)

    header_hex = header.hex()

    for hex_sig, offset, desc, ext in FILE_SIGNATURES:
        sig_bytes = hex_to_bytes(hex_sig)
        sig_len = len(sig_bytes)

        if header[offset:offset + sig_len] == sig_bytes:
            return {
                "description": desc,
                "signature": hex_sig.lower(),
                "extension": ext,
                "header_hex": header_hex[:sig_len * 2]
            }
        
    return {
        "description": "Unknown file type",
        "signature": None,
        "extension": os.path.splitext(file_path)[1].lstrip("."),
        "header_hex": header_hex
    }

def load_cached_signatures():
    if not os.path.isfile(CACHE_FILE):
        return None
    
    try:
        with open(CACHE_FILE, "r") as f:
            data = json.load(f)

        if time.time() - data["timestamp"] > CACHE_TTL:
            return None
        
        return [
            (s["hex"], s["offset"], s["description"], s["extension"])
            for s in data["signatures"]
        ]
    except (json.JSONDecodeError, KeyError, OSError):
        return None
    
def save_cached_signatures(signatures):
    try:
        with open(CACHE_FILE, "w") as f:
            json.dump(
                {
                    "timestamp": time.time(),
                    "signatures": [
                        {
                            "hex": h,
                            "offset": o,
                            "description": d,
                            "extension": e,
                        }
                        for h, o, d, e in signatures
                    ],
                },
                f,
                indent=2
            )
    except OSError:
        pass

def load_file_signatures(force_update=False):
    if not force_update:
        cached = load_cached_signatures()
        if cached:
            return BUILTIN_SIGNATURES + cached
        
    print("[*] Updating file signature database from Wikipedia...")
    scraped = scrape_file_signatures()

    if scraped:
        print(f"[*] Loaded {len(scraped)} file signatures")
        save_cached_signatures(scraped)
        return BUILTIN_SIGNATURES + scraped
    
    print("[!] Using built-in signatures only")
    return BUILTIN_SIGNATURES

def main():
    # Setup arg parser
    parser = argparse.ArgumentParser(
        prog="filetype",
        description="Identify file type using hex magic numbers"
    )

    parser.add_argument(
        "path",
        help="Path to the file"
    )
    parser.add_argument(
        "--update-db",
        action="store_true",
        help="Force update of file signature database from Wikipedia"
    )

    args = parser.parse_args()
    path = args.path

    print(BANNER) # Print Banner

    if not os.path.isfile(path):
        print(f"File: {path}: No such file or not a regular file")
        sys.exit(1)

    try:
        global FILE_SIGNATURES
        FILE_SIGNATURES = load_file_signatures(force_update=args.update_db)

        info = identify_file_type(path)
        file_ext = os.path.splitext(path)[1] or "(none)"

        print(f"File:        {path}")
        print(f"Extension:   {file_ext}")

        print("\nMagic Number Analysis:")
        print(f"Raw Hex: {info['header_hex']}")
        print(f"Detected: {info['description']}")
        print(f"Signature: {info['signature']}")

    except PermissionError:
        print(f"file {path}: Permission denied")
        sys.exit(1)

if __name__ == "__main__":
    main()
