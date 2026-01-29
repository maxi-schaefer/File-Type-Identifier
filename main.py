#!/usr/bin/env python
# File Type Identifier - Author: Max Schaefer
import os
import sys
import argparse

# Hex Signatures from wikipedia - https://en.wikipedia.org/wiki/List_of_file_signatures (TODO: Load this using scraping)
FILE_SIGNATURES = [
    # Hex Signature, Offset, Description, Extension
    ( "89504E470D0A1A0A", 0, "PNG Image", "png" ),
    ( "FFD8FFE0", 0, "JPG Image", "jpg" ),
    ( "25504446", 0, "PDF Document", "pdf" ),
    ( "47494638", 0, "GIF image", "gif"),
    ( "4D5A", 0, "Windows executable", "exe" ),
    ( "7F454C46", 0, "ELF executable", ""),
    ( "66747970", 4, "MP4 video", "mp4"),
]

BANNER = """
-+====== File Type Identifier ======+-
"""

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

    args = parser.parse_args()
    path = args.path

    print(BANNER) # Print Banner

    if not os.path.isfile(path):
        print(f"File: ${path}: No such file or not a regular file")
        sys.exit(1)

    try:
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
