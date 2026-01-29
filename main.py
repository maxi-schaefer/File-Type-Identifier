#!/usr/bin/env python
# File Type Identifier - Author: Max Schaefer

# Hex Signatures from wikipedia - https://en.wikipedia.org/wiki/List_of_file_signatures (TODO: Load this using scraping)
FILE_SIGNATURES = [
    # Hex Signature, Offset, Extension
    { "89504E470D0A1A0A", 0, "PNG Image" },
    { "FFD8FFE0", 0, "JPG Image" },
    { "25504446", 0, "PDF Document" },
    ("47494638", 0, "GIF image"),
    { "4D5A", 0, "Windows executable" },
    ("7F454C46", 0, "ELF executable"),
    ("66747970", 4, "MP4 video"),
]

# hex_to_bytes function - Convert hex to bytes properly
def hex_to_bytes(hex_string: str):
    return bytes.fromhex(hex_string)

# identify_file_type - Read file header and match signatures
def identify_file_type(file_path: str):
    max_len = max(len(sig) for sig, _, _ in FILE_SIGNATURES) // 2

    with open(file_path, "rb") as f:
        header = f.read(max_len + 16)

    for hex_sig, offset, file_type in FILE_SIGNATURES:
        sig_bytes = hex_to_bytes(hex_sig)
        sig_len = len(sig_bytes)

        if header[offset:offset + sig_bytes] == sig_bytes:
            return file_type
        
    return "Unkown file type"

