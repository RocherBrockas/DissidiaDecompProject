#!/usr/bin/env python3
"""
PSP XOR Cipher — Dissidia 012
========================================
Algorithm reverse-engineered from MIPS code at 0x0887A6A0
Key located at 0x089D68AA in PSP RAM (256-bit / 32 bytes / 16 × uint16 LE)

Cipher logic (decompiled from MIPS):
    for each uint16 word at index v1:
        key_idx = abs(v0) & 0xF      # cycles through 0..15
        word   ^= key[key_idx]
        v0     += 1

Encryption and decryption are the same operation (XOR is its own inverse).

Text encoding used by the game: UTF-16 LE (confirmed by known-plaintext analysis).

Verified key (recovered from "M.S. Prima Vista"):
    AB 90 28 5E 42 84 B1 32 DA 2D 57 A6 BF C8 33 00
    9A 57 27 F2 4C 4B A7 36 7D 92 9D 73 CE 84 98 ED
"""

import struct
import sys
import argparse


# ---------------------------------------------------------------------------
# Known / default key (recovered via known-plaintext attack on "M.S. Prima Vista")
# ---------------------------------------------------------------------------

DEFAULT_KEY_HEX = bytes.fromhex(
    "3F1C012701C011F2F8C11678B9AD0A30"
    "D5EBFF5FF7FA7D39F75BE056701A2B1F"
)


# ---------------------------------------------------------------------------
# Core cipher
# ---------------------------------------------------------------------------

def _xor_cipher(data: bytes, key: bytes, v0_start: int = 0) -> bytes:
    """
    Apply the PSP XOR cipher to `data` using `key`.

    Parameters
    ----------
    data      : raw bytes to process (length must be even)
    key       : exactly 32 bytes (16 x uint16 little-endian)
    v0_start  : initial value of the MIPS $v0 counter (almost always 0)

    Returns
    -------
    Processed bytes (same length as input).
    """
    if len(key) != 32:
        raise ValueError(f"Key must be exactly 32 bytes, got {len(key)}")
    if len(data) % 2 != 0:
        raise ValueError(f"Data length must be even, got {len(data)}")

    key_words = list(struct.unpack_from("<16H", key))
    result    = bytearray(data)
    v0        = v0_start

    for i in range(len(result) // 2):
        word    = result[i * 2] | (result[i * 2 + 1] << 8)
        key_idx = ((-v0) if v0 < 0 else v0) & 0xF
        word   ^= key_words[key_idx]
        result[i * 2]     = word & 0xFF
        result[i * 2 + 1] = (word >> 8) & 0xFF
        v0 += 1

    return bytes(result)


# ---------------------------------------------------------------------------
# High-level API
# ---------------------------------------------------------------------------

def encrypt(plaintext: str, key: bytes, encoding: str = "utf-16-le",
            v0_start: int = 0) -> bytes:
    """
    Encrypt a plaintext string into cipher bytes.

    Parameters
    ----------
    plaintext : the string to encrypt
    key       : 32-byte cipher key
    encoding  : text encoding (default: utf-16-le, as used by the game)
    v0_start  : initial $v0 counter value (default 0)

    Returns
    -------
    Encrypted bytes.
    """
    raw = plaintext.encode(encoding)
    if len(raw) % 2 != 0:
        raw += b"\x00"
    return _xor_cipher(raw, key, v0_start)


def decrypt(cipher_bytes: bytes, key: bytes, encoding: str = "utf-16-le",
            v0_start: int = 0) -> str:
    """
    Decrypt cipher bytes back to a plaintext string.

    Parameters
    ----------
    cipher_bytes : encrypted bytes (length must be even)
    key          : 32-byte cipher key
    encoding     : text encoding (default: utf-16-le, as used by the game)
    v0_start     : initial $v0 counter value (default 0)

    Returns
    -------
    Decrypted string.
    """
    raw = _xor_cipher(cipher_bytes, key, v0_start)
    raw = raw.rstrip(b"\x00")
    if encoding == "utf-16-le" and len(raw) % 2 != 0:
        raw += b"\x00"
    return raw.decode(encoding, errors="replace")


# ---------------------------------------------------------------------------
# Key / hex helpers
# ---------------------------------------------------------------------------

def parse_key_hex(hex_str: str) -> bytes:
    """
    Parse a hex string into a 32-byte key.

    Accepted formats:
        "AB 90 28 5E ..."   (space-separated bytes)
        "AB90285E..."        (continuous hex string)
        "0xAB,0x90,..."     (comma-separated with 0x prefix)
    """
    cleaned = hex_str.replace("0x", "").replace(",", " ").replace("-", " ")
    key     = bytes(int(p, 16) for p in cleaned.split() if p)
    if len(key) != 32:
        raise ValueError(
            f"Key must be 32 bytes (256 bits), got {len(key)} bytes.\n"
            "Provide exactly 32 space-separated hex byte values."
        )
    return key


def parse_hex_bytes(hex_str: str) -> bytes:
    """Parse any hex string (space / comma separated) into bytes."""
    cleaned = hex_str.replace("0x", "").replace(",", " ")
    data    = bytes(int(p, 16) for p in cleaned.split() if p)
    if len(data) % 2 != 0:
        raise ValueError(
            f"Cipher data length must be even, got {len(data)} bytes."
        )
    return data


def bytes_to_hex(data: bytes) -> str:
    """Return uppercase hex, space-separated (e.g. 'E6 90 06 5E ...')."""
    return " ".join(f"{b:02X}" for b in data)


# ---------------------------------------------------------------------------
# Brute-force helper (unknown v0 start)
# ---------------------------------------------------------------------------

def brute_force_v0(cipher_bytes: bytes, key: bytes,
                   encoding: str = "utf-16-le",
                   min_printable_ratio: float = 0.70) -> list:
    """
    Try all 16 possible v0_start values (0..15).
    Returns candidates that produce mostly printable output, best first.

    Returns
    -------
    List of dicts: [{"v0": int, "text": str, "score": float}, ...]
    """
    candidates = []
    for v0 in range(16):
        raw = _xor_cipher(cipher_bytes, key, v0).rstrip(b"\x00")
        if encoding == "utf-16-le" and len(raw) % 2 != 0:
            raw += b"\x00"
        try:
            text = raw.decode(encoding, errors="replace")
        except Exception:
            continue
        printable = sum(1 for c in text if 0x20 <= ord(c) < 0x7F or ord(c) > 0xFF)
        ratio     = printable / max(len(text), 1)
        if ratio >= min_printable_ratio:
            candidates.append({"v0": v0, "text": text, "score": ratio})
    return sorted(candidates, key=lambda x: x["score"], reverse=True)


# ---------------------------------------------------------------------------
# Known-plaintext key derivation
# ---------------------------------------------------------------------------

def derive_key(plaintext: str, cipher_bytes: bytes,
               encoding: str = "utf-16-le", v0_start: int = 0) -> bytes:
    """
    Recover key words from a known plaintext / ciphertext pair.
    XOR(plaintext_word, cipher_word) = key_word.

    Parameters
    ----------
    plaintext    : the known plaintext string
    cipher_bytes : the matching encrypted bytes
    encoding     : text encoding of plaintext (default: utf-16-le)
    v0_start     : initial $v0 counter value (default 0)

    Returns
    -------
    32-byte key (unknown positions filled with 0x00).
    """
    plain_raw = plaintext.encode(encoding)
    if len(plain_raw) % 2 != 0:
        plain_raw += b"\x00"

    n         = min(len(plain_raw), len(cipher_bytes)) // 2
    key_words = [0] * 16
    v0        = v0_start

    for i in range(n):
        pw      = struct.unpack_from("<H", plain_raw, i * 2)[0]
        cw      = struct.unpack_from("<H", cipher_bytes, i * 2)[0]
        key_idx = ((-v0) if v0 < 0 else v0) & 0xF
        key_words[key_idx] = pw ^ cw
        v0 += 1

    return b"".join(struct.pack("<H", w) for w in key_words)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="psp_cipher",
        description=(
            "PSP XOR Cipher — encrypt strings or decrypt cipher bytes\n"
            "from Final Fantasy IX PSP  (algo @ 0x0887A6A0, key @ 0x089D68AA)\n\n"
            "The default key is pre-loaded (recovered via known-plaintext analysis).\n"
            "Override it with --key if you dump a different key from PSP RAM."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=r"""
Examples
--------

  # Decrypt using the built-in key (no --key needed)
  python psp_cipher.py decrypt \
      --data "E6 90 06 5E 11 84 9F 32 FA 2D 07 A6 CD C8 5A 00 F7 57 46 F2 6C 4B F1 36 14 92 EE 73 BA 84 F9 ED"

  # Encrypt a string (reproduces the known cipher bytes above)
  python psp_cipher.py encrypt --text "M.S. Prima Vista"

  # Use a custom key (32 hex bytes, space-separated)
  python psp_cipher.py decrypt \
      --key "AB 90 28 5E 42 84 B1 32 DA 2D 57 A6 BF C8 33 00 9A 57 27 F2 4C 4B A7 36 7D 92 9D 73 CE 84 98 ED" \
      --data "E6 90 06 5E ..."

  # Brute-force v0 start offset (when the counter initial value is unknown)
  python psp_cipher.py brute --data "E6 90 06 5E ..."

  # Recover key from a known plaintext / ciphertext pair
  python psp_cipher.py derive-key \
      --plaintext "M.S. Prima Vista" \
      --data "E6 90 06 5E 11 84 9F 32 FA 2D 07 A6 CD C8 5A 00 F7 57 46 F2 6C 4B F1 36 14 92 EE 73 BA 84 F9 ED"
""",
    )

    key_kw = dict(default=None, metavar="HEX",
                  help="32-byte key as hex string (default: built-in key)")

    sub = p.add_subparsers(dest="command", required=True)

    # ---- decrypt ----
    dec = sub.add_parser("decrypt", help="Decrypt cipher bytes -> string")
    dec.add_argument("--key",  **key_kw)
    dec.add_argument("--data", required=True, metavar="HEX",
                     help="Cipher bytes as hex string")
    dec.add_argument("--v0",   type=int, default=0,
                     help="Initial $v0 counter value (default 0)")
    dec.add_argument("--enc",  default="utf-16-le",
                     help="Output text encoding (default: utf-16-le)")

    # ---- encrypt ----
    enc = sub.add_parser("encrypt", help="Encrypt a string -> cipher bytes")
    enc.add_argument("--key",  **key_kw)
    enc.add_argument("--text", required=True, help="Plaintext string to encrypt")
    enc.add_argument("--v0",   type=int, default=0,
                     help="Initial $v0 counter value (default 0)")
    enc.add_argument("--enc",  default="utf-16-le",
                     help="Input text encoding (default: utf-16-le)")

    # ---- brute ----
    brt = sub.add_parser("brute",
                         help="Brute-force v0 start: try all 16 possible offsets")
    brt.add_argument("--key",  **key_kw)
    brt.add_argument("--data", required=True, metavar="HEX",
                     help="Cipher bytes as hex string")
    brt.add_argument("--enc",  default="utf-16-le",
                     help="Text encoding to test (default: utf-16-le)")

    # ---- derive-key ----
    drv = sub.add_parser("derive-key",
                         help="Known-plaintext attack: recover up to 16 key words")
    drv.add_argument("--plaintext", required=True,
                     help="Known plaintext string")
    drv.add_argument("--data",      required=True, metavar="HEX",
                     help="Matching cipher bytes as hex string")
    drv.add_argument("--enc",  default="utf-16-le",
                     help="Plaintext encoding (default: utf-16-le)")
    drv.add_argument("--v0",   type=int, default=0,
                     help="Initial $v0 counter value (default 0)")

    return p


def _resolve_key(args) -> bytes:
    """Return the key from --key flag or fall back to DEFAULT_KEY_HEX."""
    src = args.key if args.key else DEFAULT_KEY_HEX
    return parse_key_hex(src)


def cmd_decrypt(args):
    key    = _resolve_key(args)
    data   = parse_hex_bytes(args.data)
    result = decrypt(data, key, encoding=args.enc, v0_start=args.v0)
    print(f"[Decrypted] {result}")


def cmd_encrypt(args):
    key    = _resolve_key(args)
    result = encrypt(args.text, key, encoding=args.enc, v0_start=args.v0)
    print(f"[Encrypted hex] {bytes_to_hex(result)}")


def cmd_brute(args):
    key        = _resolve_key(args)
    data       = parse_hex_bytes(args.data)
    candidates = brute_force_v0(data, key, encoding=args.enc)
    if not candidates:
        print("No candidate found (no v0 produces >=70% printable output).")
        return
    print(f"{'v0':>3}  {'score':>6}  text")
    print("-" * 52)
    for c in candidates:
        print(f"  {c['v0']:>2}   {c['score']:>5.0%}   {c['text']!r}")


def cmd_derive_key(args):
    data = parse_hex_bytes(args.data)
    key  = derive_key(args.plaintext, data,
                      encoding=args.enc, v0_start=args.v0)

    key_words     = list(struct.unpack_from("<16H", key))
    n_plain_words = len(args.plaintext.encode(args.enc)) // 2

    print(f"Recovered {n_plain_words} of 16 key words from plaintext:\n")
    for i, w in enumerate(key_words):
        mark = "<-- recovered" if w != 0 else ""
        print(f"  key[{i:2d}]  0x{w:04X}"
              f"  (bytes: {w & 0xFF:02X} {(w >> 8) & 0xFF:02X})  {mark}")

    print(f"\nFull key (hex):\n  {bytes_to_hex(key)}")
    print("\nNote: positions shown as 0x0000 are unknown.")
    print("      Dump PSP RAM at 0x089D68AA to recover all 32 bytes.")

    test = decrypt(data, key, encoding=args.enc, v0_start=args.v0)
    print(f"\nSelf-check decrypt: {test!r}")


def main():
    parser = _build_parser()
    args   = parser.parse_args()

    dispatch = {
        "decrypt":    cmd_decrypt,
        "encrypt":    cmd_encrypt,
        "brute":      cmd_brute,
        "derive-key": cmd_derive_key,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
