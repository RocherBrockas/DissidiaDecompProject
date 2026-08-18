#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Dissidia 012 - MESS PAK decryptor

Format:
- Header: "mess pak"
- After header:
    u16 unk1
    u16 unk2
    u32 unk3
    u32 text_count
    u32 pool_offset
    u32 file_size
- Then comes the pointer table (u16 offsets relative to pool_offset)
- Text data is XOR encrypted with a rotating 16-word key

The decryption routine matches the provided MIPS code.
"""

import struct
import sys
from pathlib import Path


# -----------------------------------------------------------------------------
# XOR key (16 x uint16)
# -----------------------------------------------------------------------------

KEY_HEX = (
    "AB90285E4284B132DA2D57A6BFC83300"
    "9A5727F24C4BA7367D929D73CE8498ED"
)

KEY_BYTES = bytes.fromhex(KEY_HEX)

# convert to little-endian uint16 table
KEY = [
    struct.unpack_from("<H", KEY_BYTES, i)[0]
    for i in range(0, len(KEY_BYTES), 2)
]

assert len(KEY) == 16


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def read_u16(data, offset):
    return struct.unpack_from("<H", data, offset)[0]


def write_u16(data, offset, value):
    struct.pack_into("<H", data, offset, value & 0xFFFF)


def decrypt_words(data, start_offset, word_count):
    """
    Reproduces the MIPS loop exactly.

    v0 = signed index
    if v0 >= 0:
        key_index = v0 & 0xF
    else:
        key_index = (-(-v0 & 0xF))

    In practice for normal files:
        key_index = i & 0xF
    """

    v0 = 0

    for i in range(word_count):

        word = read_u16(data, start_offset + i * 2)

        if v0 >= 0:
            key_index = v0 & 0xF
        else:
            key_index = (-((-v0) & 0xF)) & 0xF

        decrypted = word ^ KEY[key_index]

        write_u16(data, start_offset + i * 2, decrypted)

        v0 += 1


def parse_header(data):
    magic = data[0:8]

    if magic != b"mess pak":
        raise ValueError("Invalid mess pak magic")

    unk1 = read_u16(data, 0x08)
    unk2 = read_u16(data, 0x0A)

    unk3 = struct.unpack_from("<I", data, 0x0C)[0]
    text_count = struct.unpack_from("<I", data, 0x10)[0]
    pool_offset = struct.unpack_from("<I", data, 0x14)[0]
    file_size = struct.unpack_from("<I", data, 0x18)[0]

    return {
        "unk1": unk1,
        "unk2": unk2,
        "unk3": unk3,
        "text_count": text_count,
        "pool_offset": pool_offset,
        "file_size": file_size,
    }


def extract_pointers(data, text_count):
    """
    Pointer table starts at 0x20
    Each pointer is uint16 relative to pool_offset
    """

    ptrs = []

    ptr_table = 0x20

    for i in range(text_count):
        ptr = read_u16(data, ptr_table + i * 2)
        ptrs.append(ptr)

    return ptrs


# -----------------------------------------------------------------------------
# Main decrypt
# -----------------------------------------------------------------------------

def decrypt_messpak(input_path, output_path=None):

    data = bytearray(Path(input_path).read_bytes())

    hdr = parse_header(data)

    text_count = hdr["text_count"]
    pool_offset = hdr["pool_offset"]

    print(f"[+] text_count : {text_count}")
    print(f"[+] pool_offset: 0x{pool_offset:X}")

    ptrs = extract_pointers(data, text_count)

    # decrypt everything from pool_offset to EOF
    encrypted_size = len(data) - pool_offset

    if encrypted_size % 2 != 0:
        encrypted_size -= 1

    word_count = encrypted_size // 2

    print(f"[+] decrypting {word_count} words")

    decrypt_words(data, pool_offset, word_count)

    if output_path is None:
        output_path = str(Path(input_path).with_suffix(".dec.bin"))

    Path(output_path).write_bytes(data)

    print(f"[+] written: {output_path}")

    # optional text dump
    print("\n[+] Entry offsets:\n")

    for i, ptr in enumerate(ptrs):
        absolute = pool_offset + ptr
        print(f"{i:04d} -> 0x{absolute:08X}")


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: python decrypt_messpak.py file.bin [output.bin]")
        sys.exit(1)

    input_file = sys.argv[1]

    output_file = None

    if len(sys.argv) >= 3:
        output_file = sys.argv[2]

    decrypt_messpak(input_file, output_file)