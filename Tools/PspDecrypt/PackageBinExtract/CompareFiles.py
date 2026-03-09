#!/usr/bin/env python3
"""
Compare two files byte-by-byte and report offsets of differences and total differing bytes.

Usage:
    python CompareFiles.py fileA fileB [--max-offsets N] [--chunk-size B]

- --max-offsets: maximum number of differing offsets to print (default 1000)
- --chunk-size: read buffer size in bytes (default 65536)
"""
import argparse
import os
import sys

def compare_files(path_a: str, path_b: str, max_offsets: int = 1000, chunk_size: int = 65536):
    if not os.path.isfile(path_a) or not os.path.isfile(path_b):
        raise FileNotFoundError("One of this file does not exist.")

    size_a = os.path.getsize(path_a)
    size_b = os.path.getsize(path_b)

    diffs = 0
    offsets = []
    offset = 0

    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        while True:
            ba = fa.read(chunk_size)
            bb = fb.read(chunk_size)
            if not ba and not bb:
                break

            if ba == bb:
                offset += max(len(ba), len(bb))
                continue

            # compare byte per byte up to min length
            minlen = min(len(ba), len(bb))
            if minlen:
                ma = memoryview(ba)
                mb = memoryview(bb)
                for i in range(minlen):
                    if ma[i] != mb[i]:
                        diffs += 1
                        if len(offsets) < max_offsets:
                            offsets.append(offset + i)

            # remaining bytes (tail) in the longer buffer are differences
            if len(ba) != len(bb):
                tail_len = abs(len(ba) - len(bb))
                diffs += tail_len
                # record start of tail if we still can
                if len(offsets) < max_offsets:
                    offsets.append(offset + minlen)  # start offset of differing tail

            offset += max(len(ba), len(bb))

    return {
        "size_a": size_a,
        "size_b": size_b,
        "compared_bytes": min(size_a, size_b),
        "total_differences": diffs,
        "sample_offsets": offsets,
    }

def format_offsets(offsets):
    lines = []
    for off in offsets:
        if isinstance(off, int):
            lines.append(f"{off} (0x{off:X})")
        else:
            lines.append(str(off))
    return lines

def main():
    parser = argparse.ArgumentParser(description="Compare two files byte-by-byte.")
    parser.add_argument("fileA", help="First File")
    parser.add_argument("fileB", help="Second File")
    parser.add_argument("--max-offsets", type=int, default=1000, help="Max number of offset")
    parser.add_argument("--chunk-size", type=int, default=65536, help="chunl size")
    args = parser.parse_args()

    try:
        res = compare_files(args.fileA, args.fileB, args.max_offsets, args.chunk_size)
    except Exception as e:
        print("Erreur:", e, file=sys.stderr)
        sys.exit(2)

    print(f"Fichier A: {args.fileA} ({res['size_a']} octets)")
    print(f"Fichier B: {args.fileB} ({res['size_b']} octets)")
    print(f"Compared bytes (min): {res['compared_bytes']}")
    print(f"Total number of different bytes: {res['total_differences']}")
    if res["sample_offsets"]:
        print(f"First {len(res['sample_offsets'])} different offsets :")
        for s in format_offsets(res["sample_offsets"]):
            print("  ", s)
    else:
        print("No difference detected")

if __name__ == "__main__":
    main()