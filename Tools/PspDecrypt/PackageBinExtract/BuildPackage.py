#!/usr/bin/env python3
import os
import struct
import math
import re
import argparse

EXTRACT_DIR = "extract"
OUT_PKG = "package.bin"
OUT_INFO = "package_info.bin"

HEADER_SIZE = 0x10
SECTOR_SIZE = 0x800
ENTRY_FMT = "<III"  # hash, offset (in sectors), size_flags
ENTRY_SIZE = 12
MAX_SIZE_MASK = 0x0FFFFFFF

HEXNAME_RE = re.compile(r"^([0-9A-Fa-f]{8})\.")

def find_extracted_file(root, hashv):
    hex8 = f"{hashv:08X}".lower()
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            if fn.lower().startswith(hex8 + "."):
                return os.path.join(dirpath, fn)
    return None

def read_template_info(path):
    entries = []
    with open(path, "rb") as f:
        header = f.read(HEADER_SIZE)
        idx = 0
        while True:
            chunk = f.read(ENTRY_SIZE)
            if not chunk or len(chunk) < ENTRY_SIZE:
                break
            hashv, offset_sector, size_flags = struct.unpack(ENTRY_FMT, chunk)
            entries.append({"hash": hashv, "offset_sector": offset_sector, "size_flags": size_flags, "index": idx})
            idx += 1
    return header, entries

def collect_files_relayout(root):
    entries = []
    for dirpath, _, filenames in os.walk(root):
        for fn in filenames:
            m = HEXNAME_RE.match(fn)
            if not m:
                continue
            hash_hex = m.group(1)
            hashv = int(hash_hex, 16)
            full = os.path.join(dirpath, fn)
            size = os.path.getsize(full)
            entries.append({"hash": hashv, "path": full, "size": size})
    entries.sort(key=lambda e: e["hash"])
    return entries

def build_using_template(extract_root, template_info_path, template_pkg_path, out_pkg_path, out_info_path, sector_size=SECTOR_SIZE):
    header, tmpl_entries = read_template_info(template_info_path)
    # open streams
    tpl_pkg = None
    if template_pkg_path and os.path.isfile(template_pkg_path):
        tpl_pkg = open(template_pkg_path, "rb")
    with open(out_pkg_path, "wb") as out_pkg:
        # ensure output length at least 0
        info_out_entries = []
        for i, ent in enumerate(tmpl_entries):
            hashv = ent["hash"]
            offset_sector = ent["offset_sector"]
            orig_size_flags = ent["size_flags"]
            orig_size = orig_size_flags & MAX_SIZE_MASK
            sectors_alloc = math.ceil(orig_size / sector_size) if orig_size > 0 else 0
            max_bytes = sectors_alloc * sector_size

            write_pos = offset_sector * sector_size
            out_pkg.seek(write_pos)
            found = find_extracted_file(extract_root, hashv)
            if found:
                new_size = os.path.getsize(found)
                if new_size > max_bytes:
                    raise RuntimeError(
                        f"File {found} (size={new_size}) gpes pver allocated size ({max_bytes}) for hash 0{hashv:08X}. "
                        "either up the allocation in the template or relayout."
                    )
                # write file content
                with open(found, "rb") as fin:
                    out_pkg.write(fin.read())
                # pad remaining bytes of allocated area with zeros
                if max_bytes > new_size:
                    out_pkg.write(b"\x00" * (max_bytes - new_size))
                size_flags = (orig_size_flags & ~MAX_SIZE_MASK) | (new_size & MAX_SIZE_MASK)
            else:
                # no extracted file: try to copy from template package if available, else zero-fill original allocation
                if tpl_pkg:
                    tpl_pkg.seek(write_pos)
                    to_copy = tpl_pkg.read(max_bytes)
                    out_pkg.write(to_copy)
                else:
                    out_pkg.write(b"\x00" * max_bytes)
                size_flags = orig_size_flags  # preserve as-is

            info_out_entries.append((hashv & 0xFFFFFFFF, offset_sector & 0xFFFFFFFF, size_flags & 0xFFFFFFFF))

        # flush and close
        out_pkg.flush()
    if tpl_pkg:
        tpl_pkg.close()
    # write info file using original header
    with open(out_info_path, "wb") as infof:
        infof.write(header if header else (b"\x00" * HEADER_SIZE))
        for h, off, sf in info_out_entries:
            infof.write(struct.pack(ENTRY_FMT, h, off, sf))
    return len(info_out_entries)

def build_relayout(extract_root, out_pkg_path, out_info_path, sector_size=SECTOR_SIZE):
    files = collect_files_relayout(extract_root)
    if not files:
        return 0
    current_sector = 0
    info_entries = []
    with open(out_pkg_path, "wb") as out_pkg:
        for fi in files:
            hashv = fi["hash"]
            path = fi["path"]
            size = fi["size"]
            sectors_needed = math.ceil(size / sector_size) if size > 0 else 0
            offset_sector = current_sector
            write_pos = offset_sector * sector_size
            out_pkg.seek(write_pos)
            with open(path, "rb") as f:
                out_pkg.write(f.read())
            # pad to full sectors
            if sectors_needed > 0:
                end_pos = write_pos + sectors_needed * sector_size
                out_pkg.seek(end_pos - 1)
                out_pkg.write(b"\x00")
            size_flags = size & MAX_SIZE_MASK
            info_entries.append((hashv & 0xFFFFFFFF, offset_sector & 0xFFFFFFFF, size_flags & 0xFFFFFFFF))
            current_sector = offset_sector + sectors_needed
        out_pkg.flush()
    # header zeros
    with open(out_info_path, "wb") as infof:
        infof.write(b"\x00" * HEADER_SIZE)
        for h, off, sf in info_entries:
            infof.write(struct.pack(ENTRY_FMT, h, off, sf))
    return len(info_entries)

def main():
    parser = argparse.ArgumentParser(description="Rebuild package.bin from extract/ preserving template layout when possible.")
    parser.add_argument("--extract", default=EXTRACT_DIR, help="Directory containing the file to repack")
    parser.add_argument("--out-pkg", default=OUT_PKG, help="Package file name to generate")
    parser.add_argument("--out-info", default=OUT_INFO, help="package_info file name to generate")
    parser.add_argument("--template-info", help="(optionnel) template package_info.bin to use to preserve ordre/offsets")
    parser.add_argument("--template-pkg", help="(optionnel) template package.bin to use to check for missing regions")
    parser.add_argument("--sector-size", type=int, default=SECTOR_SIZE, help="Taille du secteur (default 0x800)")
    args = parser.parse_args()

    if not os.path.isdir(args.extract):
        print(f"Error: file '{args.extract}' unreachable.")
        return

    if args.template_info and os.path.isfile(args.template_info):
        try:
            n = build_using_template(args.extract, args.template_info, args.template_pkg, args.out_pkg, args.out_info, args.sector_size)
            print(f"Rebuilt {n} entries preserving the order of the template.")
        except Exception as e:
            print("Error doing rebuild with template:", e)
            return
    else:
        n = build_relayout(args.extract, args.out_pkg, args.out_info, args.sector_size)
        print(f"Rebuilt {n} entries with relayout (new offsets).")

    print("Done.")

if __name__ == "__main__":
    main()