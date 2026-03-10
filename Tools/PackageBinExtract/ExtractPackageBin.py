import struct
import os
import re

INFO_FILE = "package_info.bin"
PKG_FILE = "package.bin"

HEADER_SIZE = 0x10
ENTRY_SIZE  = 12
FILE_COUNT  = 11043

SECTOR_SIZE = 0x800

# Signatures known (3-4 bytes ASCII)
KNOWN_4_ASCII = {
    "acmd", "arc", "at3", "bin", "des4", "seq", "tpmc",
    "vold", "sdcv", "lrwd", "tim2", "clsm", "dpc", "gim","ptbl",
    "gmo", "mlng", "mpk", "sscf", "riff", "dec", "dpr", "drr", "due", "dur", "exsw", "kpsh", "mig", "omg", "ptbl", "smsc", "srmc", "srsc", "wlcn"
}

# 8-byte keys for menu/mess pak
MENU_KEYS = ("menu",)
MESS_KEYS = ("mess",)

PNG_SIG = b"\x89PNG\r\n\x1a\n"

def ensure_dir(path):
    os.makedirs(path, exist_ok=True)

def unique_path(path: str) -> str:
    if not os.path.exists(path):
        return path
    base, ext = os.path.splitext(path)
    i = 1
    while True:
        candidate = f"{base}_{i}{ext}"
        if not os.path.exists(candidate):
            return candidate
        i += 1

discovered_dynamic = set()
type_counts = {}

def detect_type(data: bytes) -> str:
    if not data:
        return "empty"

    hdr8 = data[:8]
    hdr4 = data[:4]

    # PNG
    if hdr8.startswith(PNG_SIG):
        return "png"

    # 8-byte ascii check (menu/mess pak mostly)
    try:
        a8 = hdr8.decode("ascii", errors="ignore").lower()
    except Exception:
        a8 = ""
    if any(a8.startswith(k) for k in MENU_KEYS):
        return "menu_pak"
    if any(a8.startswith(k) for k in MESS_KEYS):
        return "mess_pak"

    if len(hdr4) >= 3:
        try:
            prefix3 = hdr4[:3].decode("ascii", errors="ignore").lower()
        except Exception:
            prefix3 = ""
        if prefix3 and prefix3 in KNOWN_4_ASCII:
            return prefix3

    try:
        raw4 = ''.join(chr(b) for b in hdr4)
    except Exception:
        raw4 = ""
    candidate = raw4.rstrip('\x00 ').strip().lower()

    if 3 <= len(candidate) <= 4 and all(32 <= ord(c) < 127 for c in candidate):
        if candidate not in KNOWN_4_ASCII:
            discovered_dynamic.add(candidate)
        return candidate

    # 4 premiers octets non nuls -> .dat
    if len(hdr4) == 4 and all(b != 0x00 for b in hdr4):
        return "dat"

    # fallback binaire
    return "bin"

def sanitize_component(s: str) -> str:
    """Sanitize folder/extension component: remove unsafe chars, trim, lower-case."""
    if s is None:
        return "bin"
    s = str(s).strip()
    # remove trailing dots/spaces (Windows bad), replace other invalid chars with underscore
    s = s.rstrip(' .')
    s = re.sub(r'[^A-Za-z0-9_.-]+', '_', s)
    if not s:
        return "bin"
    return s.lower()

def write_extracted(hashv: int, ftype: str, data: bytes):
    # sanitize type to a safe folder/extension name
    ext = sanitize_component(ftype)
    out_dir = os.path.join("extract", ext)
    ensure_dir(out_dir)
    name = f"{hashv:08X}.{ext}"
    out_path = os.path.join(out_dir, name)
    out_path = unique_path(out_path)
    with open(out_path, "wb") as f:
        f.write(data)
    type_counts[ext] = type_counts.get(ext, 0) + 1
    return out_path

def main():
    ensure_dir("extract")
    with open(INFO_FILE, "rb") as info, open(PKG_FILE, "rb") as pkg:
        info.seek(HEADER_SIZE)

        for i in range(FILE_COUNT):
            entry = info.read(ENTRY_SIZE)
            if len(entry) < ENTRY_SIZE:
                print(f"[INFO] fin anticipee: entree incomplete a l'index {i}")
                break

            hashv, offset, size_flags = struct.unpack("<III", entry)
            size = size_flags & 0x0FFFFFFF
            if size == 0:
                continue

            real_offset = offset * SECTOR_SIZE
            pkg.seek(real_offset)
            data = pkg.read(size)

            if len(data) != size:
                print(f"[WARN] taille lue != taille declaree id={hashv:08X} index={i} declared={size} read={len(data)} offset=0x{real_offset:X}")

            ftype = detect_type(data)
            path = write_extracted(hashv, ftype, data)
            print(f"[EXTRACT] id={hashv:08X} type={ftype} -> {path}")

    print("Extraction terminee")
    print("Stats par type:", type_counts)
    if discovered_dynamic:
        print("Nouveaux types ASCII decouverts:", ", ".join(sorted(discovered_dynamic)))

if __name__ == "__main__":
    main()