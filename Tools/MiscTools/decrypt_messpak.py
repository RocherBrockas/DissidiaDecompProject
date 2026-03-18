#!/usr/bin/env python3
"""
Déchiffreur de fichiers .mess_pak
==================================
Schéma : XOR rotatif 256 bits (32 bytes de clé)
Clé     : adresse 0x089D68AA dans l'ISO/exécutable du jeu
Algo    : adresse 0x0887A6A0 dans l'ISO/exécutable du jeu

Structure du fichier mess_pak
------------------------------
Offset  Taille  Description
0x00       8    Magic "mess pak"
0x08       2    Version (0x01)
0x0A       2    Nombre de sections (ex. 0x02)
0x0C       4    Réservé (0x00)
0x10       4    Offset début de l'index   (= 0x20)
0x14       4    Offset fin de l'index     (= début des données chiffrées)
0x18       4    Offset fin section 0
0x1C       4    Offset fin section 1 (fin du fichier si 2 sections)
0x20    variable  Table d'index (uint16 LE) — non chiffrée
                  Format : paires (offset_debut, offset_fin) en char UTF-16
                  => 2 * N + 2 entrées pour N chaînes par section
[0x14]  variable  Table d'offsets section 0 (uint16 LE) — non chiffrée
                  Longueur = (0x18 - 0x14) bytes
[0x18]  variable  Table d'offsets section 1 (uint16 LE) — non chiffrée (*)
                  (*) En pratique la 2e moitié peut être chiffrée selon le jeu
[sec_end] fin    Pool de chaînes UTF-16 LE — CHIFFRÉ avec XOR rotatif
                  Le compteur de clé repart à 0 au début de ce bloc.

Utilisation
-----------
    python3 decrypt_messpak.py <fichier.mess_pak> [--key HEXKEY] [--out DOSSIER]

    --key   : 32 octets en hexadécimal (64 car. sans espaces)
              Défaut : clé extraite de l'ISO (voir KEY_DEFAULT ci-dessous)
    --out   : dossier de sortie (défaut : même dossier que le fichier source)

Exemple
-------
    python3 decrypt_messpak.py 1CB50F3D.mess_pak --out ./strings/

Sortie
------
  <nom>_decrypted.bin   : pool de chaînes déchiffré (UTF-16 LE brut)
  <nom>_strings.txt     : toutes les chaînes extraites, une par ligne
  <nom>_strings.json    : dictionnaire {index: chaine}
"""

import sys
import os
import struct
import json
import argparse

# Force UTF-8 sur stdout/stderr (Windows cp1252 -> problème avec caractères spéciaux)
if sys.stdout.encoding and sys.stdout.encoding.lower() not in ('utf-8', 'utf-8-sig'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
if sys.stderr.encoding and sys.stderr.encoding.lower() not in ('utf-8', 'utf-8-sig'):
    sys.stderr.reconfigure(encoding='utf-8', errors='replace')

# ── Clé par défaut (32 premiers octets à 0x089D68AA dans l'ISO) ──────────────
KEY_DEFAULT = bytes.fromhex(
    "3F1C012701C011F2F8C11678B9AD0A30"
    "D5EBFF5FF7FA7D39F75BE056701A2B1F"
)


# ── XOR rotatif ───────────────────────────────────────────────────────────────

def xor_decrypt(data: bytes, key: bytes, key_offset: int = 0) -> bytes:
    """
    Déchiffre `data` avec XOR rotatif.
    key_offset : position de départ dans la clé (pour reprendre un flux continu).
    """
    key_len = len(key)
    return bytes(b ^ key[(i + key_offset) % key_len] for i, b in enumerate(data))


# ── Parseur du fichier ────────────────────────────────────────────────────────

class MessPak:
    MAGIC = b"mess pak"

    def __init__(self, path: str, key: bytes = KEY_DEFAULT):
        self.path = path
        self.key  = key
        with open(path, "rb") as f:
            self.raw = f.read()
        self._parse_header()

    def _parse_header(self):
        raw = self.raw
        if raw[:8] != self.MAGIC:
            raise ValueError(f"Magic invalide : {raw[:8]!r} (attendu b'mess pak')")

        self.version      = struct.unpack_from("<H", raw, 0x08)[0]
        self.num_sections = struct.unpack_from("<H", raw, 0x0A)[0]
        self.index_start  = struct.unpack_from("<I", raw, 0x10)[0]   # 0x20
        self.index_end    = struct.unpack_from("<I", raw, 0x14)[0]   # fin index = début données
        self.section_ends = []
        for i in range(self.num_sections):
            off = struct.unpack_from("<I", raw, 0x18 + i * 4)[0]
            self.section_ends.append(off)

        # L'index (uint16 LE) contient N+1 offsets par section => N chaînes
        n_index_entries = (self.index_end - self.index_start) // 2
        self.index = list(struct.unpack_from(f"<{n_index_entries}H", raw, self.index_start))

        # Sections de données chiffrées
        prev = self.index_end
        self.sections_raw = []
        for end in self.section_ends:
            self.sections_raw.append(raw[prev:end])
            prev = end
        # Données après la dernière section déclarée (section supplémentaire)
        if prev < len(raw):
            self.sections_raw.append(raw[prev:])

    # ── Déchiffrement du pool de chaînes ──────────────────────────────────────

    def decrypt_string_pool(self, section_idx: int = -1) -> bytes:
        """
        Déchiffre le pool de chaînes (dernière section = le gros bloc UTF-16).
        Par défaut on prend la dernière section (la plus grande).
        """
        pool_raw = self.sections_raw[section_idx]
        return xor_decrypt(pool_raw, self.key, key_offset=0)

    # ── Extraction des offsets de chaînes ─────────────────────────────────────

    def _get_offsets(self, section_idx: int) -> list:
        """
        Retourne la liste des offsets (en chars UTF-16) pour la section donnée.
        Les offsets sont lus depuis la table d'index (non chiffrée).
        """
        # On regroupe l'index en blocs par section.
        # Heuristique : les offsets d'une section sont croissants jusqu'au prochain saut.
        all_offsets = self.index
        # Trouver les groupes croissants
        groups = []
        current = []
        for v in all_offsets:
            if current and v < current[-1]:
                if len(current) > 1:
                    groups.append(current)
                current = [v]
            else:
                current.append(v)
        if len(current) > 1:
            groups.append(current)

        if section_idx < len(groups):
            return groups[section_idx]
        return []

    # ── Extraction des chaînes ────────────────────────────────────────────────

    def extract_strings(self, section_idx: int = 0) -> dict:
        """
        Retourne un dictionnaire {index_chaine: texte_unicode} pour la section donnée.
        """
        offsets = self._get_offsets(section_idx)
        pool    = self.decrypt_string_pool(section_idx=-1)

        strings = {}
        for i in range(len(offsets) - 1):
            start_char = offsets[i]
            end_char   = offsets[i + 1]
            start_byte = start_char * 2
            end_byte   = end_char   * 2
            chunk = pool[start_byte:end_byte]
            try:
                text = chunk.decode("utf-16-le", errors="replace").rstrip("\x00")
            except Exception:
                text = chunk.hex()
            strings[i] = text
        return strings

    def extract_all_strings(self) -> dict:
        """Extrait toutes les sections et retourne un dict plat {global_idx: texte}."""
        result = {}
        idx_base = 0
        for sec in range(self.num_sections):
            sec_strings = self.extract_strings(sec)
            for k, v in sec_strings.items():
                result[idx_base + k] = v
            idx_base += len(sec_strings)
        return result


# ── Interface en ligne de commande ────────────────────────────────────────────

def parse_args():
    ap = argparse.ArgumentParser(
        description="Déchiffre les fichiers .mess_pak (XOR rotatif 256 bits)"
    )
    ap.add_argument("files", nargs="+", help="Fichier(s) .mess_pak à déchiffrer")
    ap.add_argument(
        "--key",
        default=None,
        help="Clé XOR 256 bits en hex (64 caractères). "
             "Défaut : clé extraite de l'ISO (0x089D68AA).",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="Dossier de sortie. Défaut : même dossier que l'entrée.",
    )
    ap.add_argument(
        "--raw",
        action="store_true",
        help="Écrire aussi le pool de chaînes déchiffré brut (.bin).",
    )
    return ap.parse_args()


def process_file(path: str, key: bytes, out_dir: str, write_raw: bool):
    print(f"\n[*] Traitement : {path}")
    pak = MessPak(path, key)
    print(f"    Version      : {pak.version}")
    print(f"    Sections     : {pak.num_sections}")
    print(f"    Entrées index: {len(pak.index)}")

    base = os.path.splitext(os.path.basename(path))[0]
    os.makedirs(out_dir, exist_ok=True)

    # Pool brut déchiffré
    if write_raw:
        raw_out = os.path.join(out_dir, f"{base}_decrypted.bin")
        pool = pak.decrypt_string_pool()
        with open(raw_out, "wb") as f:
            f.write(pool)
        print(f"    Pool brut    → {raw_out}")

    # Chaînes texte
    strings = pak.extract_all_strings()
    print(f"    Chaînes      : {len(strings)}")

    txt_out  = os.path.join(out_dir, f"{base}_strings.txt")
    json_out = os.path.join(out_dir, f"{base}_strings.json")

    with open(txt_out, "w", encoding="utf-8-sig") as f:  # utf-8-sig = BOM, lisible par Notepad Windows
        for idx, text in sorted(strings.items()):
            f.write(f"[{idx:04d}] {text}\n")
    print(f"    Texte        → {txt_out}")

    with open(json_out, "w", encoding="utf-8") as f:
        json.dump({str(k): v for k, v in sorted(strings.items())},
                  f, ensure_ascii=False, indent=2)
    print(f"    JSON         → {json_out}")


def main():
    args = parse_args()

    key = KEY_DEFAULT
    if args.key:
        raw_key = args.key.replace(" ", "").replace(":", "")
        if len(raw_key) != 64:
            print(f"Erreur : la clé doit faire 64 caractères hex (32 octets), "
                  f"reçu {len(raw_key)} car.", file=sys.stderr)
            sys.exit(1)
        key = bytes.fromhex(raw_key)

    for path in args.files:
        out_dir = args.out or os.path.dirname(os.path.abspath(path))
        try:
            process_file(path, key, out_dir, args.raw)
        except Exception as e:
            print(f"[!] Erreur sur {path} : {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
