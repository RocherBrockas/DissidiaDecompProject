#!/usr/bin/env python3
"""
decrypt_messpak_v2.py — Déchiffreur complet de fichiers .mess_pak
==================================================================

Jeu testé : Dissidia 012 Final Fantasy (PSP)

Algorithme (MIPS 0x0887A778) :
  - XOR sur uint16, clé de 16 uint16 (32 bytes LE), index rotatif v0 & 0xF
  - v0 repart à 0 au début du pool global (offset 0x7EA)

Clé confirmée : AB90285E4284B132DA2D57A6BFC83300
                9A5727F24C4BA7367D929D73CE8498ED

Structure du pool déchiffré (0x7EA → fin) :
  Le pool contient en alternance :
  • Blocs TEXT  : séquences de chars UTF-16 lisibles (strings du jeu)
  • Blocs DATA  : tableaux uint16 non-texte (métadonnées, offsets, etc.)
  • Blocs CTRL  : codes de contrôle isolés (balises de style, boutons)
  • Blocs NULL  : séparateurs nuls

  Deux sous-types DATA observés :
    - "META" : blocs courts (~13 uint16) à valeurs stables et répétitives
               → probablement paramètres d'affichage (position, couleur...)
               → apparaissent systématiquement entre chaque string
    - "DATA" : grands blocs à valeurs aléatoires distribuées sur 0–65535
               → données non-texte (tables d'index, animations, etc.)

Fichiers générés :
  <nom>_strings.txt        Strings lisibles uniquement (format précédent)
  <nom>_strings.json       Strings lisibles en JSON
  <nom>_full_map.tsv       Cartographie complète : TOUS les blocs dans l'ordre
                           (strings + blocs DATA avec leurs uint16)
  <nom>_data_blocks.json   Blocs DATA seuls, avec offset, taille, valeurs uint16
  <nom>_pool_decrypted.bin Pool déchiffré brut (avec --raw)


Usage :
    python3 decrypt_messpak_v2.py <fichier.mess_pak> [options]

    --key HEXKEY   Clé XOR 256 bits (64 hex).
    --out DOSSIER  Dossier de sortie.
    --raw          Écrire le pool déchiffré brut (.bin).
    --min N        Longueur minimale d'un bloc texte (défaut : 3).
    --tags         Conserver les balises de contrôle brutes.
    --no-data      Ne pas écrire les fichiers de blocs DATA.
"""

"""
Pool layout:

[header]
[index table]
[encrypted UTF-16/data pool]

The encrypted pool starts at:
    idx_end = u32 @ 0x14

The XOR stream always restarts at v0 = 0
at the beginning of the encrypted pool.
"""

import sys, os, struct, json, argparse, csv

for s in (sys.stdout, sys.stderr):
    if hasattr(s, 'reconfigure') and s.encoding.lower() not in ('utf-8', 'utf-8-sig'):
        s.reconfigure(encoding='utf-8', errors='replace')

KEY_DEFAULT = bytes.fromhex(
    "AB90285E4284B132DA2D57A6BFC83300"
    "9A5727F24C4BA7367D929D73CE8498ED"
)

# ── Decypher XOR uint16 ──────────────────────────────────────────────────
def xor_decrypt_u16(data: bytes, key_u16: list, v0_start: int = 0) -> bytes:
    """
    Déchiffre `data` avec XOR uint16 rotatif.
    key_u16   : liste de 16 uint16 (32 bytes de clé interprétés en LE)
    v0_start  : valeur initiale du compteur (0 = début du pool global)
    """
    result = bytearray()
    v0 = v0_start
    for i in range(0, len(data) - 1, 2):
        word = struct.unpack_from('<H', data, i)[0]
        word ^= key_u16[v0 & 0xF]
        result += struct.pack('<H', word)
        v0 += 1
    if len(data) % 2:
        result.append(data[-1])
    return bytes(result)

# Clean character detection
def is_clean_char(c: str) -> bool:
    """
    True if this is a readable character.
    Includes :
      - Latin characters    (U+0020..U+024F)
      - Phonetics IPA     (U+0250..U+02FF)
      - Greek and more (U+0370..U+03FF)  ex: Ω Σ α β
      - End of line, JP space
    Excludes CJK, Hangul, PUA, surrogates, controle codes.
    """
    cp = ord(c)
    return (
        (0x0020 <= cp <= 0x024F)    # Latin 
        or (0x0250 <= cp <= 0x02FF) # phonetics
        or (0x0370 <= cp <= 0x03FF) # Greek
        or cp in (0x0A, 0x0D)       # \n \r
        or cp == 0x3000             # JP space
    ) and cp != 0xFFFD              # excludes U+FFFD

# DATA bloc classification
def classify_data_block(vals: list) -> str:
    """
    Classifies DATA uint16 in subcategories:

    "META"     : short blocs (~8-20 uint16) à majorité de hautes valeurs stables.
                 Observés systématiquement entre chaque string.
                 Hypothèse : paramètres d'affichage (position, couleur, timing).

    "OFFSETS"  : valeurs petites (< 5000) et majoritairement croissantes.
                 Tables d'index de strings.

    "DATA"     : tout le reste — grands blocs à valeurs distribuées sur 0-65535.
    """
    if not vals:
        return "DATA"
    n   = len(vals)
    mx  = max(vals)

    # Blocs courts à majorité de hautes valeurs → META
    if n <= 20 and mx > 30000:
        high = sum(1 for v in vals if v > 10000)
        if high / n > 0.5:
            return "META"

    # Petites valeurs croissantes → OFFSETS
    if mx < 5000 and n >= 2:
        incr = sum(1 for i in range(n - 1) if vals[i] <= vals[i + 1])
        if incr / (n - 1) > 0.8:
            return "OFFSETS"

    return "DATA"


# ── Segmentation complète du pool ─────────────────────────────────────────────
def segment_pool(pool: bytes, min_text_len: int = 3) -> list:
    """
    Segmente le pool déchiffré en blocs typés, dans l'ordre d'apparition.

    Chaque bloc est un dict :
      type        : "TEXT" | "DATA" | "CTRL" | "NULL"
      char_offset : position en chars UTF-16 depuis le début du pool
      byte_offset : position en bytes depuis le début du pool
      char_len    : longueur en chars
      byte_len    : longueur en bytes
      --- pour TEXT ---
      raw         : contenu str brut (inclut les balises inline \x10..\x1b)
      --- pour DATA / CTRL / NULL ---
      uint16_vals : liste des valeurs uint16 LE
      hex_vals    : "XXXX XXXX ..." (repr hex, pratique pour l'analyse)
      data_class  : "META" | "OFFSETS" | "DATA"  (DATA blocs seulement)

    Balises inline conservées dans les blocs TEXT :
      \x10 ... \x1b  balise de style ouverte/fermée (couleur, taille...)
      \x11 ... \x1b  variante balise (certains fichiers)
      \x1e XX      icône de bouton de manette
      \x3000         espace idéographique JP
      \n \r          retours à la ligne
    Ces codes n'interrompent PAS un bloc TEXT en cours.
    """
    try:
        text = pool.decode('utf-16-le', errors='replace')
    except Exception as e:
        raise RuntimeError(f"Décodage UTF-16 impossible : {e}")

    segments = []
    cur_type  = None
    cur_start = 0
    cur_chars = []

    def flush():
        nonlocal cur_type, cur_start, cur_chars
        if not cur_chars:
            return
        n        = len(cur_chars)
        byte_off = cur_start * 2
        seg = {
            'type':        cur_type,
            'char_offset': cur_start,
            'byte_offset': byte_off,
            'char_len':    n,
            'byte_len':    n * 2,
        }
        if cur_type == 'TEXT':
            seg['raw'] = ''.join(cur_chars)
        else:
            raw_bytes = pool[byte_off : byte_off + n * 2]
            nw        = len(raw_bytes) // 2
            vals      = list(struct.unpack_from(f'<{nw}H', raw_bytes)) if nw else []
            seg['uint16_vals'] = vals
            seg['hex_vals']    = ' '.join(f'{v:04X}' for v in vals)
            seg['data_class']  = classify_data_block(vals)

            # Parse mixed command/text streams
            parsed_tokens = parse_tag_stream(vals)

            seg['parsed_tokens'] = parsed_tokens
            seg['rendered'] = render_tokens(parsed_tokens)
        segments.append(seg)
        cur_chars = []

    in_tag   = False   # sommes-nous à l'intérieur d'une balise \x10..\x1b ?
    tag_depth = 0      # profondeur d'imbrication (rare mais possible)

    for i, c in enumerate(text):
        cp = ord(c)

        # ── Balises inline dans un TEXT en cours ────────────────────────────
        # \x10 / \x11 ouvrent une balise ; \x1b la ferme
        if in_tag:
            cur_chars.append(c)
            if cp == 0x1B:
                in_tag = False
            continue

        # \x1e = icône bouton (prend 1 char paramètre) → absorber si en TEXT
        if cp == 0x1E and cur_type == 'TEXT':
            cur_chars.append(c)
            continue

        # \x10 / \x11 inline dans un TEXT existant → démarrer une balise
        # MAIS \x11 suivi d'un seul char puis \x00 = séparateur de champ, pas balise
        if cp in (0x10, 0x11) and cur_type == 'TEXT':
            # Vérifier si c'est vraiment une balise \x10/\x11...\x1b
            # ou juste un séparateur de champ (\x11 + 1-2 chars + \x00)
            if cp == 0x10:
                # \x10 est toujours une balise de style
                in_tag = True
                cur_chars.append(c)
                continue
            else:
                # \x11 : vérifier si \x1b suit dans les 20 prochains chars
                has_close = any(ord(text[k]) == 0x1B
                                for k in range(i+1, min(i+20, len(text))))
                if has_close:
                    in_tag = True
                    cur_chars.append(c)
                    continue
                else:
                    # Séparateur de champ : absorber comme CTRL inline
                    cur_chars.append(c)
                    continue

        # \x1b orphelin → absorber si en TEXT
        if cp == 0x1B and cur_type == 'TEXT':
            cur_chars.append(c)
            continue

        # ── Classification normale ───────────────────────────────────────────
        if is_clean_char(c):
            t = 'TEXT'
        elif cp == 0x00:
            t = 'NULL'
        elif cp in (0x10, 0x11):
            t = 'CTRL'
        elif cp < 0x20:
            t = 'CTRL'
        else:
            t = 'DATA'

        if t != cur_type:
            # Texte trop court → reclasser en DATA avant le flush
            if cur_type == 'TEXT' and len(cur_chars) < min_text_len:
                cur_type = 'DATA'
                in_tag   = False
            flush()
            cur_type  = t
            cur_start = i

            # Si on commence un CTRL avec \x10 et que du texte lisible suit
            # après la balise fermante \x1b → démarrer un TEXT à la place
            if t == 'CTRL' and cp == 0x10:
                j = i + 1
                while j < len(text) and ord(text[j]) != 0x1B and j < i + 30:
                    j += 1
                peek = j + 1
                if peek < len(text) and is_clean_char(text[peek]):
                    cur_type = 'TEXT'
                    in_tag   = True
            # \x11 sans \x1b suivant = séparateur de champ, pas une vraie balise
            # Ne pas démarrer un TEXT depuis un \x11 isolé

        cur_chars.append(c)

    # Dernier bloc
    if cur_type == 'TEXT' and len(cur_chars) < min_text_len:
        cur_type = 'DATA'
    flush()

    return segments


def parse_tag_stream(vals):

    out = []
    i = 0

    while i < len(vals):

        v = vals[i]

        # --------------------------------------------------
        # COMMAND MODE
        # --------------------------------------------------
        if (
            v >= 0x8000
            or (v & 0xFF00) == 0xFF00
        ):
            cmd = [v]
            i += 1
            while i < len(vals):

                p = vals[i]
                # probable text
                if 0x20 <= p <= 0x024F:
                    break
                cmd.append(p)
                i += 1

            out.append({
                "type": "CMD",
                "values": cmd
            })

            continue

        # --------------------------------------------------
        # TEXT MODE
        # --------------------------------------------------

        txt = []
        while i < len(vals):
            v = vals[i]
            if (
                v >= 0x8000
                or (v & 0xFF00) == 0xFF00
            ):
                break

            txt.append(chr(v))
            i += 1

        out.append({
            "type": "TEXT",
            "text": "".join(txt)
        })

    return out

def render_tokens(tokens):

    out = []

    for t in tokens:

        if t["type"] == "TEXT":

            out.append(t["text"])

        elif t["type"] == "CMD":

            vals = " ".join(f"{x:04X}" for x in t["values"])

            out.append(f"<TAG:{vals}>")

    return "".join(out)


# ── Fusion des micro-blocs adjacents ──────────────────────────────────────────
def merge_adjacent(segments: list) -> list:
    """
    Fusionne les blocs adjacents de même type non-TEXT.
    Évite les milliers de micro-blocs DATA/NULL/CTRL séparés d'1 char.
    Les blocs TEXT restent individuels (chaque string reste séparée).
    """
    if not segments:
        return []
    out = [segments[0].copy()]
    for seg in segments[1:]:
        prev = out[-1]
        contiguous = (seg['char_offset'] == prev['char_offset'] + prev['char_len'])
        same_type  = (seg['type'] == prev['type'])
        if same_type and seg['type'] != 'TEXT' and contiguous:
            prev['char_len']    += seg['char_len']
            prev['byte_len']    += seg['byte_len']
            merged_vals          = prev['uint16_vals'] + seg['uint16_vals']
            prev['uint16_vals']  = merged_vals
            prev['hex_vals']     = ' '.join(f'{v:04X}' for v in merged_vals)
            prev['data_class']   = classify_data_block(merged_vals)
        else:
            out.append(seg.copy())
    return out


# ── Suppression des préfixes TYPE-ID ─────────────────────────────────────────
def strip_type_ids(segments: list) -> list:
    """
    Dans le format mess_pak, chaque enregistrement DATA se termine par un
    uint16 'TYPE-ID' qui identifie la string suivante. Cette valeur peut
    tomber accidentellement dans la plage ASCII (ex: 'c'=0x63, '/'=0x2F,
    '['=0x5B), ce qui la fait absorber comme premier char du bloc TEXT suivant.

    Ce post-traitement détecte et supprime ces préfixes :
    - Le bloc TEXT suit directement un bloc DATA (ou NULL+DATA)
    - Son premier char est ASCII ≤ 0x7F (plage type-ID observée)
    - Le char précédent dans le pool (dernier char du bloc DATA précédent)
      est hors-Latin (> 0x03FF) — confirme qu'on vient du DATA

    Le char retiré est ajouté à la fin du bloc DATA précédent.
    """
    result = list(segments)
    i = 0
    while i < len(result):
        seg = result[i]
        if seg['type'] != 'TEXT':
            i += 1
            continue
        raw = seg.get('raw', '')
        if not raw:
            i += 1
            continue

        first_cp = ord(raw[0])
        # Condition 1 : premier char est ASCII ≤ 0x7F
        if first_cp > 0x007F:
            i += 1
            continue

        # Condition 2 : trouver le bloc DATA/CTRL immédiatement avant
        prev_idx = i - 1
        while prev_idx >= 0 and result[prev_idx]['type'] in ('NULL', 'CTRL'):
            prev_idx -= 1

        if prev_idx < 0 or result[prev_idx]['type'] not in ('DATA',):
            i += 1
            continue

        prev_seg = result[prev_idx]
        prev_vals = prev_seg.get('uint16_vals', [])
        if not prev_vals:
            i += 1
            continue

        # Condition 3 : dernier uint16 du bloc DATA précédent est > 0x03FF
        # (confirme qu'on était bien en DATA non-Latin juste avant le type-ID)
        if prev_vals[-1] <= 0x03FF:
            i += 1
            continue

        # Toutes les conditions réunies → retirer le premier char du TEXT
        # et l'ajouter au bloc DATA précédent
        type_id_val = first_cp
        new_raw = raw[1:]

        # Mettre à jour le bloc DATA
        prev_seg['uint16_vals'] = prev_vals + [type_id_val]
        prev_seg['hex_vals']    = ' '.join(f'{v:04X}' for v in prev_seg['uint16_vals'])
        prev_seg['char_len']   += 1
        prev_seg['byte_len']   += 2
        prev_seg['data_class']  = classify_data_block(prev_seg['uint16_vals'])

        if new_raw:
            seg['raw']        = new_raw
            seg['char_len']  -= 1
            seg['byte_len']  -= 2
            seg['char_offset'] += 1
            seg['byte_offset'] += 2
        else:
            # La string était réduite à 1 char (le type-ID seul) → supprimer
            result.pop(i)
            continue

        i += 1
    return result


def clean_string(s: str, keep_tags: bool = False) -> str:
    """
    Remplace les codes de contrôle du jeu par des annotations lisibles.
    \x10...\x1b  → [TAG:...(contenu)...]
    \x1exXX     → [BTN]
    PUA          → supprimés
    """
    if keep_tags:
        return s
    out = []
    i = 0
    while i < len(s):
        c = s[i]
        cp = ord(c)
        if c == '\x10':
            end = s.find('\x1b', i + 1)
            if end == -1:
                out.append('[TAG]')
                break
            raw_tag = s[i + 1:end]

            # Convertir en uint16 pour inspection
            vals = [ord(x) for x in raw_tag]
            # Extraire uniquement les vrais morceaux texte
            text_parts = []
            current = []
            for v in vals:
                # ASCII/Latin lisible
                if 0x20 <= v <= 0x7E:
                    current.append(chr(v))
                else:
                    if len(current) >= 2:
                        text_parts.append(''.join(current))
                    current = []
            if len(current) >= 2:
                text_parts.append(''.join(current))
            if text_parts:
                out.append('[TAG:' + '|'.join(text_parts) + ']')
            else:
                out.append('[TAG]')
            i = end + 1
        elif c == '\x1e':
            # \x1e = icône bouton PSP ; le char suivant est l'ID du bouton
            btn_id = ord(s[i + 1]) if i + 1 < len(s) else 0
            out.append(f'[BTN:{btn_id:02X}]')
            i += 2
        elif c == '\x11':
            # \x11 = séparateur de champ (clé/valeur) ou variante balise
            out.append('[SEP]')
            i += 1
        elif c == '\x1b':
            i += 1
        elif c == '\x00':
            out.append(' ')
            i += 1
        elif cp < 0x20 and c not in ('\n', '\r', '\t'):
            out.append(f'[{cp:02X}]')
            i += 1
        elif 0xE000 <= cp <= 0xF8FF:
            i += 1  # PUA silencieux
        elif c == '\u3000':
            out.append(' ')
            i += 1
        else:
            out.append(c)
            i += 1
    return ''.join(out).strip()

# ── Parseur ───────────────────────────────────────────────────────────────────
class MessPakV2:
    MAGIC = b"mess pak"

    def __init__(self, path: str, key: bytes = KEY_DEFAULT):
        self.path    = path
        self.key     = key
        self.key_u16 = list(struct.unpack('<16H', key))
        with open(path, 'rb') as f:
            self.raw = f.read()
        if self.raw[:8] != self.MAGIC:
            raise ValueError(f"Magic invalide : {self.raw[:8]!r} (attendu b'mess pak')")
        self.version = struct.unpack_from('<H', self.raw, 0x08)[0]
        self.idx_end = struct.unpack_from('<I', self.raw, 0x14)[0]

    def decrypt_pool(self) -> bytes:
        """Déchiffre le pool global depuis idx_end."""
        return xor_decrypt_u16(self.raw[self.idx_end:], self.key_u16, v0_start=0)

    def extract_all(self, min_len: int = 3, keep_tags: bool = False,
                    strip_prefix: bool = False) -> dict:
        """
        Segmente et extrait le contenu complet du pool déchiffré.

        Retourne un dict :
          'segments'    : liste complète de tous les blocs dans l'ordre
                          (TEXT + DATA + CTRL + NULL fusionnés)
          'strings'     : liste des blocs TEXT uniquement
                          (chaque dict a en plus : 'index', 'clean')
          'data_blocks' : liste des blocs DATA/CTRL/NULL uniquement
                          (chaque dict a en plus : 'block_index')
        """
        pool     = self.decrypt_pool()
        raw_segs = segment_pool(pool, min_text_len=min_len)
        segments = merge_adjacent(raw_segs)

        strings     = []
        data_blocks = []
        str_idx     = 0
        blk_idx     = 0

        for seg in segments:
            if seg['type'] == 'TEXT':
                raw_str   = seg['raw']
                clean_str = clean_string(raw_str, keep_tags=keep_tags)
                if clean_str.strip():
                    seg['index'] = str_idx
                    seg['clean'] = clean_str
                    strings.append(seg)
                    str_idx += 1
            else:
                seg['block_index'] = blk_idx
                data_blocks.append(seg)
                blk_idx += 1

        return {
            'segments':    segments,
            'strings':     strings,
            'data_blocks': data_blocks,
        }

# ── Traitement d'un fichier ───────────────────────────────────────────────────
def process_file(path: str, key: bytes, out_dir: str, write_raw: bool,
                 min_len: int, keep_tags: bool, no_data: bool,
                 strip_prefix: bool):
    print(f"\n[*] Traitement : {path}")
    pak = MessPakV2(path, key)
    print(f"    Version  : {pak.version}")
    print(f"    Taille   : {len(pak.raw):,} bytes")
    print(f"    Index end: 0x{pak.idx_end:X}")
    print(f"    Pool start: 0x{pak.idx_end:X}")

    base = os.path.splitext(os.path.basename(path))[0]
    os.makedirs(out_dir, exist_ok=True)

    # ── Pool brut déchiffré ──
    if write_raw:
        pool    = pak.decrypt_pool()
        raw_out = os.path.join(out_dir, f"{base}_pool_decrypted.bin")
        with open(raw_out, 'wb') as f:
            f.write(pool)
        print(f"    Pool brut → {raw_out}")

    # ── Extraction complète ──
    result      = pak.extract_all(min_len=min_len, keep_tags=keep_tags,
                                   strip_prefix=strip_prefix)
    strings     = result['strings']
    data_blocks = result['data_blocks']
    segments    = result['segments']

    print(f"    Strings     : {len(strings)}")
    print(f"    Blocs DATA  : {len(data_blocks)}")
    print(f"      dont META   : {sum(1 for b in data_blocks if b.get('data_class')=='META')}")
    print(f"      dont OFFSETS: {sum(1 for b in data_blocks if b.get('data_class')=='OFFSETS')}")
    print(f"      dont DATA   : {sum(1 for b in data_blocks if b.get('data_class')=='DATA')}")

    # ── 1. Fichier texte strings (inchangé) ──
    txt_out = os.path.join(out_dir, f"{base}_strings.txt")
    with open(txt_out, 'w', encoding='utf-8-sig') as f:
        for s in strings:
            line = s['clean'].replace('\n', '\n         ')
            f.write(f"[{s['index']:04d}] {line}\n")
    print(f"    Strings TXT → {txt_out}")

    # ── 2. JSON strings (inchangé) ──
    json_out = os.path.join(out_dir, f"{base}_strings.json")
    with open(json_out, 'w', encoding='utf-8') as f:
        json.dump(
            {str(s['index']): s['clean'] for s in strings},
            f, ensure_ascii=False, indent=2
        )
    print(f"    Strings JSON→ {json_out}")

    if not no_data:
        # ── 3. Cartographie complète (TSV) ──
        # Colonnes : ordre | type | data_class | char_offset | byte_offset |
        #            char_len | uint16_count | content
        map_out = os.path.join(out_dir, f"{base}_full_map.tsv")
        with open(map_out, 'w', encoding='utf-8-sig', newline='') as f:
            w = csv.writer(f, delimiter='\t')
            w.writerow(['ordre', 'type', 'data_class', 'char_offset',
                        'byte_offset', 'char_len', 'uint16_count', 'content'])
            for order, seg in enumerate(segments):
                stype      = seg['type']
                data_class = seg.get('data_class', '')
                char_off   = seg['char_offset']
                byte_off   = seg['byte_offset']
                char_len   = seg['char_len']

                if stype == 'TEXT':
                    content    = seg.get('clean', seg.get('raw', ''))
                    content    = content.replace('\n', '\\n').replace('\t', '\\t')
                    uint16_cnt = char_len
                else:
                    vals       = seg.get('uint16_vals', [])
                    uint16_cnt = len(vals)
                    # Afficher les 16 premières valeurs hex, puis "..." si plus
                    preview = seg.get('rendered', '')
                    if not preview:
                        preview = ' '.join(f'{v:04X}' for v in vals[:16])
                    if len(vals) > 16:
                        preview += f' ... ({len(vals)} total)'
                    content = preview

                w.writerow([order, stype, data_class, char_off,
                            byte_off, char_len, uint16_cnt, content])
        print(f"    Full map TSV→ {map_out}")

        # ── 4. JSON blocs DATA ──
        data_json_out = os.path.join(out_dir, f"{base}_data_blocks.json")
        data_export = []
        for blk in data_blocks:
            entry = {
                'block_index': blk['block_index'],
                'type':        blk['type'],
                'data_class':  blk.get('data_class', ''),
                'char_offset': blk['char_offset'],
                'byte_offset': blk['byte_offset'],
                'char_len':    blk['char_len'],
                'uint16_count': len(blk.get('uint16_vals', [])),
                'uint16_vals': blk.get('uint16_vals', []),
                'hex_vals':    blk.get('hex_vals', ''),
            }
            # Ajouter le contexte : string précédente et suivante
            entry['prev_string'] = ''
            entry['next_string'] = ''
            data_export.append(entry)

        # Enrichir avec contexte (string avant/après chaque bloc DATA)
        seg_list = segments
        for i, seg in enumerate(seg_list):
            if seg['type'] != 'TEXT':
                continue
            clean = seg.get('clean', seg.get('raw', ''))[:80]
            # Chercher les blocs DATA juste avant et après
            for j in range(i - 1, -1, -1):
                if seg_list[j]['type'] != 'TEXT' and 'block_index' in seg_list[j]:
                    bi = seg_list[j]['block_index']
                    data_export[bi]['next_string'] = clean
                    break
            for j in range(i + 1, len(seg_list)):
                if seg_list[j]['type'] != 'TEXT' and 'block_index' in seg_list[j]:
                    bi = seg_list[j]['block_index']
                    data_export[bi]['prev_string'] = clean
                    break

        with open(data_json_out, 'w', encoding='utf-8') as f:
            json.dump(data_export, f, ensure_ascii=False, indent=2)
        print(f"    Data JSON   → {data_json_out}")

    # ── Aperçu console ──
    print("\n    === Aperçu strings (30 premières) ===")
    for s in strings[:30]:
        preview = s['clean'].replace('\n', ' / ')[:100]
        print(f"    [{s['index']:04d}] {preview}")


# ── CLI ───────────────────────────────────────────────────────────────────────
def parse_args():
    ap = argparse.ArgumentParser(
        description="Déchiffre les .mess_pak — XOR uint16, clé 256 bits"
    )
    ap.add_argument("files", nargs="+", help="Fichier(s) .mess_pak")
    ap.add_argument("--key",     default=None,
                    help="Clé hex 64 car. (32 bytes).")
    ap.add_argument("--out",     default=None,
                    help="Dossier de sortie.")
    ap.add_argument("--raw",     action="store_true",
                    help="Écrire le pool déchiffré brut (.bin).")
    ap.add_argument("--min",     type=int, default=3,
                    help="Longueur minimale d'un bloc texte (défaut : 3).")
    ap.add_argument("--tags",    action="store_true",
                    help="Conserver les balises de contrôle brutes.")
    ap.add_argument("--no-data", action="store_true",
                    help="Ne pas écrire les fichiers full_map.tsv et data_blocks.json.")
    ap.add_argument("--strip-prefix", action="store_true",
                    help="Supprimer les TYPE-ID en tête de strings (caractères "
                         "parasites comme 'c', '/', '[' venant du bloc DATA précédent). "
                         "Activer quand la structure META des blocs est confirmée.")
    return ap.parse_args()

def main():
    args = parse_args()
    key = KEY_DEFAULT
    if args.key:
        raw_key = args.key.replace(" ", "").replace(":", "")
        if len(raw_key) != 64:
            print(f"Erreur : clé = 64 car. hex (32 bytes), reçu {len(raw_key)}.",
                  file=sys.stderr)
            sys.exit(1)
        key = bytes.fromhex(raw_key)

    for path in args.files:
        out_dir = args.out or os.path.dirname(os.path.abspath(path))
        try:
            process_file(path, key, out_dir, args.raw, args.min, args.tags,
                         getattr(args, 'no_data', False),
                         getattr(args, 'strip_prefix', False))
        except Exception as e:
            import traceback
            print(f"[!] Erreur sur {path} : {e}", file=sys.stderr)
            traceback.print_exc()

if __name__ == "__main__":
    main()
