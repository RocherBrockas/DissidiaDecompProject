# DES4 Files in PSP Games

## Overview

`DES4` is a container file format used in some **PlayStation Portable (PSP)** games to store packaged game resources.
The exact contents depend on the game engine used by the game.

---

## Name Meaning

The name **DES4** comes from the **magic number** found at the beginning of the file:

```
44 45 53 34
```

Which corresponds to the ASCII string:

```
DES4
```

This header identifies the file as belonging to the DES4 archive format.

---

## Typical File Structure

While implementations vary slightly between games, a DES4 file generally follows this structure:
Identification of the DES4 file format for 012 is yet to be done but research usually leads to structures similar to the following:

```
Header
 ├─ Magic ("DES4")
 ├─ Version / flags
 ├─ File count
 └─ Offset to file table

File Table
 ├─ Entry 0
 │   ├─ File name / hash
 │   ├─ Offset
 │   ├─ Size
 │   └─ Compression flag
 ├─ Entry 1
 └─ ...

File Data
 ├─ Raw or compressed file blocks
 ├─ Asset data
 └─ Resource streams
```

Each entry in the **file table** points to a specific resource stored later in the archive.

---

## Compression

Many DES4 archives store their internal files using compression such as:

* **LZ77 / LZSS variants**
* **zlib**
* Custom game-specific compression

Because of this, extracting the archive may require an additional decompression step after unpacking.

---

## How They Are Used

In PSP games, DES4 archives help:

* Reduce the number of files on the UMD
* Improve loading performance
* Group related resources together
* Allow streaming of large asset groups

Games typically load the archive into memory and access resources through offsets rather than individual files.

---
