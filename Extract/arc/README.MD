# ARC Files in PSP Games

## Overview

`ARC` files are **archive containers** commonly used in PlayStation Portable (PSP) games to package multiple assets into a single file.
They function similarly to formats like `.pak`, `.dat`.

An ARC file typically stores game resources such as:

* Textures
* 3D models
* Animations
* Scripts
* Audio files
* UI assets
* Level data

The exact internal structure of an ARC file varies within 012, since `ARC` is a **generic extension rather than a standardized format**.

---

## Purpose

Game developers use ARC archives to:

* Reduce the number of files stored on the **UMD**
* Improve loading speed
* Simplify asset management
* Enable sequential streaming of resources

Instead of loading many individual files, the engine reads a single archive and retrieves assets using internal offsets.

---

## Typical File Structure

Although implementations vary, many ARC archives follow a structure similar to this:

```
Header
 ├─ Magic (sometimes "ARC", but not always)
 ├─ Version
 ├─ File count
 └─ Offset to file table

File Table
 ├─ Entry 0
 │   ├─ File name or hash
 │   ├─ Offset
 │   ├─ Size
 │   └─ Compression flag
 ├─ Entry 1
 └─ ...

File Data
 ├─ Asset block 0
 ├─ Asset block 1
 └─ ...
```

The **file table** describes where each internal file is located in the archive.

In some games:

* File names are stored directly
* File names are most of the time **hashed**
* Files are grouped by resource type

---

## Compression

ARC archives often store files in compressed form to save space.
Common compression methods include:

* **LZ77 / LZSS**
* **zlib**
* Custom compression algorithms

Some archives mix **compressed and uncompressed entries**, indicated by flags in the file table.

---

## Variants

Because `ARC` is a generic extension, many **different formats share the same name**.
Examples include:

* **Level archives**
* **Asset bundles**
* **Streaming containers**
* **Script packages**

Two ARC files may have **completely different layouts**.
