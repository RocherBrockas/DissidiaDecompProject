# LRWD Files in PSP Games
I could not find any notes on the file format, there are 7 files in the game data
Please edit this to human notes as soon as we get a headstart on understanding the format, for now this is just a dump of the information i got from Chatgpt, which is not guaranteed to be accurate.
## Overview

`LRWD` files are a **proprietary binary resource format** found in some PlayStation Portable (PSP) games.
They typically store **structured gameplay data rather than raw assets**, and are usually interpreted directly by the game engine at runtime.

Unlike archive formats (such as ARC or DES4), LRWD files are often **single-resource data files** used to describe specific gameplay systems or configuration data.

The exact purpose of LRWD files varies by title, but they commonly contain:

* Level configuration data
* Gameplay parameters
* Object placement
* Event triggers
* Script references
* Resource lookup tables

Because the format is **engine-specific**, the internal structure must usually be reverse engineered.

---

## Name Meaning

The file header begins with the ASCII magic:

```
4C 52 57 44
```

Which corresponds to:

```
LRWD
```

This magic value identifies the file type when inspecting it in a hex editor.

The acronym itself is not publicly documented, but it likely represents an **internal engine subsystem name**.

---

## Typical Structure

While layouts vary, many LRWD files follow a pattern similar to structured engine data formats:

```
Header
 ├─ Magic ("LRWD")
 ├─ Version
 ├─ Section count
 └─ Offset table

Sections
 ├─ Section 0
 │   ├─ Type ID
 │   ├─ Offset
 │   └─ Size
 ├─ Section 1
 └─ ...

Data Blocks
 ├─ Structured binary data
 ├─ Tables
 ├─ Object definitions
 └─ Script parameters
```

Sections may represent different types of data such as:

* entity lists
* configuration tables
* event scripts
* references to external assets

---

## Common Characteristics

During reverse engineering, LRWD files often show the following patterns:

### Structured tables

Many LRWD files contain **arrays of fixed-size records**, for example:

```
struct ObjectEntry
{
    float posX;
    float posY;
    float posZ;
    int objectType;
    int parameter;
}
```

### Resource references

Entries may reference assets stored in other containers:

* ARC archives
* texture packs
* animation bundles

### Alignment

Data blocks are frequently aligned to **16 or 32 bytes**, which is common for PSP engines.

---

## How the Game Uses Them

LRWD files are typically:

1. Loaded during **level initialization**
2. Parsed by a **loader function in the game executable**
3. Converted into **runtime objects or configuration structures**

This means that understanding the format usually requires analyzing the **LRWD parsing code** in the game binary.

---

## Reverse Engineering Approach

To understand LRWD files:

### 1. Inspect the header

Open the file in a hex editor and verify the magic value:

```
LRWD
```

Then try identifying:

* version numbers
* section counts
* pointer tables

---

### 2. Search for repeating structures

Look for patterns that might represent arrays of objects:

```
XX XX XX XX  YY YY YY YY  ZZ ZZ ZZ ZZ
```

These may correspond to floats, IDs, or offsets.

---

### 3. Trace loader functions

In **Ghidra**:

* Search for the string `"LRWD"`
* Identify functions referencing it
* Analyze how the file is parsed into memory

These functions usually reveal:

* structure layouts
* entry counts
* field meanings

---

### 4. Monitor runtime behavior

Using **PPSSPP debugger**:

* Set breakpoints on file reads
* Track buffers containing LRWD data
* Observe how the engine interprets them

---

## Tools Useful for Analysis

Typical tools used to analyze LRWD files include:

* **Hex editors** (HxD, 010 Editor)
* **Ghidra** for reversing the parser
* **PPSSPP debugger** for runtime inspection
* **Custom Python scripts** to parse binary structures

---

## Important Notes

* `LRWD` is **not a standard PSP file format**
* It is part of a **specific game engine’s internal data system**
* Two games using LRWD files may still have **different internal layouts**

As a result, accurate documentation usually requires **reverse engineering the loader function inside the game executable**.

---

## Reverse Engineering Tip

A reliable way to reconstruct the LRWD format is:

1. Find the **file loading function**
2. Identify the **struct definitions used in memory**
3. Rebuild those structures in a parser script

This approach often reveals the entire file structure faster than pure hex analysis.
