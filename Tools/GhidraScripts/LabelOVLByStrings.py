#Label functions in PSP OVL files using C++ class/function name strings found in the binary.
#For OVL overlay files that have no sceModuleInfo or ELF symbol table,
#this script finds string literals (class names, method names, constants)
#and creates Ghidra labels at every location that references them,
#helping to identify functions by the strings they use.
#@author Dissidia Decompilation Project
#@category Analysis

from ghidra.program.model.symbol import SourceType
from ghidra.app.cmd.function import DeleteFunctionCmd
import re

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Minimum string length to consider (shorter = more false positives)
MIN_STRING_LEN = 6

# Only keep strings that look like C++ identifiers:
# - contain '::' (method names)   e.g. BOJ_CAMERA_MANAGER::ExecTask
# - OR start with uppercase and contain '_' (constants/class names) e.g. PTC_BLIND
# Set to False to label all strings found (much noisier)
FILTER_CPP_IDENTIFIERS = True

# If True, also create a function at the referencing address when none exists
CREATE_FUNCTIONS = True

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def looks_like_identifier(s):
    """Return True if the string looks like a C++ class/method/constant name."""
    if '::' in s:
        return True
    if s[0].isupper() and '_' in s:
        return True
    return False

def safe_label(name):
    """Sanitize a string so it can be used as a Ghidra label."""
    # Replace characters that Ghidra does not allow in labels
    return re.sub(r'[^A-Za-z0-9_]', '_', name)

def find_string_addrs(program, min_len):
    """
    Scan the loaded memory for null-terminated ASCII strings of at least min_len
    printable characters. Returns a list of (Address, str) tuples.
    """
    results = []
    mem = program.getMemory()

    for block in mem.getBlocks():
        # Skip Ghidra-internal ELF metadata blocks
        if block.getName().startswith('_') or block.getName().startswith('.shstrtab'):
            continue
        if not block.isInitialized():
            continue

        start  = block.getStart()
        length = block.getSize()
        data   = block.getData()  # InputStream over block bytes

        buf        = []
        buf_start  = None

        for i in range(length):
            b = data.read() & 0xFF
            if 0x20 <= b <= 0x7E:
                if buf_start is None:
                    buf_start = start.add(i)
                buf.append(chr(b))
            else:
                if b == 0 and buf_start is not None and len(buf) >= min_len:
                    s = ''.join(buf)
                    if not FILTER_CPP_IDENTIFIERS or looks_like_identifier(s):
                        results.append((buf_start, s))
                buf = []
                buf_start = None

    return results

def find_references(program, string_addr):
    """Return all addresses in the program that contain a pointer to string_addr."""
    ref_mgr = program.getReferenceManager()
    refs = ref_mgr.getReferencesTo(string_addr)
    return [r.getFromAddress() for r in refs]

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    program  = currentProgram
    listing  = program.getListing()
    sym_tbl  = program.getSymbolTable()
    ref_mgr  = program.getReferenceManager()

    print("=== LabelOVLByStrings ===")
    print("Scanning for strings (min_len={}, filter_cpp={})...".format(
        MIN_STRING_LEN, FILTER_CPP_IDENTIFIERS))

    strings = find_string_addrs(program, MIN_STRING_LEN)
    print("Found {} candidate strings.".format(len(strings)))

    labeled    = 0
    no_refs    = 0

    for str_addr, s in strings:
        refs = find_references(program, str_addr)
        if not refs:
            no_refs += 1
            continue

        label = safe_label(s)

        for ref_addr in refs:
            # Try to find or create the enclosing function
            func = listing.getFunctionContaining(ref_addr)
            if func is None and CREATE_FUNCTIONS:
                func = createFunction(ref_addr, "fn_" + label)

            if func is not None:
                existing_name = func.getName()
                # Only rename if the function still has an auto-generated name
                # (starts with 'FUN_' or 'fn_') to avoid overwriting manual names
                if existing_name.startswith('FUN_') or existing_name.startswith('fn_'):
                    try:
                        func.setName(label, SourceType.ANALYSIS)
                        print("  Renamed {} -> {} (refs string '{}' at {})".format(
                            existing_name, label, s, str_addr))
                        labeled += 1
                    except Exception as e:
                        print("  WARNING: Could not rename {}: {}".format(existing_name, e))
            else:
                # No function context - just drop a label at the referencing address
                try:
                    sym_tbl.createLabel(ref_addr, "ref_" + label, SourceType.ANALYSIS)
                    print("  Label ref_{} at {} (string '{}' at {})".format(
                        label, ref_addr, s, str_addr))
                    labeled += 1
                except Exception as e:
                    print("  WARNING: Could not create label at {}: {}".format(ref_addr, e))

    print("")
    print("=== Summary ===")
    print("  Strings found:       {}".format(len(strings)))
    print("  Strings with no ref: {}".format(no_refs))
    print("  Labels/renames:      {}".format(labeled))

main()
