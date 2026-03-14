#Resolve Sony PSP NIDs to function names
#Adds support for OVL (overlay) ELF files such as Dissidia's ovl_*_elf,
#where sceModuleInfo is located via e_flags instead of p_paddr.
#@author John Kelley <john@kelley.ca>
#@category Analysis
#@website https://github.com/pspdev/psp-ghidra-scripts

# PPSSPP NIDs: sift -e "\{(0[Xx][0-9A-F]+),\s+[^,]*,\s+\"[a-zA-Z0-9]+\"," | awk '{print $2 " " $4}'|tr -d "{,\""

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ghidra.program.model.data import DataTypeConflictHandler, ArrayDataType, PointerDataType
from ghidra.program.model.scalar import Scalar
from ghidra.app.cmd.function import DeleteFunctionCmd
from ghidra.app.util.cparser.C import CParser
from ghidra.app.util.opinion import ElfLoader
from ghidra.app.util.bin.format.objectiveC.ObjectiveC1_Utilities import *
from ghidra.program.model.data import TerminatedStringDataType
import xml.etree.ElementTree as ET
import os.path
import sys
import re

def safeClearAndCreateDwords(base_addr, count):
    listing = currentProgram.getListing()
    for i in range(count):
        addr = base_addr.add(i * 4)
        end_addr = addr.add(3)
        # Erase instructions and data
        listing.clearCodeUnits(addr, end_addr, False)
    createDwords(base_addr, count)

def getNameForNID(nidDB, lib_name, nid):
    # fix for NIDs with missing leading 0's
    while len(nid) < 10:
        nid = nid[:2] + '0' + nid[2:]
    return nidDB.get(nid, lib_name+"_"+nid)

def createPSPModuleInfoStruct():
    # struct from prxtypes.h
    PSPModuleInfo_txt = """
    struct PspModuleInfo {
        unsigned int flags;
        char name[28];
        void *gp;
        void *exports;
        void *exp_end;
        void *imports;
        void *imp_end;
    };"""

    # Get Data Type Manager
    data_type_manager = currentProgram.getDataTypeManager()

    # Create CParser
    parser = CParser(data_type_manager)

    # Parse structure
    parsed_datatype = parser.parse(PSPModuleInfo_txt)

    # Add parsed type to data type manager
    datatype = data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)

    # datatype isn't accurate, so lets request it from data type manager and return it
    return currentProgram.getDataTypeManager().getDataType("/PspModuleInfo")

def createPSPModuleImportStruct():
    # struct from prxtypes.h
    PspModuleImport_txt = """
    struct PspModuleImport{
        char *name;
        unsigned int flags;
        byte     entry_size;
        byte     var_count;
        unsigned short func_count;
        unsigned int *nids;
        unsigned int *funcs;
    };"""

    # Get Data Type Manager
    data_type_manager = currentProgram.getDataTypeManager()

    # Create CParser
    parser = CParser(data_type_manager)

    # Parse structure
    parsed_datatype = parser.parse(PspModuleImport_txt)

    # Add parsed type to data type manager
    datatype = data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)

    # datatype isn't accurate, so lets request it from data type manager and return it
    return currentProgram.getDataTypeManager().getDataType("/PspModuleImport")

def createPSPModuleExportStruct():
    # struct from prxtypes.h
    PSPModuleExport_txt = """
    struct PspModuleExport
    {
        char *name;
        unsigned int flags;
        byte     entry_len;
        byte     var_count;
        unsigned short func_count;
        unsigned int *exports;
    };"""

    # Get Data Type Manager
    data_type_manager = currentProgram.getDataTypeManager()

    # Create CParser
    parser = CParser(data_type_manager)

    # Parse structure
    parsed_datatype = parser.parse(PSPModuleExport_txt)

    # Add parsed type to data type manager
    datatype = data_type_manager.addDataType(parsed_datatype, DataTypeConflictHandler.DEFAULT_HANDLER)

    # datatype isn't accurate, so lets request it from data type manager and return it
    return currentProgram.getDataTypeManager().getDataType("/PspModuleExport")

def resolveExports(exports_addr, exports_end, nidDB, moduleInfo_name):
    # undefine .lib.ent section members
    currentProgram.getListing().clearCodeUnits(exports_addr, exports_end, False)

    export_t = createPSPModuleExportStruct()
    export_t_len = export_t.getLength()
    num_exports = exports_end.subtract(exports_addr)/export_t_len
    if num_exports < 1:
        print "No exports to resolve"
        return 0

    exports_offset = 0
    addr = exports_addr
    modules = []
    while addr.add(export_t_len).compareTo(exports_end) <= 0:
        # create struct at address
        currentProgram.getListing().createData(addr, export_t, export_t_len)
        # create module object from data
        module = getDataAt(addr)
        # append module to modules list
        modules.append(module)
        # get entry len & update exports_offset
        entry_len = module.getComponent(2).value.getUnsignedValue()
        exports_offset += 4*entry_len
        # update address
        addr = exports_addr.add(exports_offset)


    # iterate through array of exports
    module_index = 0
    for module in modules:
        # roundabout way to grab the string pointed to by the name field
        module_name_addr = module.getComponent(0)
        module_name = "(none)"
        # why we can't just get a number to compare against 0 is beyond me
        if module_name_addr.value.toString() != "00000000":
            module_name = getDataAt(module_name_addr.value).value
        elif module_index == 0:
            module_name = moduleInfo_name
        else:
            module_name = "unknown"
        # increase module count
        module_index += 1

        # another roundabout way to get an actual number
        num_vars  = module.getComponent(3).value.getUnsignedValue()
        num_funcs = module.getComponent(4).value.getUnsignedValue()
        nids_base = module.getComponent(5).value
        num_nids = num_vars + num_funcs
        stub_base = nids_base.add(4 * num_nids)
        # at stub_base, function NIDs come first, followed by variable NIDs
        #print module_name,"has", num_vars, "variables, and", num_funcs, "exported functions"
        # convert raw data to DWORDs to 'show' NIDs
        safeClearAndCreateDwords(nids_base, num_nids)
        # convert raw data to pointers for vars & funcs
        for n in range(num_nids):
            applyData(currentProgram, PointerDataType(), stub_base.add(4 * n))
        # label the NIDs with the module name
        createLabel(nids_base, module_name+"_nids", True)
        # label the funcs with the module name
        createLabel(stub_base, module_name+"_funcs", True)
        # label the vars with the module name
        if num_vars > 0:
            createLabel(stub_base.add(4*num_funcs), module_name+"_vars", True)

        print "Resolving Export NIDs for",module_name
        for func_idx in range(num_funcs):
            nid_addr = nids_base.add(4 * func_idx)
            stub_addr = getDataAt(stub_base.add(4 * func_idx)).value
            # get NID hex and convert to uppercase
            nid = str(getDataAt(nid_addr).value).upper()
            # ensure 0x instead of 0X
            nid = nid.replace('X', 'x')
            # resolve NID to function name
            label = getNameForNID(nidDB, module_name, nid)
            # delete any existing function so we can re-name it
            df = DeleteFunctionCmd(stub_addr, True)
            df.applyTo(currentProgram)
            # create a function with the proper name
            createFunction(stub_addr, label)

        for var_idx in range(num_vars):
            nid_addr = nids_base.add(4*num_funcs + 4*var_idx)
            stub_addr = getDataAt(stub_base.add(4*num_funcs + 4*var_idx)).value
            # get NID hex and convert to uppercase
            nid = str(getDataAt(nid_addr).value).upper()
            # ensure 0x instead of 0X
            nid = nid.replace('X', 'x')
            # resolve NID to variable name
            label = getNameForNID(nidDB, module_name, nid)
            createLabel(stub_addr, "var_"+label, True)

def resolveImports(imports_addr, imports_end, nidDB):
    # undefine .lib.stub section members
    currentProgram.getListing().clearCodeUnits(imports_addr, imports_end, False)

    # create array of PspModuleImport
    import_t = createPSPModuleImportStruct()
    import_t_len = import_t.getLength()
    num_imports = imports_end.subtract(imports_addr)/import_t_len
    if num_imports < 1:
        print "No imports to resolve"
        return 0

    imports_offset = 0
    addr = imports_addr
    modules = []
    while addr.add(import_t_len).compareTo(imports_end) <= 0:
        try:
            # create struct at address
            currentProgram.getListing().createData(addr, import_t, import_t_len)
            # create module object from data
            module = getDataAt(addr)
            # append module to modules list
            modules.append(module)
            # get entry len & update exports_offset
            entry_len = module.getComponent(2).value.getUnsignedValue()
            imports_offset += 4 * entry_len
            # update address
            addr = imports_addr.add(imports_offset)
        except ghidra.program.model.util.CodeUnitInsertionException as e:
            print("Warning: Skipping address {addr} due to conflict: {e}")

    # iterate through array of library imports
    for module in modules:
        # validate name field, thanks to FW 6.61 wlan.prx (See Issue #1)
        module_name_ptr = module.getComponent(0).value
        module_name_data = getDataAt(module_name_ptr)
        if module_name_data is None:
            print "WARNING: Attempting to correct incomplete string datatype for PSPModuleImport.name"
            try:
                currentProgram.getListing().createData(module_name_ptr, TerminatedStringDataType.dataType)
            except ghidra.program.model.util.CodeUnitInsertionException as e:
                # this is brittle but we lack a better way right now
                # fingers crossed that Ghidra doesn't change their python exception message
                match = re.match(".*([0-8A-Fa-f]{8})\sto\s([0-8A-Fa-f]{8})", e.message)
                if match:
                    print "WARNING: Clearing data from ", match.group(1), "to", match.group(2)
                    currentProgram.getListing().clearCodeUnits(module_name_ptr.getNewAddress(int("0x"+match.group(1), 16)), module_name_ptr.getNewAddress(int("0x"+match.group(2), 16)), False)
                    currentProgram.getListing().createData(module_name_ptr, TerminatedStringDataType.dataType)

        # roundabout way to grab the string pointed to by the name field
        module_name = getDataAt(module.getComponent(0).value).value
        # another roundabout way to get an actual number
        # num_vars  = module.getComponent(3).value.getUnsignedValue()
        num_funcs = module.getComponent(4).value.getUnsignedValue()
        nids_base = module.getComponent(5).value
        stub_base = module.getComponent(6).value
        # TODO: account for variables here, like above.
        #       We have yet to see variables in an import
        # num_nids = num_vars + num_funcs
        # convert raw data to DWORDs to 'show' NIDs
        safeClearAndCreateDwords(nids_base, num_funcs)
        # label the NIDs with the module name
        createLabel(nids_base, module_name+"_nids", True)

        print "Resolving Import NIDs for",module_name
        for func_idx in range(num_funcs):
            nid_addr = nids_base.add(4*func_idx)
            stub_addr = stub_base.add(8*func_idx) # should this be 4?
            # get NID hex and convert to uppercase
            nid = str(getDataAt(nid_addr).value).upper()
            # ensure 0x instead of 0X
            nid = nid.replace('X', 'x')
            # resolve NID to function name
            label = getNameForNID(nidDB, module_name, nid)
            # delete any existing function so we can re-name it
            df = DeleteFunctionCmd(stub_addr, True)
            df.applyTo(currentProgram)
            # create a function with the proper name
            createFunction(stub_addr, label)

def readU32LE(addr):
    # Read 4 bytes at addr and return them as an unsigned 32-bit little-endian integer.
    # We cannot rely on getInt() on Ghidra data components for ELF header fields
    # because Ghidra may return 0 for fields it does not expose via the Java API.
    # Reading raw bytes and assembling manually is always reliable.
    raw = getBytes(addr, 4)
    b = [x & 0xFF for x in raw]
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24)

def getModuleInfoAddrFromLoadCommands():
    # Locate sceModuleInfo for ET_SCE_PRX files (ELF type 0xFFA8), which includes
    # standard PRX files as well as OVL (overlay) files such as Dissidia's ovl_*_elf.
    #
    # The PSP SDK encodes the FILE offset of sceModuleInfo in the upper 24 bits
    # of the ELF e_flags field. Extraction: module_info_file_offset = e_flags >> 8
    #
    # The lower 8 bits of e_flags are standard MIPS ABI/CPU flags and are ignored.
    #
    # To convert the file offset to a virtual address:
    #   sceModuleInfo_addr = p_vaddr + (module_info_file_offset - p_offset)
    #
    # where:
    #   p_vaddr  = virtual address where the first PT_LOAD segment is mapped
    #   p_offset = file offset where the first PT_LOAD segment begins
    #
    # Subtracting p_offset converts the absolute file offset into an offset
    # relative to the start of the segment, then adding p_vaddr gives the
    # final virtual address.
    #
    # Example for OVL_BATTLE_APP.ELF:
    #   e_flags               = 0x10A23001
    #   module_info_file_off  = 0x10A23001 >> 8 = 0x0010A230
    #   p_offset              = 0x54
    #   p_vaddr               = 0x089DD4C0
    #   sceModuleInfo_addr    = 0x089DD4C0 + (0x0010A230 - 0x54) = 0x08AE769C
    #
    # Note: the original script used p_paddr instead of e_flags, which works for
    # simple PRX files but fails for OVL files where p_paddr is 0.

    mem = currentProgram.getMemory()

    # --- Read e_flags from the raw ELF header bytes ---
    # ELF32 header layout (all ints are little-endian):
    #   0x00  e_ident    (16 bytes)
    #   0x10  e_type     ( 2 bytes)
    #   0x12  e_machine  ( 2 bytes)
    #   0x14  e_version  ( 4 bytes)
    #   0x18  e_entry    ( 4 bytes)
    #   0x1C  e_phoff    ( 4 bytes)
    #   0x20  e_shoff    ( 4 bytes)
    #   0x24  e_flags    ( 4 bytes)  <-- what we need
    elf_header_start = mem.getBlock("_elfHeader").getStart()
    e_flags = readU32LE(elf_header_start.add(0x24))
    print("e_flags (raw): 0x{:08x}".format(e_flags))

    # Extract the file offset of sceModuleInfo from e_flags
    module_info_file_offset = (e_flags >> 8) & 0xFFFFFF
    print("sceModuleInfo file offset (from e_flags >> 8): 0x{:x}".format(module_info_file_offset))

    # --- Read p_vaddr and p_offset from the first ELF program header ---
    # ELF32 PT_LOAD layout (all fields 4 bytes, little-endian):
    #   0x00  p_type
    #   0x04  p_offset  <-- file offset of segment start
    #   0x08  p_vaddr   <-- virtual address of segment start
    #   0x0C  p_paddr
    #   0x10  p_filesz
    #   0x14  p_memsz
    #   0x18  p_flags
    #   0x1C  p_align
    phdr_start = mem.getBlock("_elfProgramHeaders").getStart()
    p_offset = readU32LE(phdr_start.add(0x04))
    p_vaddr  = readU32LE(phdr_start.add(0x08))

    # Mask out the upper bit used by kernel-mode PRX files (0x80000000)
    p_vaddr &= 0x7FFFFFFF
    print("p_offset: 0x{:08x}".format(p_offset))
    print("p_vaddr:  0x{:08x}".format(p_vaddr))

    # Convert file offset -> virtual address by rebasing onto p_vaddr
    final_addr = (p_vaddr + module_info_file_offset - p_offset) & 0xFFFFFFFF
    print("sceModuleInfo final addr: 0x{:08x}".format(final_addr))

    return getAddressFactory().getDefaultAddressSpace().getAddress(final_addr)

def findAndLoadModuleInfoStruct():
    # create sceModuleInfo struct
    sceModuleInfo_t = createPSPModuleInfoStruct()
    sceModuleInfo_t_len = sceModuleInfo_t.getLength()

    # .lib.stub isn't required in PRXes, so use .rodata.sceModuleInfo instead.
    sceModuleInfo_section = currentProgram.getMemory().getBlock(".rodata.sceModuleInfo")
    if sceModuleInfo_section is None:
        # Just kidding, this isn't guaranteed to exist either - I'm looking at you, Assassin's Creed - Bloodlines.
        print "Could not find .rodata.sceModuleInfo section, calculating its location from ELF Program Headers"
        sceModuleInfo_addr = getModuleInfoAddrFromLoadCommands()
    else:
        sceModuleInfo_addr = sceModuleInfo_section.getStart()

    # re-create sceModuleInfo struct at the given address
    currentProgram.getListing().clearCodeUnits(sceModuleInfo_addr, sceModuleInfo_addr.add(sceModuleInfo_t_len), False)
    currentProgram.getListing().createData(sceModuleInfo_addr, sceModuleInfo_t)
    return getDataAt(sceModuleInfo_addr)

def loadNIDDB(xml_file):
    # Ghidra hack to get the current directory to load data files
    script_path = os.path.dirname(getSourceFile().getCanonicalPath())

    # load NID database
    xml_root = ET.parse(os.path.join(script_path, xml_file))

    # construct dict of NID->NAME to greatly speed up lookup
    nidDB = {}
    funcs = xml_root.findall(".//FUNCTION")
    for func in funcs:
        nid = func.find("NID").text
        name = func.find("NAME").text
        nidDB[nid] = name
    return nidDB

def main():
    nidDB = loadNIDDB("ppsspp_niddb.xml")
    sceModuleInfo = findAndLoadModuleInfoStruct()

    # DEBUG - dump raw dwords at sceModuleInfo to verify struct layout
    print("=== Raw dwords at sceModuleInfo (0x08AE769C) ===")
    base = sceModuleInfo.getAddress()
    for i in range(16):
        addr = base.add(i * 4)
        val = readU32LE(addr)
        print("  +0x{:02x} ({}) = 0x{:08x}".format(i*4, addr, val))

    module_name = str(sceModuleInfo.getComponent(1).value).encode('ascii', 'replace')
    exports_addr = sceModuleInfo.getComponent(3).getValue()
    exports_end  = sceModuleInfo.getComponent(4).getValue()
    imports_addr = sceModuleInfo.getComponent(5).getValue()
    imports_end  = sceModuleInfo.getComponent(6).getValue()

    print("module_name:  {}".format(module_name))
    print("exports_addr: {}".format(exports_addr))
    print("exports_end:  {}".format(exports_end))
    print("imports_addr: {}".format(imports_addr))
    print("imports_end:  {}".format(imports_end))

    resolveExports(exports_addr, exports_end, nidDB, module_name)
    resolveImports(imports_addr, imports_end, nidDB)

if __name__ == "__main__":
    main()
