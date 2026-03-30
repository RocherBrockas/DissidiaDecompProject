from ghidra.program.model.listing import Instruction

listing = currentProgram.getListing()
output = open("E:/DEv/DissidiaDecompProject/DisasmResult/eboot.text.s", "w")

funcs = currentProgram.getFunctionManager().getFunctions(True)
for func in funcs:
    output.write("\n\n# Function: " + func.getName() + "\n")
    output.write(func.getEntryPoint().toString() + ":\n")
    
    addrSet = func.getBody()
    instructions = listing.getInstructions(addrSet, True)
    
    for instr in instructions:
        output.write("\t" + instr.toString() + "\n")

output.close()
print("Export Done")