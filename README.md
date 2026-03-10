# DissidiaDecompProject
A project about decompiling Dissidia 012 (Duodecim) for the PSP to enable advanced modding capabilities and better ways to play the game online

# Tools

Tools needed to help with the project:

- UMDGen https://datacrystal.tcrf.net/wiki/UMDGen
- PPSSPP https://www.ppsspp.org/
- Ghidra https://ghidra-sre.org/
- Allegrex Plugin for Ghidra https://github.com/kotcrab/ghidra-allegrex
- PSP reverse engineering HQ https://psp-re.github.io/
- PSP Dev, a repo with lots of technical information on psp game architecture and tools https://pspdev.github.io/

# Might be useful later:

- uofw, a reverse engineered PSP kernel & hardware https://github.com/uofw/uofw

# Getting Started

Find a ULUS-10566 ISO of the game and put it in PlaceYourIsoHere, and open it with UMDGen or any ISO extract tool,
Extract the content to the ISO to the folder PlaceYourIsoHere/Extracted_Iso

Then in the project Root run
python ./Tools/PackageBinExtract/ExtractPackageBin.py
This should extract everything to the Extract folder.