"""
Simple fish.dll export analyzer - writes to file
"""
import pefile

pe = pefile.PE(r"d:\boottt\fish.dll")

with open("fish_exports.txt", "w") as f:
    f.write("fish.dll Export Analysis\n")
    f.write("=" * 50 + "\n\n")
    
    f.write(f"Architecture: {'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'}\n")
    f.write(f"Sections: {pe.FILE_HEADER.NumberOfSections}\n\n")
    
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        exports = pe.DIRECTORY_ENTRY_EXPORT.symbols
        f.write(f"Exported Functions: {len(exports)}\n\n")
        
        for exp in exports:
            name = exp.name.decode('utf-8') if exp.name else "(ordinal only)"
            f.write(f"[{exp.ordinal:4}] {name}\n")
    else:
        f.write("No exports found!\n")
        
    f.write("\n\nImported DLLs:\n")
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            f.write(f"\n{entry.dll.decode('utf-8')}:\n")
            for imp in entry.imports[:10]:
                if imp.name:
                    f.write(f"  - {imp.name.decode('utf-8')}\n")
            if len(entry.imports) > 10:
                f.write(f"  ... +{len(entry.imports) - 10} more\n")

pe.close()
print("Done! Check fish_exports.txt")
