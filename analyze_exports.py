"""
fish.dll Export Finder using pefile library
"""

import subprocess
import sys

# Install pefile if not available
try:
    import pefile
except ImportError:
    print("Installing pefile...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "pefile", "-q"])
    import pefile

FISH_DLL_PATH = r"d:\boottt\fish.dll"

def main():
    print("=" * 60)
    print(" fish.dll Export Analysis")
    print("=" * 60)
    
    try:
        pe = pefile.PE(FISH_DLL_PATH)
        
        print(f"\nMachine Type: {'x64' if pe.FILE_HEADER.Machine == 0x8664 else 'x86'}")
        print(f"Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        
        # Check for exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            exports = pe.DIRECTORY_ENTRY_EXPORT.symbols
            print(f"\n✓ Found {len(exports)} exported functions:\n")
            
            for exp in exports:
                if exp.name:
                    print(f"  [{exp.ordinal:4}] {exp.name.decode('utf-8')}")
                else:
                    print(f"  [{exp.ordinal:4}] (ordinal only)")
        else:
            print("\n⚠ No export directory found!")
            print("  Checking for other methods...")
            
        # Check imports to understand dependencies
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            print(f"\n--- DLL Imports ---")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"\n  {entry.dll.decode('utf-8')}:")
                for imp in entry.imports[:5]:  # First 5 only
                    if imp.name:
                        print(f"    - {imp.name.decode('utf-8')}")
                if len(entry.imports) > 5:
                    print(f"    ... and {len(entry.imports) - 5} more")
                    
        pe.close()
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
