"""Debug fish.dll analysis"""
import sys
print("Starting...")
sys.stdout.flush()

try:
    import pefile
    print("pefile imported OK")
except Exception as e:
    print(f"pefile import error: {e}")
    sys.exit(1)

try:
    print("Loading fish.dll...")
    pe = pefile.PE(r"d:\boottt\fish.dll")
    print(f"Loaded! Machine: {hex(pe.FILE_HEADER.Machine)}")
    
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print(f"Exports found: {len(pe.DIRECTORY_ENTRY_EXPORT.symbols)}")
        for i, exp in enumerate(pe.DIRECTORY_ENTRY_EXPORT.symbols[:20]):
            name = exp.name.decode('utf-8') if exp.name else "ORDINAL"
            print(f"  {i}: {name}")
    else:
        print("NO EXPORTS FOUND in fish.dll!")
        print("This DLL does not expose functions publicly.")
        
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
