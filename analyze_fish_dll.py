"""
Lords Mobile Protocol Bot - fish.dll Analyzer

This script analyzes the fish.dll to find exported functions
that can be used for packet encoding/decoding.
"""

import ctypes
from ctypes import wintypes
import os
import struct

# Path to fish.dll
FISH_DLL_PATH = r"d:\boottt\fish.dll"

def get_dll_exports(dll_path):
    """
    Get a list of exported functions from a DLL.
    Uses ctypes to load and inspect the DLL.
    """
    exports = []
    
    try:
        # Load the DLL
        dll = ctypes.CDLL(dll_path)
        
        # Try common function names used in encoding
        common_names = [
            # Encoding/Decoding
            "Encode", "encode", "ENCODE",
            "Decode", "decode", "DECODE",
            "Encrypt", "encrypt", "ENCRYPT",
            "Decrypt", "decrypt", "DECRYPT",
            "Compress", "compress",
            "Decompress", "decompress",
            
            # Packet functions
            "Pack", "pack", "PACK",
            "Unpack", "unpack", "UNPACK",
            "Send", "send",
            "Recv", "recv", "Receive",
            
            # Init functions
            "Init", "init", "Initialize",
            "Create", "create",
            "Setup", "setup",
            
            # Fish-specific guesses
            "fish_encode", "fish_decode",
            "FishEncode", "FishDecode",
            "encode_packet", "decode_packet",
            "EncodePacket", "DecodePacket",
            
            # DES/AES
            "des_encrypt", "des_decrypt",
            "aes_encrypt", "aes_decrypt",
            "DESEncrypt", "DESDecrypt",
            "AESEncrypt", "AESDecrypt",
        ]
        
        print(f"Testing {len(common_names)} common function names...")
        
        for name in common_names:
            try:
                func = getattr(dll, name)
                exports.append(name)
                print(f"  ✓ Found: {name}")
            except AttributeError:
                pass
                
    except Exception as e:
        print(f"Error loading DLL: {e}")
        
    return exports

def analyze_dll_with_pe():
    """
    Analyze DLL using PE structure to find all exports.
    """
    print("\n--- Analyzing fish.dll PE Structure ---")
    
    try:
        with open(FISH_DLL_PATH, 'rb') as f:
            # Read DOS header
            dos_header = f.read(64)
            if dos_header[:2] != b'MZ':
                print("Not a valid PE file!")
                return
                
            # Get PE header offset
            pe_offset = struct.unpack('<I', dos_header[60:64])[0]
            
            # Read PE signature
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b'PE\x00\x00':
                print("Invalid PE signature!")
                return
                
            print(f"✓ Valid PE file")
            print(f"  PE Header at offset: 0x{pe_offset:X}")
            
            # Read COFF header
            coff_header = f.read(20)
            machine = struct.unpack('<H', coff_header[0:2])[0]
            num_sections = struct.unpack('<H', coff_header[2:4])[0]
            optional_header_size = struct.unpack('<H', coff_header[16:18])[0]
            
            print(f"  Machine: 0x{machine:X} ({'x64' if machine == 0x8664 else 'x86' if machine == 0x14c else 'unknown'})")
            print(f"  Sections: {num_sections}")
            print(f"  Optional header size: {optional_header_size}")
            
            # Read optional header to find export directory
            optional_header = f.read(optional_header_size)
            
            # Check if PE32 or PE32+
            magic = struct.unpack('<H', optional_header[0:2])[0]
            is_pe32_plus = magic == 0x20b
            
            # Export directory RVA and size
            if is_pe32_plus:
                export_rva = struct.unpack('<I', optional_header[112:116])[0]
                export_size = struct.unpack('<I', optional_header[116:120])[0]
            else:
                export_rva = struct.unpack('<I', optional_header[96:100])[0]
                export_size = struct.unpack('<I', optional_header[100:104])[0]
                
            print(f"\n  Export Directory RVA: 0x{export_rva:X}")
            print(f"  Export Directory Size: {export_size} bytes")
            
            if export_rva == 0:
                print("\n  ⚠ No export directory found!")
                print("  This DLL might use different method to expose functions.")
                return
                
    except Exception as e:
        print(f"Error analyzing PE: {e}")

def main():
    print("=" * 50)
    print(" Lords Mobile Protocol Bot - fish.dll Analyzer")
    print("=" * 50)
    
    if not os.path.exists(FISH_DLL_PATH):
        print(f"ERROR: fish.dll not found at {FISH_DLL_PATH}")
        return
        
    file_size = os.path.getsize(FISH_DLL_PATH)
    print(f"\nfish.dll found: {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")
    
    # Analyze PE structure
    analyze_dll_with_pe()
    
    # Try to find exported functions
    print("\n--- Searching for exported functions ---")
    exports = get_dll_exports(FISH_DLL_PATH)
    
    if exports:
        print(f"\n✓ Found {len(exports)} exported functions!")
        for name in exports:
            print(f"  - {name}")
    else:
        print("\n⚠ No common function names found.")
        print("  The DLL might use ordinal exports or different naming.")
        
    print("\n" + "=" * 50)
    
if __name__ == "__main__":
    main()
