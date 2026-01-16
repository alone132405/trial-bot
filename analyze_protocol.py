"""
Lords Mobile Binary Protocol Analyzer
Analyzes captured network data to understand the protocol format
"""

import json
import base64

# Load captured data
with open('captured.json', 'r') as f:
    data = json.load(f)

print("="*60)
print(" Analyzing Captured Network Data")
print("="*60)

for i, entry in enumerate(data):
    if entry.startswith('[NET]'):
        raw = entry[6:]  # Remove "[NET] " prefix
        
        print(f"\n--- Packet {i} ---")
        print(f"Length: {len(raw)} chars")
        
        # Check for known patterns
        if 'eyJ' in raw:  # JWT/Base64 JSON
            print("Contains Base64 JSON (eyJ...)")
            # Find and decode the base64 part
            start = raw.find('eyJ')
            end = raw.find('.', start)
            if end > start:
                b64 = raw[start:end]
                try:
                    decoded = base64.b64decode(b64 + '==')
                    print(f"Decoded: {decoded}")
                except:
                    pass
        
        if '0d48db23' in raw:  # Device ID
            print("Contains Device ID!")
        
        # Show hex representation
        try:
            hex_repr = raw[:50].encode('utf-8', errors='replace').hex()
            print(f"Hex (first 50): {hex_repr}")
        except:
            pass
        
        # Show printable ASCII
        printable = ''.join(c if 32 <= ord(c) < 127 else '.' for c in raw[:100])
        print(f"ASCII: {printable}")

print("\n" + "="*60)
print(" Protocol Structure Analysis")
print("="*60)

# The captured data shows:
# 1. First packet: Short header/handshake
# 2. Second packet: Contains device ID + JWT token
# 3. Following: Encrypted game data

print("""
Based on captured traffic, the protocol appears to be:

1. HEADER (variable length):
   - Magic bytes / protocol version
   - Some binary metadata
   
2. DEVICE_ID:
   - Sent as UTF-8 string (UUID format)
   
3. ACCESS_TOKEN:
   - JWT format: base64_header.signature
   - Header contains: akid, rkid, game_id, version
   
4. PAYLOAD:
   - Encrypted game commands
   - Likely using the DES/AES encryption we researched

To properly communicate:
- We need to replicate the binary header format
- Send device ID + token in the exact format
- Handle the encryption for payloads
""")

# Extract the raw binary pattern
print("\nLooking for patterns in captured data...")
for entry in data:
    if '[NET] F' in entry:  # This seems to be the login packet
        print(f"\nPotential login packet found:")
        print(f"  Starts with: {repr(entry[:30])}")
