"""
Lords Mobile Protocol Analysis
Based on captured packets from packets.json
"""

import json

# Load packets
with open('packets.json', 'r') as f:
    data = json.load(f)

packets = data.get('packets', [])
print(f"Total packets: {len(packets)}")
print("="*60)

# Analyze packet types
packet_types = {}
login_packets = []
command_packets = []

for p in packets:
    if p.get('type') != 'packet':
        continue
        
    hex_data = p.get('hex', '')
    length = p.get('length', 0)
    
    # First byte seems to be packet type
    if len(hex_data) >= 2:
        first_byte = hex_data[:2]
        if first_byte not in packet_types:
            packet_types[first_byte] = []
        packet_types[first_byte].append({
            'length': length,
            'hex': hex_data[:50]
        })
        
    # Check for login packets (contain device ID)
    if 'd48db23' in hex_data or 'eyJ' in p.get('ascii', ''):
        login_packets.append(p)
        
    # Small command packets (8-16 bytes)
    if 8 <= length <= 16:
        command_packets.append(p)

print("\n--- Packet Type Distribution ---")
for ptype, packets_list in sorted(packet_types.items(), key=lambda x: -len(x[1])):
    print(f"  0x{ptype}: {len(packets_list)} packets")
    if len(packets_list) <= 3:
        for pkt in packets_list[:3]:
            print(f"    len={pkt['length']}: {pkt['hex']}")

print(f"\n--- Login Packets Found: {len(login_packets)} ---")
for lp in login_packets[:3]:
    print(f"  Length: {lp['length']}")
    print(f"  Hex: {lp['hex'][:100]}...")

print(f"\n--- Command Packets (8-16 bytes): {len(command_packets)} ---")
# Group by first 4 bytes
cmd_groups = {}
for cp in command_packets:
    key = cp['hex'][:8]
    if key not in cmd_groups:
        cmd_groups[key] = 0
    cmd_groups[key] += 1

print("  Common command patterns:")
for pattern, count in sorted(cmd_groups.items(), key=lambda x: -x[1])[:10]:
    print(f"    {pattern}: {count} times")

print("\n" + "="*60)
print("PROTOCOL STRUCTURE ANALYSIS")
print("="*60)

print("""
Based on captured packets, the protocol structure is:

1. HANDSHAKE (23 bytes):
   01 08 njtlvaaz 0c tl95ndc8b94l
   - First byte: 0x01 (handshake type)
   - Contains server identifier strings

2. SOCKS PROXY (10 bytes):
   05 01 00 01 ...
   - SOCKS5 protocol handshake
   
3. LOGIN PACKET (582 bytes):
   46 02 13 04 <server_id:4> 00 00 00 00 b9 02 1d 01 01 01 <device_id:36> <padding> <jwt_token>
   - 0x46 = 'F' (First byte)
   - 0x02 = Version?
   - 0x13 = Login command
   - 0x04 = Subtype?
   - Device ID as ASCII string (36 chars)
   - JWT token as ASCII string
   
4. TLS ENCRYPTED (starts with 17 03 03):
   - Standard TLS 1.2 Application Data
   - These are encrypted game commands
   
5. GAME COMMANDS (8-49 bytes):
   Various small packets for game actions:
   - 08 00 xx xx = Simple commands
   - 10 00 xx xx = Status updates  
   - 31 00 99 08 = Query/Response (49 bytes)

KEY FINDING: The protocol uses TWO layers:
1. Raw TCP for handshake + login
2. TLS encryption for game commands
""")

# Save analysis
with open('protocol_analysis.txt', 'w') as f:
    f.write("Protocol Analysis Results\n")
    f.write(f"Total packets: {len(packets)}\n")
    f.write(f"Login packets: {len(login_packets)}\n")
    f.write(f"Command packets: {len(command_packets)}\n")

print("\nAnalysis saved to protocol_analysis.txt")
