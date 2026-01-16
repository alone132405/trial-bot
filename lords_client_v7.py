"""
Lords Mobile Client v7 - Correct SOCKS5 sequence!
Based on FULL traffic capture analysis.

The correct sequence is:
1. Connect to SOCKS proxy
2. Send SOCKS greeting: 05 02 00 02 (SOCKS5, 2 auth methods: none, user/pass)
3. Get response: 05 00 or 05 02 (chosen auth method)
4. If 05 02, send username/password auth
5. Send handshake: 01 08 njtlvaaz...
6. Send SOCKS connect: 05 01 00 01 <ip> <port>
7. Get SOCKS response: 05 00 00 01 <bound ip> <port>
8. Send login packet
"""

import socket
import struct
import time
from config import DEVICE_ID, ACCESS_TOKEN

# SOCKS proxy (assuming the bot uses its own proxy)
# The bot connects somewhere, sends SOCKS greeting, then sends the handshake
# We need to find WHAT SERVER the bot connects to first

# From capture analysis - game servers
GAME_SERVERS = [
    ("63.217.234.17", 5999),
    ("63.217.234.13", 5999),
    ("204.141.178.243", 5999),  # cc 8d b2 f3
]

# Static protocol elements from capture
SOCKS_GREETING = bytes([0x05, 0x02, 0x00, 0x02])  # SOCKS5, 2 methods: none, user/pass
HANDSHAKE = bytes.fromhex("01086e6a746c7661617a0c746c39356e6463386239346c")

def build_socks_connect(ip, port):
    """Build SOCKS CONNECT request"""
    pkt = bytearray()
    pkt.append(0x05)  # SOCKS5
    pkt.append(0x01)  # CONNECT
    pkt.append(0x00)  # Reserved
    pkt.append(0x01)  # IPv4
    
    # IP bytes
    for octet in ip.split('.'):
        pkt.append(int(octet))
    
    # Port (big endian)
    pkt.extend(struct.pack('>H', port))
    return bytes(pkt)

def build_login(device_id, token, server_id=0xa10fd93a):
    """Build 582-byte login packet"""
    pkt = bytearray(582)
    pkt[0:4] = bytes([0x46, 0x02, 0x13, 0x04])
    pkt[4:8] = struct.pack('<I', server_id)
    pkt[12:18] = bytes([0xb9, 0x02, 0x1d, 0x01, 0x01, 0x01])
    pkt[18:54] = device_id.encode('ascii')
    pkt[69:71] = bytes([0xa0, 0x01])
    token_bytes = token.encode('ascii')
    for i, b in enumerate(token_bytes[:510]):
        pkt[71+i] = b
    return bytes(pkt)

def try_as_socks_proxy(host, port):
    """Try connecting as if this is a SOCKS proxy"""
    print(f"\n{'='*50}")
    print(f"Testing {host}:{port} as SOCKS proxy")
    print('='*50)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        print("[+] Connected!")
    except Exception as e:
        print(f"[-] Connect failed: {e}")
        return False
    
    try:
        # Step 1: SOCKS greeting
        print(f"[>] SOCKS greeting: {SOCKS_GREETING.hex()}")
        sock.send(SOCKS_GREETING)
        time.sleep(0.3)
        
        sock.settimeout(3)
        try:
            resp = sock.recv(64)
            print(f"[<] SOCKS response: {resp.hex() if resp else 'none'} ({len(resp)} bytes)")
            
            if resp and len(resp) >= 2:
                if resp[0] == 0x05:
                    print(f"    SOCKS version: {resp[0]}, Method: {resp[1]}")
                    
                    if resp[1] == 0x00:
                        print("[+] Auth: None required!")
                    elif resp[1] == 0x02:
                        print("[+] Auth: Username/Password required")
                        # We'd need to send auth here
        except socket.timeout:
            print("[!] No SOCKS response - trying handshake anyway")
        
        # Step 2: Send handshake
        print(f"\n[>] Handshake: {HANDSHAKE.hex()}")
        sock.send(HANDSHAKE)
        time.sleep(0.3)
        
        try:
            resp = sock.recv(64)
            print(f"[<] Response: {resp.hex() if resp else 'none'}")
        except socket.timeout:
            print("[!] No response to handshake")
        
        # Step 3: SOCKS connect to game server
        target_ip = "63.217.234.17"
        target_port = 5999
        connect_pkt = build_socks_connect(target_ip, target_port)
        print(f"\n[>] SOCKS CONNECT to {target_ip}:{target_port}")
        print(f"    Packet: {connect_pkt.hex()}")
        sock.send(connect_pkt)
        time.sleep(0.3)
        
        try:
            resp = sock.recv(64)
            print(f"[<] Response: {resp.hex() if resp else 'none'}")
            
            if resp and len(resp) >= 4 and resp[0] == 0x05 and resp[1] == 0x00:
                print("[+] SOCKS CONNECT successful!")
                
                # Step 4: Send login
                login = build_login(DEVICE_ID, ACCESS_TOKEN)
                print(f"\n[>] Login packet: {len(login)} bytes")
                sock.send(login)
                time.sleep(0.5)
                
                sock.settimeout(5)
                data = sock.recv(4096)
                print(f"[<] Response: {len(data)} bytes")
                if data:
                    print(f"    {data[:50].hex()}")
                    print("\n[+] SUCCESS! Got game data!")
                    return True
        except socket.timeout:
            print("[!] Timeout")
        
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sock.close()
    
    return False

def main():
    print("="*60)
    print(" Lords Mobile Client v7 - SOCKS5 Protocol")
    print("="*60)
    print(f"Device: {DEVICE_ID}")
    
    # Try each server as a SOCKS proxy
    for host, port in GAME_SERVERS:
        if try_as_socks_proxy(host, port):
            break
    
    print("\n" + "="*60)
    print("Done!")
    print("="*60)

if __name__ == "__main__":
    main()
