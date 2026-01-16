"""
Lords Mobile Client v5 - Try different connection approaches
"""

import socket
import struct
import time
from config import DEVICE_ID, ACCESS_TOKEN

# Static handshake
HANDSHAKE = bytes.fromhex("01086e6a746c7661617a0c746c39356e6463386239346c")

# Different IPs decoded from SOCKS packets in capture
SERVERS_TO_TRY = [
    ("63.217.234.17", 5999),   # From SOCKS: 3f d9 ea 11 17 6f
    ("63.217.234.13", 5999),   # From earlier: 3f d9 ea 0d
    ("34.168.134.194", 5999),  # Another possible: 22 a8 86 c2
]

def build_login(device_id, token, server_id=0xa10fd93a):
    """Build 582-byte login"""
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

def try_connection(host, port, variant):
    """Try connecting with different packet sequences"""
    print(f"\n{'='*50}")
    print(f"Trying {host}:{port} - Variant {variant}")
    print('='*50)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        print("[+] Connected!")
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return False
    
    try:
        if variant == 1:
            # Just handshake
            print("[>] Sending handshake only")
            sock.send(HANDSHAKE)
            time.sleep(0.5)
            sock.settimeout(3)
            data = sock.recv(1024)
            print(f"[<] Got {len(data)} bytes: {data[:30].hex() if data else 'empty'}")
            
        elif variant == 2:
            # Handshake + login
            print("[>] Handshake + Login")
            sock.send(HANDSHAKE)
            time.sleep(0.3)
            login = build_login(DEVICE_ID, ACCESS_TOKEN)
            sock.send(login)
            time.sleep(0.5)
            sock.settimeout(3)
            data = sock.recv(1024)
            print(f"[<] Got {len(data)} bytes")
            
        elif variant == 3:
            # Login directly (no handshake)
            print("[>] Login directly")
            login = build_login(DEVICE_ID, ACCESS_TOKEN)
            sock.send(login)
            time.sleep(0.5)
            sock.settimeout(3)
            data = sock.recv(1024)
            print(f"[<] Got {len(data)} bytes")
            
        elif variant == 4:
            # SOCKS greeting first
            print("[>] SOCKS greeting + Handshake")
            sock.send(bytes([0x05, 0x01, 0x00]))  # SOCKS5 no auth
            time.sleep(0.3)
            sock.settimeout(2)
            try:
                greeting_resp = sock.recv(64)
                print(f"[<] SOCKS response: {greeting_resp.hex() if greeting_resp else 'none'}")
            except:
                print("[!] No SOCKS response")
            
            sock.send(HANDSHAKE)
            time.sleep(0.3)
            data = sock.recv(1024)
            print(f"[<] Got {len(data)} bytes")
            
        return True
        
    except socket.timeout:
        print("[!] Timeout waiting for response")
    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        sock.close()
    
    return False

def main():
    print("="*60)
    print(" Lords Mobile Client v5 - Connection Testing")
    print("="*60)
    print(f"Device: {DEVICE_ID}")
    
    # Try each server with each variant
    for host, port in SERVERS_TO_TRY:
        for variant in [1, 2, 3, 4]:
            try_connection(host, port, variant)
            time.sleep(0.5)
    
    print("\n" + "="*60)
    print("Testing complete!")
    print("="*60)

if __name__ == "__main__":
    main()
