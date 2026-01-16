"""
Lords Mobile Client v4 - Full Protocol Implementation
Based on complete capture analysis
"""

import socket
import struct
import time
from config import DEVICE_ID, ACCESS_TOKEN

# Static values from capture - these are server identifiers, not tokens!
HANDSHAKE_HEX = "01086e6a746c7661617a0c746c39356e6463386239346c"
GAME_SERVER = "63.217.234.17"  # From SOCKS data
GAME_PORT = 5999

class LordsClientV4:
    def __init__(self, device_id, access_token):
        self.device_id = device_id
        self.access_token = access_token
        self.socket = None
        
    def connect(self):
        """Direct connect to game server"""
        print(f"[*] Connecting to {GAME_SERVER}:{GAME_PORT}...")
        
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(10)
        
        try:
            self.socket.connect((GAME_SERVER, GAME_PORT))
            print("[+] Connected!")
            return True
        except Exception as e:
            print(f"[-] Failed: {e}")
            return False
    
    def send(self, data, desc=""):
        """Send data"""
        print(f"[>] Sending {desc}: {len(data)} bytes")
        print(f"    {data[:40].hex()}")
        self.socket.send(data)
    
    def recv(self, timeout=3):
        """Receive data"""
        try:
            self.socket.settimeout(timeout)
            data = self.socket.recv(4096)
            print(f"[<] Received: {len(data)} bytes")
            if data:
                print(f"    {data[:50].hex()}")
            return data
        except socket.timeout:
            print("[!] Timeout")
            return None
        except Exception as e:
            print(f"[-] Error: {e}")
            return None
    
    def build_handshake(self):
        """Static handshake packet"""
        return bytes.fromhex(HANDSHAKE_HEX)
    
    def build_login(self, server_id=0xa10fd93a):
        """582-byte login packet"""
        pkt = bytearray(582)
        
        # Header: 46 02 13 04
        pkt[0:4] = bytes([0x46, 0x02, 0x13, 0x04])
        
        # Server ID (little endian)
        pkt[4:8] = struct.pack('<I', server_id)
        
        # Zeros
        pkt[8:12] = bytes(4)
        
        # Device marker: b9 02 1d 01 01 01
        pkt[12:18] = bytes([0xb9, 0x02, 0x1d, 0x01, 0x01, 0x01])
        
        # Device ID (36 chars ASCII)
        device = self.device_id.encode('ascii')
        pkt[18:54] = device
        
        # Zeros (15 bytes)
        pkt[54:69] = bytes(15)
        
        # Token marker: a0 01
        pkt[69:71] = bytes([0xa0, 0x01])
        
        # Token
        token = self.access_token.encode('ascii')
        end = min(71 + len(token), 582)
        pkt[71:end] = token[:end-71]
        
        return bytes(pkt)
    
    def login_sequence(self):
        """Full login sequence matching captured flow"""
        print("\n" + "="*50)
        print(" LOGIN SEQUENCE")
        print("="*50)
        
        # Step 1: Send handshake
        self.send(self.build_handshake(), "handshake")
        time.sleep(0.3)
        
        # Check for response
        resp1 = self.recv(2)
        if resp1:
            print(f"[+] Server acknowledged handshake!")
        
        # Step 2: SOCKS-like connect (what the bot sends next)
        # 05 01 00 01 <ip> <port>
        socks_connect = bytes.fromhex("050100013fd9ea11176f")
        self.send(socks_connect, "SOCKS connect")
        time.sleep(0.3)
        
        resp2 = self.recv(2)
        
        # Step 3: Login packet
        self.send(self.build_login(), "login")
        time.sleep(0.5)
        
        # Get response
        resp3 = self.recv(5)
        
        if resp3 and len(resp3) > 10:
            print("\n[+] SUCCESS! Got game data!")
            return True
        else:
            print("\n[-] Login failed")
            return False
    
    def close(self):
        if self.socket:
            self.socket.close()
            print("[*] Disconnected")


def main():
    print("="*50)
    print(" Lords Mobile Client v4")
    print("="*50)
    print(f"Server: {GAME_SERVER}:{GAME_PORT}")
    print(f"Device: {DEVICE_ID}")
    
    client = LordsClientV4(DEVICE_ID, ACCESS_TOKEN)
    
    if not client.connect():
        return
    
    try:
        client.login_sequence()
    except Exception as e:
        print(f"[-] Error: {e}")
    
    time.sleep(1)
    client.close()

if __name__ == "__main__":
    main()
