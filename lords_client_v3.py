"""
Lords Mobile Client v3 - Direct connection to game server
Based on SOCKS data analysis - connects to 63.217.234.13:5999
"""

import socket
import struct
import time
from config import DEVICE_ID, ACCESS_TOKEN

# REAL game server from SOCKS analysis!
GAME_SERVER = "63.217.234.13"
GAME_PORT = 5999

class LordsClientV3:
    def __init__(self, device_id, access_token):
        self.device_id = device_id
        self.access_token = access_token
        self.socket = None
        
    def connect(self):
        """Connect directly to game server"""
        print(f"[*] Connecting to {GAME_SERVER}:{GAME_PORT}...")
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((GAME_SERVER, GAME_PORT))
            print("[+] Connected!")
            return True
        except Exception as e:
            print(f"[-] Failed: {e}")
            return False
    
    def build_handshake(self):
        """First handshake packet"""
        return bytes.fromhex("01086e6a746c7661617a0c746c39356e6463386239346c")
    
    def build_login_packet(self, server_id=0xa10fd93a):
        """582-byte login packet"""
        packet = bytearray(582)
        
        # Header
        packet[0:4] = bytes([0x46, 0x02, 0x13, 0x04])
        packet[4:8] = struct.pack('<I', server_id)
        packet[8:12] = bytes(4)
        packet[12:18] = bytes([0xb9, 0x02, 0x1d, 0x01, 0x01, 0x01])
        
        # Device ID
        device = self.device_id.encode('ascii')
        packet[18:18+len(device)] = device
        
        # Padding + token marker
        packet[54:69] = bytes(15)
        packet[69:71] = bytes([0xa0, 0x01])
        
        # Token
        token = self.access_token.encode('ascii')
        for i, b in enumerate(token):
            if 71 + i < 582:
                packet[71 + i] = b
        
        return bytes(packet)
    
    def send(self, data, desc="data"):
        """Send and show"""
        print(f"[>] Sending {desc}: {len(data)} bytes")
        print(f"    {data[:40].hex()}...")
        self.socket.send(data)
    
    def recv(self, size=4096):
        """Receive and show"""
        try:
            self.socket.settimeout(5)
            data = self.socket.recv(size)
            print(f"[<] Received: {len(data)} bytes")
            if data:
                print(f"    {data[:50].hex()}")
                # Try ASCII
                try:
                    ascii_data = data.decode('ascii', errors='replace')
                    print(f"    ASCII: {ascii_data[:100]}")
                except:
                    pass
            return data
        except socket.timeout:
            print("[!] Timeout")
            return None
    
    def login_sequence(self):
        """Full login sequence"""
        print("\n" + "="*50)
        print(" LOGIN SEQUENCE")
        print("="*50)
        
        # Step 1: Handshake
        self.send(self.build_handshake(), "handshake")
        time.sleep(0.3)
        resp1 = self.recv()
        
        # Step 2: Login
        self.send(self.build_login_packet(), "login")
        time.sleep(0.5)
        resp2 = self.recv()
        
        # Try to receive more
        time.sleep(1)
        resp3 = self.recv()
        
        return resp2 or resp3
    
    def close(self):
        if self.socket:
            self.socket.close()
            print("[*] Disconnected")


def main():
    print("="*50)
    print(" Lords Mobile Client v3")
    print(" Direct connection to game server!")
    print("="*50)
    print(f"\nTarget: {GAME_SERVER}:{GAME_PORT}")
    print(f"Device: {DEVICE_ID}")
    
    client = LordsClientV3(DEVICE_ID, ACCESS_TOKEN)
    
    if not client.connect():
        return
    
    try:
        result = client.login_sequence()
        if result:
            print("\n[+] SUCCESS! Got response!")
        else:
            print("\n[-] No response from game server")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    client.close()

if __name__ == "__main__":
    main()
