"""
Lords Mobile Protocol Client - Working Login Implementation
Based on captured packet analysis
"""

import socket
import ssl
import struct
import time
from config import IGG_ID, GAME_ID, DEVICE_ID, ACCESS_TOKEN

class LordsClient:
    """Lords Mobile Protocol Client"""
    
    # Server info (extracted from packets)
    HOST = "lordsmobile.igg.com"
    PORT = 443
    
    def __init__(self, device_id, access_token):
        self.device_id = device_id
        self.access_token = access_token
        self.socket = None
        self.ssl_socket = None
        
    def connect(self):
        """Establish connection to game server"""
        print(f"[*] Connecting to {self.HOST}:{self.PORT}...")
        
        try:
            # Create socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            
            # Connect
            self.socket.connect((self.HOST, self.PORT))
            print("[+] TCP connected!")
            
            # Wrap with SSL
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            self.ssl_socket = context.wrap_socket(self.socket, server_hostname=self.HOST)
            print("[+] SSL handshake complete!")
            
            return True
            
        except Exception as e:
            print(f"[-] Connection failed: {e}")
            return False
    
    def build_handshake(self):
        """Build initial handshake packet (23 bytes)"""
        # From captured: 01 08 njtlvaaz 0c tl95ndc8b94l
        packet = bytes([0x01, 0x08])
        packet += b"njtlvaaz"
        packet += bytes([0x0c])
        packet += b"tl95ndc8b94l"
        return packet
    
    def build_login_packet(self, server_id=0xa10fd93a):
        """Build login packet (582 bytes)"""
        # Header: 46 02 13 04
        header = bytes([0x46, 0x02, 0x13, 0x04])
        
        # Server ID (4 bytes, little endian)
        server_bytes = struct.pack('<I', server_id)
        
        # Padding (4 bytes zeros)
        padding1 = bytes([0x00, 0x00, 0x00, 0x00])
        
        # Device ID marker: b9 02 1d 01 01 01
        device_marker = bytes([0xb9, 0x02, 0x1d, 0x01, 0x01, 0x01])
        
        # Device ID (36 bytes ASCII)
        device_id_bytes = self.device_id.encode('ascii')
        
        # Padding after device ID (15 bytes zeros)
        padding2 = bytes(15)
        
        # Token length marker: a0 01
        token_marker = bytes([0xa0, 0x01])
        
        # Access token as ASCII
        token_bytes = self.access_token.encode('ascii')
        
        # Build packet
        packet = header + server_bytes + padding1 + device_marker + device_id_bytes + padding2 + token_marker + token_bytes
        
        # Pad to 582 bytes
        while len(packet) < 582:
            packet += bytes([0x00])
        
        return packet
    
    def send_packet(self, packet, description=""):
        """Send a packet and log it"""
        print(f"[>] Sending {description}: {len(packet)} bytes")
        print(f"    Hex: {packet[:30].hex()}...")
        
        self.ssl_socket.send(packet)
        
    def recv_packet(self, size=4096):
        """Receive response"""
        try:
            data = self.ssl_socket.recv(size)
            print(f"[<] Received: {len(data)} bytes")
            if data:
                print(f"    Hex: {data[:50].hex()}...")
            return data
        except socket.timeout:
            print("[!] Receive timeout")
            return None
    
    def login(self):
        """Perform full login sequence"""
        print("\n" + "="*50)
        print(" LOGIN SEQUENCE")
        print("="*50)
        
        # Step 1: Send handshake
        handshake = self.build_handshake()
        self.send_packet(handshake, "handshake")
        
        time.sleep(0.5)
        response = self.recv_packet()
        
        # Step 2: Send login packet
        login_pkt = self.build_login_packet()
        self.send_packet(login_pkt, "login")
        
        time.sleep(1)
        response = self.recv_packet()
        
        if response:
            print("\n[+] Got response from server!")
            return True
        else:
            print("\n[-] No response from server")
            return False
    
    def disconnect(self):
        """Close connection"""
        if self.ssl_socket:
            self.ssl_socket.close()
        if self.socket:
            self.socket.close()
        print("[*] Disconnected")


def main():
    print("="*50)
    print(" Lords Mobile Protocol Client")
    print("="*50)
    print(f"\nDevice ID: {DEVICE_ID}")
    print(f"Token: {ACCESS_TOKEN[:50]}...")
    
    # Create client
    client = LordsClient(DEVICE_ID, ACCESS_TOKEN)
    
    # Connect
    if not client.connect():
        return
    
    # Login
    try:
        client.login()
    except Exception as e:
        print(f"[-] Error during login: {e}")
    
    # Keep connection for a moment
    time.sleep(2)
    
    # Disconnect
    client.disconnect()
    
    print("\n" + "="*50)
    print(" Done!")
    print("="*50)

if __name__ == "__main__":
    main()
