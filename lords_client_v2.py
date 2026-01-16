"""
Lords Mobile Protocol Client v2
Tries multiple connection approaches based on captured traffic analysis
"""

import socket
import ssl
import struct
import time
from config import IGG_ID, GAME_ID, DEVICE_ID, ACCESS_TOKEN

class LordsClientV2:
    """Lords Mobile Protocol Client - Version 2"""
    
    def __init__(self, device_id, access_token):
        self.device_id = device_id
        self.access_token = access_token
        self.socket = None
        
    def try_raw_connection(self, host, port):
        """Try raw TCP connection (no SSL)"""
        print(f"\n[*] Trying RAW TCP to {host}:{port}...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            print("[+] Connected!")
            return sock
        except Exception as e:
            print(f"[-] Failed: {e}")
            return None
            
    def try_ssl_connection(self, host, port):
        """Try SSL connection"""
        print(f"\n[*] Trying SSL to {host}:{port}...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            ssl_sock = context.wrap_socket(sock, server_hostname=host)
            print("[+] SSL connected!")
            return ssl_sock
        except Exception as e:
            print(f"[-] Failed: {e}")
            return None
    
    def build_handshake(self):
        """Handshake from captured traffic"""
        return bytes.fromhex("01086e6a746c7661617a0c746c39356e6463386239346c")
    
    def build_socks_greeting(self):
        """SOCKS5 greeting (captured: 05 01 00 01 ...)"""
        return bytes([0x05, 0x01, 0x00])
    
    def build_login_packet(self, server_id=0xa10fd93a):
        """Build complete 582-byte login packet"""
        # Exact structure from captured traffic
        packet = bytearray(582)
        
        # Header
        packet[0:4] = bytes([0x46, 0x02, 0x13, 0x04])
        
        # Server ID (little endian)
        packet[4:8] = struct.pack('<I', server_id)
        
        # Zeros
        packet[8:12] = bytes([0x00, 0x00, 0x00, 0x00])
        
        # Device marker
        packet[12:18] = bytes([0xb9, 0x02, 0x1d, 0x01, 0x01, 0x01])
        
        # Device ID (36 chars)
        device_bytes = self.device_id.encode('ascii')
        packet[18:54] = device_bytes
        
        # Zeros (padding)
        packet[54:69] = bytes(15)
        
        # Token marker
        packet[69:71] = bytes([0xa0, 0x01])
        
        # Token
        token_bytes = self.access_token.encode('ascii')
        for i, b in enumerate(token_bytes):
            if 71 + i < 582:
                packet[71 + i] = b
        
        return bytes(packet)
    
    def send_and_recv(self, sock, data, description):
        """Send data and wait for response"""
        print(f"\n[>] Sending {description}: {len(data)} bytes")
        print(f"    {data[:40].hex()}")
        
        try:
            sock.send(data)
            time.sleep(0.5)
            
            sock.settimeout(3)
            response = sock.recv(4096)
            print(f"[<] Received: {len(response)} bytes")
            if response:
                print(f"    {response[:50].hex()}")
            return response
        except socket.timeout:
            print("[!] Timeout")
            return None
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def test_approach_1(self):
        """Direct connection to lordsmobile.igg.com via SSL"""
        print("\n" + "="*50)
        print(" APPROACH 1: Direct SSL")
        print("="*50)
        
        sock = self.try_ssl_connection("lordsmobile.igg.com", 443)
        if not sock:
            return False
            
        # Send login directly
        login = self.build_login_packet()
        resp = self.send_and_recv(sock, login, "login packet")
        
        sock.close()
        return resp is not None
    
    def test_approach_2(self):
        """Try different ports"""
        print("\n" + "="*50)
        print(" APPROACH 2: Try different ports")
        print("="*50)
        
        ports = [80, 8080, 443, 9339, 9050]
        
        for port in ports:
            sock = self.try_raw_connection("lordsmobile.igg.com", port)
            if sock:
                # Send handshake
                hs = self.build_handshake()
                resp = self.send_and_recv(sock, hs, f"handshake to port {port}")
                sock.close()
                
                if resp:
                    print(f"[+] Got response on port {port}!")
                    return True
                    
        return False
    
    def test_approach_3(self):
        """Try cgi.igg.com endpoints"""
        print("\n" + "="*50)
        print(" APPROACH 3: CGI endpoint")
        print("="*50)
        
        import urllib.request
        import json
        
        url = "https://cgi.igg.com/lordsmobile/connect"
        
        headers = {
            "Content-Type": "application/octet-stream",
            "User-Agent": "LordsMobile/5.80",
        }
        
        login = self.build_login_packet()
        
        try:
            req = urllib.request.Request(url, data=login, headers=headers, method='POST')
            with urllib.request.urlopen(req, timeout=10) as response:
                data = response.read()
                print(f"[<] Response: {data[:100]}")
                return True
        except Exception as e:
            print(f"[-] Failed: {e}")
            return False


def main():
    print("="*50)
    print(" Lords Mobile Client v2 - Testing Approaches")
    print("="*50)
    print(f"\nDevice ID: {DEVICE_ID}")
    print(f"Token: {ACCESS_TOKEN[:40]}...")
    
    client = LordsClientV2(DEVICE_ID, ACCESS_TOKEN)
    
    # Try each approach
    client.test_approach_1()
    client.test_approach_2()
    client.test_approach_3()
    
    print("\n" + "="*50)
    print(" Testing complete!")
    print("="*50)

if __name__ == "__main__":
    main()
