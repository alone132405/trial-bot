"""
Lords Mobile Client v6 - Try with TLS on port 5999
"""

import socket
import ssl
import struct
import time
from config import DEVICE_ID, ACCESS_TOKEN

HANDSHAKE = bytes.fromhex("01086e6a746c7661617a0c746c39356e6463386239346c")

def build_login(device_id, token, server_id=0xa10fd93a):
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

def try_with_ssl(host, port):
    """Connect with SSL/TLS"""
    print(f"\n{'='*50}")
    print(f"Trying {host}:{port} with SSL/TLS")
    print('='*50)
    
    try:
        # Raw socket first
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host, port))
        print("[+] TCP connected!")
        
        # Send handshake first (before TLS)
        print("[>] Sending handshake (pre-TLS)")
        sock.send(HANDSHAKE)
        time.sleep(0.3)
        
        # Try to get response
        sock.settimeout(2)
        try:
            resp = sock.recv(64)
            print(f"[<] Pre-TLS response: {resp.hex() if resp else 'none'} ({len(resp)} bytes)")
        except socket.timeout:
            print("[!] No pre-TLS response")
        
        # Now wrap with TLS
        print("[*] Upgrading to TLS...")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        print("[+] TLS handshake complete!")
        
        # Send login over TLS
        login = build_login(DEVICE_ID, ACCESS_TOKEN)
        print(f"[>] Sending login over TLS: {len(login)} bytes")
        ssl_sock.send(login)
        
        time.sleep(0.5)
        ssl_sock.settimeout(5)
        
        try:
            data = ssl_sock.recv(4096)
            print(f"[<] Got {len(data)} bytes over TLS!")
            if data:
                print(f"    {data[:50].hex()}")
            return True
        except socket.timeout:
            print("[!] Timeout waiting for TLS response")
            
    except ssl.SSLError as e:
        print(f"[-] SSL Error: {e}")
    except Exception as e:
        print(f"[-] Error: {e}")
    
    return False

def try_ssl_from_start(host, port):
    """Connect with SSL from the start"""
    print(f"\n{'='*50}")
    print(f"Trying {host}:{port} - SSL from start")
    print('='*50)
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        ssl_sock = context.wrap_socket(sock, server_hostname=host)
        ssl_sock.connect((host, port))
        print("[+] SSL connected!")
        
        # Send handshake
        print("[>] Sending handshake over SSL")
        ssl_sock.send(HANDSHAKE)
        time.sleep(0.3)
        
        # Send login
        login = build_login(DEVICE_ID, ACCESS_TOKEN)
        print(f"[>] Sending login: {len(login)} bytes")
        ssl_sock.send(login)
        
        time.sleep(0.5)
        ssl_sock.settimeout(3)
        
        data = ssl_sock.recv(4096)
        print(f"[<] Got {len(data)} bytes!")
        return True
        
    except Exception as e:
        print(f"[-] Error: {e}")
    
    return False

def main():
    print("="*60)
    print(" Lords Mobile Client v6 - TLS Testing")
    print("="*60)
    
    servers = [
        ("63.217.234.17", 5999),
        ("63.217.234.13", 5999),
    ]
    
    for host, port in servers:
        try_with_ssl(host, port)
        try_ssl_from_start(host, port)
    
    print("\n" + "="*60)
    print("Done!")
    print("="*60)

if __name__ == "__main__":
    main()
