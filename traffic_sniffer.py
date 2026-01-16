"""
Lords Mobile Traffic Sniffer
Captures network packets to/from IGG servers to extract auth data

Requirements: pip install scapy
Run as Administrator for packet capture
"""

import socket
import struct
import sys
import json
from datetime import datetime

# Try to use scapy for packet capture
try:
    from scapy.all import sniff, TCP, IP, Raw
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    print("Scapy not installed. Install with: pip install scapy")
    print("Using socket-based connection monitor instead...")

# Known IGG endpoints
IGG_SERVERS = [
    "cgi.igg.com",
    "api.igg.com",
    "game.igg.com",
    "login.igg.com",
]

# Patterns to look for in traffic
AUTH_PATTERNS = [
    b"igg_id",
    b"IGG_ID",
    b"device_id",
    b"deviceId",
    b"access_key",
    b"accessKey",
    b"access_token",
    b"accessToken",
    b"udid",
    b"UDID",
    b"sign",
    b"timestamp",
]

captured_data = []

def analyze_packet(data):
    """Check packet for auth-related data"""
    findings = []
    for pattern in AUTH_PATTERNS:
        if pattern in data:
            # Try to extract the value
            try:
                # Look for JSON-like patterns
                idx = data.find(pattern)
                snippet = data[max(0, idx-20):min(len(data), idx+100)]
                findings.append({
                    "pattern": pattern.decode('utf-8', errors='ignore'),
                    "snippet": snippet.decode('utf-8', errors='ignore')
                })
            except:
                pass
    return findings

def packet_callback(packet):
    """Callback for each captured packet"""
    if TCP in packet and Raw in packet:
        payload = bytes(packet[Raw].load)
        
        # Check if going to/from IGG
        dst = packet[IP].dst if IP in packet else "unknown"
        src = packet[IP].src if IP in packet else "unknown"
        
        findings = analyze_packet(payload)
        
        if findings:
            print("\n" + "=" * 60)
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Auth data found!")
            print(f"  From: {src} -> To: {dst}")
            print(f"  Port: {packet[TCP].dport}")
            print(f"  Size: {len(payload)} bytes")
            
            for f in findings:
                print(f"\n  Pattern: {f['pattern']}")
                print(f"  Context: {f['snippet']}")
            
            captured_data.append({
                "time": datetime.now().isoformat(),
                "src": src,
                "dst": dst,
                "findings": findings,
                "raw": payload.hex()[:200]
            })
            
            # Save to file
            with open("captured_auth.json", "w") as f:
                json.dump(captured_data, f, indent=2)
            print("\n  Saved to captured_auth.json")

def simple_listener():
    """Simple approach: Monitor specific ports"""
    print("\n" + "=" * 60)
    print(" Simple Connection Monitor")
    print("=" * 60)
    print("\nThis monitors outgoing connections to known IGG servers.")
    print("Start the Lords Mobile Bot while this is running.")
    print("\nMonitoring... (Press Ctrl+C to stop)\n")
    
    import subprocess
    
    while True:
        try:
            # Use netstat to find connections
            result = subprocess.run(
                ['netstat', '-n', '-o'],
                capture_output=True,
                text=True
            )
            
            for line in result.stdout.split('\n'):
                # Look for port 443/80 connections
                if 'ESTABLISHED' in line:
                    if ':443' in line or ':80' in line:
                        # Check if it contains IGG-related IP
                        print(f"[Connection] {line.strip()}")
            
            import time
            time.sleep(5)
            
        except KeyboardInterrupt:
            print("\nStopping monitor...")
            break

def main():
    print("=" * 60)
    print(" Lords Mobile Traffic Sniffer")
    print("=" * 60)
    print("\nThis tool captures network traffic to find auth credentials.")
    print("\nInstructions:")
    print("1. Run this script AS ADMINISTRATOR")
    print("2. Start the Lords Mobile Bot")
    print("3. Connect an account")
    print("4. Watch for captured auth data")
    print()
    
    if HAS_SCAPY:
        print("Using Scapy for packet capture...")
        print("Sniffing on all interfaces...")
        print("Press Ctrl+C to stop\n")
        
        try:
            # Sniff TCP traffic on ports 80 and 443
            sniff(filter="tcp port 443 or tcp port 80", 
                  prn=packet_callback, 
                  store=0)
        except KeyboardInterrupt:
            print("\nStopping capture...")
        except PermissionError:
            print("\nERROR: Run as Administrator for packet capture!")
            simple_listener()
    else:
        simple_listener()
    
    print("\n" + "=" * 60)
    if captured_data:
        print(f"Captured {len(captured_data)} auth-related packets!")
        print("Check captured_auth.json for details.")
    else:
        print("No auth data captured.")
        print("\nAlternative: Use Wireshark with filter:")
        print('  tcp.port == 443 and frame contains "igg"')

if __name__ == "__main__":
    main()
