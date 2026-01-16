"""
Lords Mobile Protocol Bot - Core Module
Based on community research: Uses DES/AES encryption

This module provides packet encoding/decoding for Lords Mobile
without relying on fish.dll (which has obfuscated exports).
"""

from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import struct
import socket
import json
import hashlib
import time

# Known encryption parameters (from community reverse engineering)
# These may need to be updated if the game changes them

# DES key - 8 bytes (from Assembly-CSharp.dll analysis)
# Note: This is a placeholder - actual key from game binary needed
DES_KEY = b"JeffHapp"  # Common key found in community discussions

# AES key - 16/24/32 bytes for AES-128/192/256
AES_KEY = b"0123456789ABCDEF"  # Placeholder

class PacketEncoder:
    """Handles encoding of outgoing packets"""
    
    def __init__(self, use_aes=False):
        self.use_aes = use_aes
        if use_aes:
            self.cipher = AES.new(AES_KEY, AES.MODE_ECB)
            self.block_size = 16
        else:
            self.cipher = DES.new(DES_KEY, DES.MODE_ECB)
            self.block_size = 8
    
    def encode(self, data: bytes) -> bytes:
        """Encode/encrypt packet data"""
        # Pad to block size
        padded = pad(data, self.block_size)
        # Encrypt
        encrypted = self.cipher.encrypt(padded)
        return encrypted
    
    def decode(self, data: bytes) -> bytes:
        """Decode/decrypt packet data"""
        # Decrypt
        decrypted = self.cipher.decrypt(data)
        # Unpad
        try:
            unpadded = unpad(decrypted, self.block_size)
            return unpadded
        except ValueError:
            # Padding error - return raw
            return decrypted


class MessageBuilder:
    """Builds Lords Mobile protocol messages"""
    
    # Message type constants (based on community research)
    MSG_LOGIN = 0x01
    MSG_HEARTBEAT = 0x02
    MSG_GET_PLAYER_INFO = 0x10
    MSG_GET_RESOURCES = 0x11
    MSG_TRAIN_TROOPS = 0x20
    MSG_RESEARCH = 0x21
    MSG_BUILD = 0x22
    MSG_GATHER = 0x30
    MSG_RALLY_JOIN = 0x31
    MSG_RALLY_CREATE = 0x32
    
    @staticmethod
    def build_header(msg_type: int, payload_len: int) -> bytes:
        """Build message header"""
        # Header format: [magic: 2 bytes][type: 2 bytes][length: 4 bytes]
        header = struct.pack('<HHII', 0xCAFE, msg_type, payload_len, 0)
        return header
    
    @staticmethod
    def build_login_packet(igg_id: int, device_id: str, access_key: str) -> bytes:
        """Build login packet"""
        payload = {
            "igg_id": igg_id,
            "device_id": device_id,
            "access_key": access_key,
            "timestamp": int(time.time()),
            "version": "5.80"  # Game version
        }
        return json.dumps(payload).encode('utf-8')
    
    @staticmethod
    def build_resource_query() -> bytes:
        """Build resource query packet"""
        payload = {"action": "get_resources"}
        return json.dumps(payload).encode('utf-8')


class LordsMobileClient:
    """Main client for Lords Mobile protocol communication"""
    
    # Server endpoints (may need updating)
    GAME_SERVER = "cgi.igg.com"
    GAME_PORT = 443
    
    def __init__(self, igg_id: int, device_id: str, access_key: str):
        self.igg_id = igg_id
        self.device_id = device_id
        self.access_key = access_key
        self.encoder = PacketEncoder()
        self.socket = None
        self.session_id = None
    
    def connect(self):
        """Connect to game server"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.GAME_SERVER, self.GAME_PORT))
            print(f"Connected to {self.GAME_SERVER}:{self.GAME_PORT}")
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from server"""
        if self.socket:
            self.socket.close()
            self.socket = None
    
    def send_packet(self, msg_type: int, payload: bytes):
        """Send an encrypted packet"""
        # Encrypt payload
        encrypted = self.encoder.encode(payload)
        
        # Build and send
        header = MessageBuilder.build_header(msg_type, len(encrypted))
        packet = header + encrypted
        
        self.socket.send(packet)
        print(f"Sent packet type {msg_type}, {len(packet)} bytes")
    
    def receive_packet(self) -> tuple:
        """Receive and decrypt a packet"""
        # Read header
        header = self.socket.recv(12)
        if len(header) < 12:
            return None, None
            
        magic, msg_type, length, _ = struct.unpack('<HHII', header)
        
        # Read encrypted payload
        encrypted_payload = self.socket.recv(length)
        
        # Decrypt
        payload = self.encoder.decode(encrypted_payload)
        
        return msg_type, payload
    
    def login(self) -> bool:
        """Perform login sequence"""
        payload = MessageBuilder.build_login_packet(
            self.igg_id, self.device_id, self.access_key
        )
        self.send_packet(MessageBuilder.MSG_LOGIN, payload)
        
        msg_type, response = self.receive_packet()
        if response:
            print(f"Login response: {response[:100]}...")
            return True
        return False


# Demo usage
if __name__ == "__main__":
    print("Lords Mobile Protocol Bot - Demo")
    print("=" * 50)
    
    # Test encryption
    encoder = PacketEncoder()
    test_data = b"Hello Lords Mobile!"
    
    encrypted = encoder.encode(test_data)
    print(f"Original: {test_data}")
    print(f"Encrypted: {encrypted.hex()[:50]}...")
    
    decrypted = encoder.decode(encrypted)
    print(f"Decrypted: {decrypted}")
    print(f"Match: {test_data == decrypted}")
    
    print("\n" + "=" * 50)
    print("To use, you need:")
    print("1. Your IGG ID (from game settings)")
    print("2. Device ID (from intercepted traffic)")
    print("3. Access Key (from intercepted traffic)")
    print("\nUse Wireshark/mitmproxy to capture these values.")
