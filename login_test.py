"""
Lords Mobile Protocol - Login Test Client
Tests authentication with captured credentials
"""

import requests
import json
import time
import hashlib
import base64
from config import IGG_ID, GAME_ID, DEVICE_ID, ACCESS_TOKEN

# Known IGG endpoints
ENDPOINTS = {
    "cgi": "https://cgi.igg.com",
    "api": "https://api.igg.com",
    "lordsmobile": "https://lordsmobile.igg.com",
}

def decode_token(token):
    """Decode the JWT-like access token"""
    parts = token.split('.')
    if len(parts) >= 1:
        # Add padding
        payload = parts[0] + '=='
        try:
            decoded = base64.b64decode(payload)
            return json.loads(decoded)
        except:
            pass
    return None

def test_cgi_login():
    """Test login via cgi.igg.com"""
    print("\n" + "="*50)
    print("Testing cgi.igg.com login...")
    print("="*50)
    
    url = "https://cgi.igg.com/lordsmobile/api/"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }
    
    # Build login payload
    payload = {
        "igg_id": IGG_ID,
        "game_id": GAME_ID,
        "device_id": DEVICE_ID,
        "access_token": ACCESS_TOKEN,
        "platform": "android",
        "version": "5.80",
        "timestamp": int(time.time()),
    }
    
    print(f"URL: {url}")
    print(f"Payload: {json.dumps(payload, indent=2)}")
    
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        print(f"\nStatus: {response.status_code}")
        print(f"Response: {response.text[:500]}")
        return response
    except Exception as e:
        print(f"Error: {e}")
        return None

def test_api_endpoint():
    """Test the API endpoint"""
    print("\n" + "="*50)
    print("Testing api.igg.com...")
    print("="*50)
    
    url = "https://api.igg.com/sdk/user/verify"
    
    headers = {
        "User-Agent": "UnityPlayer/2021.3.26f1",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    
    data = {
        "iggId": IGG_ID,
        "gameId": GAME_ID,
        "udid": DEVICE_ID,
        "accessToken": ACCESS_TOKEN,
    }
    
    print(f"URL: {url}")
    print(f"Data: {data}")
    
    try:
        response = requests.post(url, data=data, headers=headers, timeout=10)
        print(f"\nStatus: {response.status_code}")
        print(f"Response: {response.text[:500]}")
        return response
    except Exception as e:
        print(f"Error: {e}")
        return None

def test_socket_connection():
    """Test raw socket connection to game server"""
    import socket
    
    print("\n" + "="*50)
    print("Testing socket connection to game server...")
    print("="*50)
    
    # Common Lords Mobile game server ports
    servers_to_try = [
        ("game.igg.com", 443),
        ("lordsmobile.igg.com", 443),
        ("s1.lordsmobile.igg.com", 443),
    ]
    
    for host, port in servers_to_try:
        print(f"\nTrying {host}:{port}...")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            print(f"  Connected to {host}:{port}!")
            sock.close()
        except socket.gaierror:
            print(f"  DNS resolution failed for {host}")
        except socket.timeout:
            print(f"  Connection timed out")
        except Exception as e:
            print(f"  Error: {e}")

def main():
    print("="*50)
    print(" Lords Mobile - Login Test Client")
    print("="*50)
    
    # Show credentials
    print("\nCredentials:")
    print(f"  IGG ID: {IGG_ID}")
    print(f"  Game ID: {GAME_ID}")
    print(f"  Device ID: {DEVICE_ID}")
    print(f"  Token: {ACCESS_TOKEN[:50]}...")
    
    # Decode token
    token_data = decode_token(ACCESS_TOKEN)
    if token_data:
        print(f"\nDecoded Token:")
        print(f"  {json.dumps(token_data, indent=4)}")
    
    # Run tests
    test_socket_connection()
    test_cgi_login()
    test_api_endpoint()
    
    print("\n" + "="*50)
    print("Tests complete!")
    print("="*50)

if __name__ == "__main__":
    main()
