"""
Lords Mobile API Explorer
Tests IGG API endpoints to understand the protocol

Since the access_key is encrypted in acc.json, we'll:
1. Try to understand the API structure
2. See what endpoints are public
3. Prepare for when we get the access key
"""

import requests
import json
import hashlib
import time
from config import IGG_ID, GAME_ID, DEVICE_ID

# Known IGG API endpoints (from community research)
ENDPOINTS = {
    "main": "https://cgi.igg.com",
    "api": "https://api.igg.com", 
    "game": "https://lordsmobile-api.igg.com",
    "login": "https://login.igg.com",
}

def test_endpoint(name, url):
    """Test if endpoint is reachable"""
    print(f"\nTesting {name}: {url}")
    try:
        response = requests.get(url, timeout=5)
        print(f"  Status: {response.status_code}")
        print(f"  Headers: {dict(response.headers)[:100] if response.headers else 'None'}...")
        if response.text:
            print(f"  Body preview: {response.text[:200]}...")
        return True
    except requests.exceptions.SSLError as e:
        print(f"  SSL Error: {e}")
        return False
    except requests.exceptions.ConnectionError as e:
        print(f"  Connection Error: {e}")
        return False
    except Exception as e:
        print(f"  Error: {e}")
        return False

def try_cgi_endpoint():
    """Try the main CGI endpoint used by the game"""
    print("\n" + "=" * 60)
    print("Testing cgi.igg.com API")
    print("=" * 60)
    
    # The game typically POSTs to cgi.igg.com with specific parameters
    url = "https://cgi.igg.com/lordsmobile/"
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    
    # Try a basic info request
    params = {
        "igg_id": IGG_ID,
        "game_id": GAME_ID,
        "device_id": DEVICE_ID,
        "cmd": "getServerList",  # Common command
        "timestamp": int(time.time()),
    }
    
    print(f"\nPOSTing to: {url}")
    print(f"Params: {json.dumps(params, indent=2)}")
    
    try:
        response = requests.post(url, data=params, headers=headers, timeout=10)
        print(f"\nResponse Status: {response.status_code}")
        print(f"Response Body: {response.text[:500] if response.text else 'Empty'}")
    except Exception as e:
        print(f"Error: {e}")

def main():
    print("=" * 60)
    print(" Lords Mobile API Explorer")
    print("=" * 60)
    print(f"\nUsing credentials:")
    print(f"  IGG ID: {IGG_ID}")
    print(f"  Game ID: {GAME_ID}")
    print(f"  Device ID: {DEVICE_ID}")
    
    # Test endpoints
    for name, url in ENDPOINTS.items():
        test_endpoint(name, url)
    
    # Try API call
    try_cgi_endpoint()
    
    print("\n" + "=" * 60)
    print("NEXT STEPS:")
    print("=" * 60)
    print("""
To get the access_key, you need to capture it when logging in:

Option 1: Use HTTP Catcher on your phone
  - Install HTTP Catcher (iOS) or similar app
  - Enable HTTPS decryption
  - Login to Lords Mobile
  - Look for requests containing "access_key" or "accessKey"

Option 2: Use Fiddler on PC
  - Install Fiddler: https://www.telerik.com/fiddler
  - Enable HTTPS decryption
  - Run the Lords Mobile Bot
  - Capture the login traffic

Option 3: Decrypt acc.json
  - The bot encrypts/decrypts this file
  - We'd need to reverse engineer the encryption key
  - This is in the DNGuard-protected code
""")

if __name__ == "__main__":
    main()
