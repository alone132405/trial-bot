"""
acc.json Decoder - Attempts to decode the encrypted account data
"""
import base64
import json
import os

# Read the acc.json file
ACC_FILE = r"d:\boottt\config\987303841\acc.json"

with open(ACC_FILE, 'r') as f:
    data = f.read().strip()

print("acc.json Analysis")
print("=" * 60)
print(f"Length: {len(data)} characters")
print(f"First 100 chars: {data[:100]}...")
print()

# Try base64 decode
try:
    decoded = base64.b64decode(data)
    print(f"Base64 decoded length: {len(decoded)} bytes")
    print(f"First 50 bytes (hex): {decoded[:50].hex()}")
    print()
    
    # Check if it's printable text
    try:
        text = decoded.decode('utf-8')
        print("Decoded as UTF-8 text:")
        print(text[:500])
    except:
        print("Not valid UTF-8 text - likely encrypted")
        
    # Check for JSON markers
    if b'{' in decoded[:20]:
        print("Contains JSON-like structure!")
    
    # Check for common encryption patterns
    # Look for patterns that might indicate encryption method
    
except Exception as e:
    print(f"Base64 decode failed: {e}")
    
# Check settings.json for any plain-text auth data
SETTINGS_FILE = r"d:\boottt\config\987303841\settings.json"

if os.path.exists(SETTINGS_FILE):
    with open(SETTINGS_FILE, 'r') as f:
        settings = json.load(f)
    
    print("\n" + "=" * 60)
    print("Checking settings.json for auth-related fields...")
    
    # Look for auth-related keys
    auth_keys = ['igg', 'IGG', 'device', 'Device', 'access', 'Access', 
                 'key', 'Key', 'token', 'Token', 'uid', 'UID', 'udid', 'UDID']
    
    def search_dict(d, parent_key=''):
        found = []
        for key, value in d.items():
            full_key = f"{parent_key}.{key}" if parent_key else key
            for auth in auth_keys:
                if auth.lower() in key.lower():
                    found.append((full_key, value))
                    break
            if isinstance(value, dict):
                found.extend(search_dict(value, full_key))
        return found
    
    results = search_dict(settings)
    
    if results:
        print("\nFound potential auth fields:")
        for key, value in results:
            if isinstance(value, str) and len(value) > 100:
                print(f"  {key}: {value[:50]}... (truncated)")
            else:
                print(f"  {key}: {value}")
    else:
        print("No auth-related fields found in settings.json")

print("\n" + "=" * 60)
print("Next Step: Use Wireshark to capture live traffic")
print("The access key is sent during login - we can intercept it there.")
