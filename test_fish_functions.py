"""
fish.dll Function Wrapper
Wraps the obfuscated functions: magnify, sprite_ctx_b, sprite_ctx_s
"""
import ctypes
from ctypes import c_char_p, c_int, c_void_p, c_size_t, POINTER, c_ubyte, create_string_buffer
import os

# Load fish.dll
FISH_DLL = ctypes.CDLL(r"d:\boottt\fish.dll")

# Get function references
magnify = FISH_DLL.magnify
sprite_ctx_b = FISH_DLL.sprite_ctx_b
sprite_ctx_s = FISH_DLL.sprite_ctx_s

print("fish.dll Functions Loaded!")
print("=" * 50)

# Try to determine function signatures by testing
# Common patterns: 
#   encode(input, input_len, output, output_len)
#   decode(input, input_len, output, output_len)

# Test: Try calling magnify with various signatures
test_data = b"Hello World Test Data!"

print("\nTesting magnify function...")
print("-" * 50)

# Test 1: magnify(data, len) -> returns something?
try:
    magnify.restype = c_void_p
    magnify.argtypes = [c_char_p, c_int]
    result = magnify(test_data, len(test_data))
    print(f"  Test 1 (data, len) -> {result}")
except Exception as e:
    print(f"  Test 1 failed: {e}")

# Test 2: magnify(data, len, output_buffer, output_len)
try:
    output = create_string_buffer(1024)
    magnify.restype = c_int
    magnify.argtypes = [c_char_p, c_int, c_char_p, c_int]
    result = magnify(test_data, len(test_data), output, 1024)
    print(f"  Test 2 (data, len, out, out_len) -> Return: {result}")
    if result > 0:
        print(f"    Output: {output.raw[:min(result, 50)]}")
except Exception as e:
    print(f"  Test 2 failed: {e}")

# Test 3: sprite_ctx_b - Maybe "build" context?
print("\nTesting sprite_ctx_b function...")
print("-" * 50)

try:
    sprite_ctx_b.restype = c_void_p
    sprite_ctx_b.argtypes = []  # No args - returns context pointer?
    ctx = sprite_ctx_b()
    print(f"  No args -> Context pointer: {hex(ctx) if ctx else 'NULL'}")
except Exception as e:
    print(f"  Test failed: {e}")

# Test 4: sprite_ctx_s - Maybe "set" context?
print("\nTesting sprite_ctx_s function...")
print("-" * 50)

try:
    sprite_ctx_s.restype = c_void_p
    sprite_ctx_s.argtypes = []
    result = sprite_ctx_s()
    print(f"  No args -> {hex(result) if result else 'NULL'}")
except Exception as e:
    print(f"  Test failed: {e}")

print("\n" + "=" * 50)
print("Function signature analysis complete.")
print("The actual usage requires deeper reverse engineering")
print("or observing how LordsMobileBot.exe calls these functions.")
