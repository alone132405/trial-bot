"""
Lords Mobile Bot - Frida Hook Script
Captures the access_key when the bot decrypts acc.json

Run this BEFORE starting the bot, or attach to running bot.
Requires: pip install frida frida-tools
Run as Administrator!
"""

import frida
import sys
import json
import time
import os

# Frida JavaScript to inject into the bot
HOOK_SCRIPT = """
'use strict';

// Log function
function log(msg) {
    send({type: 'log', data: msg});
}

log('[*] Frida script loaded!');
log('[*] Searching for .NET runtime...');

// Hook .NET CLR methods
try {
    // Try to find the CLR
    var clr = Module.findBaseAddress('clr.dll') || Module.findBaseAddress('coreclr.dll');
    
    if (clr) {
        log('[+] Found CLR at: ' + clr);
    } else {
        log('[!] CLR not found - bot may use different runtime');
    }
} catch (e) {
    log('[!] Error finding CLR: ' + e);
}

// Hook common crypto functions
var cryptFunctions = [
    'CryptDecrypt',
    'CryptEncrypt', 
    'BCryptDecrypt',
    'BCryptEncrypt',
];

cryptFunctions.forEach(function(funcName) {
    try {
        var func = Module.findExportByName('advapi32.dll', funcName) ||
                   Module.findExportByName('bcrypt.dll', funcName) ||
                   Module.findExportByName('ncrypt.dll', funcName);
        
        if (func) {
            log('[+] Found ' + funcName + ' at: ' + func);
            
            Interceptor.attach(func, {
                onEnter: function(args) {
                    this.funcName = funcName;
                    log('[>] ' + funcName + ' called');
                },
                onLeave: function(retval) {
                    log('[<] ' + this.funcName + ' returned');
                }
            });
        }
    } catch (e) {
        // Function not found, skip
    }
});

// Hook file operations to see when acc.json is read
try {
    var CreateFileW = Module.findExportByName('kernel32.dll', 'CreateFileW');
    if (CreateFileW) {
        log('[+] Hooking CreateFileW');
        
        Interceptor.attach(CreateFileW, {
            onEnter: function(args) {
                var filename = args[0].readUtf16String();
                if (filename && filename.indexOf('acc.json') !== -1) {
                    log('[!] acc.json accessed: ' + filename);
                }
            }
        });
    }
} catch (e) {
    log('[!] Error hooking CreateFileW: ' + e);
}

// Hook ReadFile to capture acc.json content being read
try {
    var ReadFile = Module.findExportByName('kernel32.dll', 'ReadFile');
    if (ReadFile) {
        Interceptor.attach(ReadFile, {
            onEnter: function(args) {
                this.buffer = args[1];
                this.bytesToRead = args[2].toInt32();
            },
            onLeave: function(retval) {
                if (this.bytesToRead > 100) {
                    try {
                        var data = this.buffer.readUtf8String(Math.min(200, this.bytesToRead));
                        if (data && (data.indexOf('access') !== -1 || data.indexOf('igg') !== -1)) {
                            log('[!] Potential credential data read: ' + data.substring(0, 100));
                        }
                    } catch (e) {}
                }
            }
        });
    }
} catch (e) {
    log('[!] Error hooking ReadFile: ' + e);
}

// Hook network send to capture outgoing data
try {
    var send_func = Module.findExportByName('ws2_32.dll', 'send');
    if (send_func) {
        log('[+] Hooking network send()');
        
        Interceptor.attach(send_func, {
            onEnter: function(args) {
                var size = args[2].toInt32();
                if (size > 10 && size < 10000) {
                    try {
                        var data = args[1].readUtf8String(Math.min(size, 500));
                        if (data) {
                            log('[NET] Sending: ' + data.substring(0, 200));
                            
                            // Look for credentials
                            if (data.indexOf('access') !== -1 || 
                                data.indexOf('token') !== -1 ||
                                data.indexOf('igg_id') !== -1) {
                                log('[!!!] CREDENTIALS FOUND IN NETWORK DATA!');
                                send({type: 'credentials', data: data});
                            }
                        }
                    } catch (e) {}
                }
            }
        });
    }
} catch (e) {
    log('[!] Error hooking send: ' + e);
}

// Hook SSL/TLS write for HTTPS traffic
try {
    var secur32 = Module.findBaseAddress('secur32.dll');
    var schannel = Module.findBaseAddress('schannel.dll');
    
    // EncryptMessage is used for SSL/TLS
    var EncryptMessage = Module.findExportByName('secur32.dll', 'EncryptMessage');
    if (EncryptMessage) {
        log('[+] Hooking EncryptMessage (SSL traffic)');
        
        Interceptor.attach(EncryptMessage, {
            onEnter: function(args) {
                // args[1] contains the message buffers before encryption
                try {
                    var pMessage = args[1];
                    // SecBufferDesc structure
                    var cBuffers = pMessage.add(4).readU32();
                    var pBuffers = pMessage.add(8).readPointer();
                    
                    for (var i = 0; i < cBuffers; i++) {
                        var bufferPtr = pBuffers.add(i * 16);
                        var cbBuffer = bufferPtr.readU32();
                        var bufferType = bufferPtr.add(4).readU32();
                        var pvBuffer = bufferPtr.add(8).readPointer();
                        
                        if (bufferType === 1 && cbBuffer > 0 && cbBuffer < 5000) {
                            try {
                                var data = pvBuffer.readUtf8String(Math.min(cbBuffer, 500));
                                if (data && data.length > 10) {
                                    log('[SSL] Pre-encrypt: ' + data.substring(0, 200));
                                    
                                    if (data.indexOf('access') !== -1 || 
                                        data.indexOf('key') !== -1 ||
                                        data.indexOf('igg') !== -1 ||
                                        data.indexOf('device') !== -1) {
                                        log('[!!!] CREDENTIALS IN SSL DATA!');
                                        send({type: 'credentials', data: data});
                                    }
                                }
                            } catch (e) {}
                        }
                    }
                } catch (e) {}
            }
        });
    }
} catch (e) {
    log('[!] Error hooking EncryptMessage: ' + e);
}

log('[*] All hooks installed. Wait for bot to connect...');
"""

# Captured credentials storage
captured = {
    "logs": [],
    "credentials": []
}

def on_message(message, data):
    """Callback for Frida messages"""
    if message['type'] == 'send':
        payload = message['payload']
        
        if payload['type'] == 'log':
            print(payload['data'])
            captured['logs'].append(payload['data'])
            
        elif payload['type'] == 'credentials':
            print("\n" + "=" * 60)
            print("!!! CREDENTIALS CAPTURED !!!")
            print("=" * 60)
            print(payload['data'])
            print("=" * 60 + "\n")
            captured['credentials'].append(payload['data'])
            
            # Save immediately
            with open('captured_credentials.json', 'w') as f:
                json.dump(captured, f, indent=2)
            print("Saved to captured_credentials.json")
            
    elif message['type'] == 'error':
        print(f"[ERROR] {message['stack']}")

def attach_to_bot():
    """Attach Frida to running LordsMobileBot.exe"""
    print("=" * 60)
    print(" Lords Mobile Bot - Credential Capture")
    print("=" * 60)
    print("\nLooking for LordsMobileBot.exe...")
    
    try:
        # Try to attach to running process
        session = frida.attach("LordsMobileBot.exe")
        print("[+] Attached to LordsMobileBot.exe!")
        
        print("[*] Injecting hooks...")
        script = session.create_script(HOOK_SCRIPT)
        script.on('message', on_message)
        script.load()
        
        print("\n[*] Hooks active! Now connect an account in the bot.")
        print("[*] Press Ctrl+C to stop and see captured data.\n")
        
        # Keep running
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopping...")
            
        session.detach()
        
    except frida.ProcessNotFoundError:
        print("[!] LordsMobileBot.exe is not running!")
        print("[!] Please start the bot first, then run this script.")
        return False
        
    except frida.PermissionDeniedError:
        print("[!] Permission denied!")
        print("[!] Run this script as Administrator.")
        return False
        
    except Exception as e:
        print(f"[!] Error: {e}")
        return False
    
    return True

def main():
    print("\nInstructions:")
    print("1. Start LordsMobileBot.exe (don't connect account yet)")
    print("2. Run this script as Administrator")
    print("3. Connect an account in the bot")
    print("4. Watch for captured credentials\n")
    
    result = attach_to_bot()
    
    print("\n" + "=" * 60)
    print("Results:")
    print("=" * 60)
    
    if captured['credentials']:
        print(f"\n[+] Captured {len(captured['credentials'])} credential entries!")
        for i, cred in enumerate(captured['credentials']):
            print(f"\n--- Entry {i+1} ---")
            print(cred[:500])
    else:
        print("\n[-] No credentials captured.")
        print("    The bot may not have connected or uses different methods.")
    
    # Save all results
    with open('captured_credentials.json', 'w') as f:
        json.dump(captured, f, indent=2)
    print("\nAll logs saved to captured_credentials.json")

if __name__ == "__main__":
    main()
