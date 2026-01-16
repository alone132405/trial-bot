"""
Enhanced Frida Hook - Captures detailed packet data
Saves binary data for protocol analysis
"""

import frida
import json
import time
import os

HOOK_SCRIPT = r'''
send('[*] Enhanced hook loaded');

var packets = [];

setTimeout(function() {
    
    // Hook send with hex output
    try {
        var ws2 = Process.getModuleByName('ws2_32.dll');
        var sendAddr = ws2.getExportByName('send');
        
        Interceptor.attach(sendAddr, {
            onEnter: function(args) {
                var len = args[2].toInt32();
                if (len > 5 && len < 8000) {
                    try {
                        // Get raw bytes as hex
                        var bytes = args[1].readByteArray(len);
                        var hex = Array.from(new Uint8Array(bytes))
                            .map(b => b.toString(16).padStart(2, '0'))
                            .join('');
                        
                        send({
                            type: 'packet',
                            direction: 'SEND',
                            length: len,
                            hex: hex,
                            ascii: args[1].readCString(Math.min(len, 200))
                        });
                    } catch(e) {}
                }
            }
        });
        send('[+] send() hooked');
    } catch(e) {
        send('[!] send hook failed: ' + e);
    }
    
    // Hook recv
    try {
        var ws2 = Process.getModuleByName('ws2_32.dll');
        var recvAddr = ws2.getExportByName('recv');
        
        Interceptor.attach(recvAddr, {
            onLeave: function(retval) {
                var len = retval.toInt32();
                if (len > 5 && len < 8000) {
                    // Can't easily get buffer here, just log
                    send({type: 'log', data: '[RECV] ' + len + ' bytes'});
                }
            }
        });
        send('[+] recv() hooked');
    } catch(e) {}
    
    // Hook fish.dll functions
    try {
        var fish = Process.getModuleByName('fish.dll');
        if (fish) {
            var exports = fish.enumerateExports();
            exports.forEach(function(exp) {
                if (exp.type === 'function') {
                    try {
                        Interceptor.attach(exp.address, {
                            onEnter: function(args) {
                                // Try to read first arg as potential data
                                try {
                                    var data = args[0].readCString(50);
                                    if (data && data.length > 0) {
                                        send({type: 'fish', func: exp.name, arg0: data});
                                    }
                                } catch(e) {}
                            },
                            onLeave: function(retval) {
                                send({type: 'fish_ret', func: exp.name});
                            }
                        });
                        send('[+] fish.' + exp.name + ' hooked');
                    } catch(e) {}
                }
            });
        }
    } catch(e) {
        send('[!] fish.dll hook failed: ' + e);
    }
    
    send('[*] Ready! Perform actions in the bot...');
    
}, 1000);
'''

all_data = {
    "logs": [],
    "packets": [],
    "fish_calls": []
}

def on_message(msg, data):
    if msg['type'] == 'send':
        payload = msg['payload']
        
        if isinstance(payload, str):
            print(payload)
            all_data['logs'].append(payload)
        elif payload.get('type') == 'packet':
            direction = payload['direction']
            length = payload['length']
            hex_data = payload['hex'][:100]  # First 100 hex chars
            
            print(f"[{direction}] {length} bytes: {hex_data}...")
            all_data['packets'].append(payload)
            
            # Save after each packet
            with open('packets.json', 'w') as f:
                json.dump(all_data, f, indent=2)
                
        elif payload.get('type') == 'fish':
            print(f"[FISH] {payload['func']}: {payload.get('arg0', '')[:50]}")
            all_data['fish_calls'].append(payload)
            
        elif payload.get('type') == 'fish_ret':
            print(f"[FISH] {payload['func']} returned")
            
        elif payload.get('type') == 'log':
            print(payload['data'])
            
    elif msg['type'] == 'error':
        print(f"[ERR] {msg}")

def main():
    print("="*60)
    print(" Enhanced Packet Capture")
    print("="*60)
    print("\nInstructions:")
    print("1. Make sure LordsMobileBot.exe is running")
    print("2. This will capture all network packets")
    print("3. Perform actions in the bot:")
    print("   - Click different tabs")
    print("   - View resources")
    print("   - Open settings")
    print("4. Press Ctrl+C to stop and save\n")
    
    try:
        session = frida.attach("LordsMobileBot.exe")
        print("[+] Attached to bot")
        
        script = session.create_script(HOOK_SCRIPT)
        script.on('message', on_message)
        script.load()
        
        print("\n[*] Capturing... Press Ctrl+C to stop\n")
        
        while True:
            time.sleep(1)
            
    except frida.ProcessNotFoundError:
        print("[!] Bot not running!")
    except KeyboardInterrupt:
        print("\n[*] Stopped")
    
    # Save final data
    with open('packets.json', 'w') as f:
        json.dump(all_data, f, indent=2)
    
    print(f"\nCaptured {len(all_data['packets'])} packets")
    print(f"Saved to packets.json")

if __name__ == "__main__":
    main()
