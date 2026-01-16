"""
Lords Mobile Bot - Simple Frida Hook v3
Minimal version to ensure it works
"""

import frida
import json
import time

# Minimal working Frida script
HOOK_SCRIPT = r'''
send('[*] Script loaded');

// Wait for modules to load then hook
setTimeout(function() {
    
    // Find fish.dll
    try {
        var mods = Process.enumerateModules();
        mods.forEach(function(m) {
            if (m.name.toLowerCase().indexOf('fish') >= 0) {
                send('[+] Found: ' + m.name + ' at ' + m.base);
            }
        });
    } catch(e) {
        send('[!] Module enum error: ' + e);
    }
    
    // Hook ws2_32.dll send
    try {
        var ws2 = Process.getModuleByName('ws2_32.dll');
        var sendAddr = ws2.getExportByName('send');
        send('[+] send() at ' + sendAddr);
        
        Interceptor.attach(sendAddr, {
            onEnter: function(args) {
                var len = args[2].toInt32();
                if (len > 10 && len < 3000) {
                    try {
                        var buf = args[1].readCString(len);
                        if (buf) {
                            send('[NET] ' + buf.substring(0, 200));
                        }
                    } catch(e) {}
                }
            }
        });
    } catch(e) {
        send('[!] send hook error: ' + e);
    }
    
    // Hook kernel32 CreateFileW
    try {
        var k32 = Process.getModuleByName('kernel32.dll');
        var cfAddr = k32.getExportByName('CreateFileW');
        send('[+] CreateFileW at ' + cfAddr);
        
        Interceptor.attach(cfAddr, {
            onEnter: function(args) {
                try {
                    var path = args[0].readUtf16String();
                    if (path && path.indexOf('acc.json') >= 0) {
                        send('[!] ACC.JSON ACCESSED: ' + path);
                    }
                } catch(e) {}
            }
        });
    } catch(e) {
        send('[!] CreateFileW hook error: ' + e);
    }
    
    send('[*] Hooks ready - now START the account!');
    
}, 1000);
'''

captured = []

def on_message(msg, data):
    if msg['type'] == 'send':
        payload = msg['payload']
        print(payload)
        captured.append(payload)
        
        # Save periodically
        if len(captured) % 10 == 0:
            with open('captured.json', 'w') as f:
                json.dump(captured, f, indent=2)
    else:
        print(f"[MSG] {msg}")

def main():
    print("="*50)
    print(" Simple Frida Hook v3")
    print("="*50)
    
    try:
        print("\nAttaching to LordsMobileBot.exe...")
        session = frida.attach("LordsMobileBot.exe")
        print("Attached!\n")
        
        script = session.create_script(HOOK_SCRIPT)
        script.on('message', on_message)
        script.load()
        
        print("Waiting for hooks... Press Ctrl+C to stop\n")
        
        while True:
            time.sleep(1)
            
    except frida.ProcessNotFoundError:
        print("ERROR: LordsMobileBot.exe not running!")
    except KeyboardInterrupt:
        print("\nStopped")
    except Exception as e:
        print(f"Error: {e}")
    
    with open('captured.json', 'w') as f:
        json.dump(captured, f, indent=2)
    print(f"\nSaved {len(captured)} entries to captured.json")

if __name__ == "__main__":
    main()
