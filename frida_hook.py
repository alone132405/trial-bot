"""
Lords Mobile Bot - Frida Hook Script v2
Fixed API compatibility issues
"""

import frida
import sys
import json
import time

# Fixed Frida JavaScript
HOOK_SCRIPT = """
'use strict';

send({type: 'log', data: '[*] Frida script loaded!'});

// Hook network send
var sendPtr = Module.getExportByName('ws2_32.dll', 'send');
if (sendPtr) {
    send({type: 'log', data: '[+] Found send() at ' + sendPtr});
    
    Interceptor.attach(sendPtr, {
        onEnter: function(args) {
            var size = args[2].toInt32();
            if (size > 10 && size < 5000) {
                try {
                    var data = args[1].readCString(size);
                    if (data && data.length > 5) {
                        send({type: 'log', data: '[NET] ' + data.substring(0, 150)});
                        if (data.indexOf('access') > -1 || data.indexOf('igg') > -1 || data.indexOf('key') > -1) {
                            send({type: 'cred', data: data});
                        }
                    }
                } catch(e) {}
            }
        }
    });
}

// Hook WSASend (alternative network function)
var wsaSendPtr = Module.getExportByName('ws2_32.dll', 'WSASend');
if (wsaSendPtr) {
    send({type: 'log', data: '[+] Found WSASend()'});
}

// Hook file read
var readFilePtr = Module.getExportByName('kernel32.dll', 'ReadFile');
if (readFilePtr) {
    send({type: 'log', data: '[+] Found ReadFile()'});
    
    Interceptor.attach(readFilePtr, {
        onLeave: function(retval) {
            // Check return value
        }
    });
}

// Hook CreateFileW to detect acc.json access
var createFilePtr = Module.getExportByName('kernel32.dll', 'CreateFileW');
if (createFilePtr) {
    send({type: 'log', data: '[+] Hooking CreateFileW'});
    
    Interceptor.attach(createFilePtr, {
        onEnter: function(args) {
            try {
                var fname = args[0].readUtf16String();
                if (fname && fname.indexOf('acc.json') > -1) {
                    send({type: 'log', data: '[FILE] acc.json accessed!'});
                }
                if (fname && fname.indexOf('settings') > -1) {
                    send({type: 'log', data: '[FILE] ' + fname});
                }
            } catch(e) {}
        }
    });
}

// Hook SSL encrypt (schannel)
var encryptPtr = Module.getExportByName('secur32.dll', 'EncryptMessage');
if (encryptPtr) {
    send({type: 'log', data: '[+] Found EncryptMessage (SSL)'});
}

// Monitor fish.dll if loaded
setTimeout(function() {
    var fishBase = Module.findBaseAddress('fish.dll');
    if (fishBase) {
        send({type: 'log', data: '[+] fish.dll found at ' + fishBase});
        
        // List exports
        var exports = Module.enumerateExports('fish.dll');
        exports.forEach(function(exp) {
            send({type: 'log', data: '[fish.dll] ' + exp.type + ': ' + exp.name});
            
            // Hook the exports
            if (exp.type === 'function') {
                try {
                    Interceptor.attach(exp.address, {
                        onEnter: function(args) {
                            send({type: 'log', data: '[fish] ' + exp.name + ' called'});
                        }
                    });
                } catch(e) {}
            }
        });
    } else {
        send({type: 'log', data: '[!] fish.dll not loaded yet'});
    }
}, 2000);

send({type: 'log', data: '[*] Hooks installed. Waiting for activity...'});
"""

captured = {"logs": [], "credentials": []}

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        msg_type = payload.get('type', '')
        msg_data = payload.get('data', '')
        
        print(msg_data)
        captured['logs'].append(msg_data)
        
        if msg_type == 'cred':
            print("\n" + "!"*50)
            print("CREDENTIALS FOUND!")
            print("!"*50)
            print(msg_data[:500])
            print("!"*50 + "\n")
            captured['credentials'].append(msg_data)
            
            with open('captured_credentials.json', 'w') as f:
                json.dump(captured, f, indent=2)
                
    elif message['type'] == 'error':
        print(f"[ERR] {message.get('stack', message)}")

def main():
    print("="*50)
    print(" Frida Hook v2 - Lords Mobile Bot")
    print("="*50)
    
    try:
        print("\n[*] Attaching to LordsMobileBot.exe...")
        session = frida.attach("LordsMobileBot.exe")
        print("[+] Attached!")
        
        script = session.create_script(HOOK_SCRIPT)
        script.on('message', on_message)
        script.load()
        
        print("\n[*] Now START the account in the bot!")
        print("[*] Press Ctrl+C to stop\n")
        
        while True:
            time.sleep(1)
            
    except frida.ProcessNotFoundError:
        print("[!] LordsMobileBot.exe not running!")
        print("[!] Start the bot first!")
    except KeyboardInterrupt:
        print("\n[*] Stopped")
    except Exception as e:
        print(f"[!] Error: {e}")
    
    with open('captured_credentials.json', 'w') as f:
        json.dump(captured, f, indent=2)
    print(f"\nCaptured {len(captured['credentials'])} credentials")
    print("Saved to captured_credentials.json")

if __name__ == "__main__":
    main()
