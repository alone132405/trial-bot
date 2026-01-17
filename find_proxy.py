"""
Find Proxy Server - Capture the first connection the bot makes
"""

import frida
import json
import time

HOOK_SCRIPT = r'''
send('[*] Proxy finder loaded!');

setTimeout(function() {
    
    // Method 1: Hook connect in ws2_32.dll
    try {
        var ws2 = Process.getModuleByName('ws2_32.dll');
        var connectAddr = ws2.getExportByName('connect');
        if (connectAddr) {
            Interceptor.attach(connectAddr, {
                onEnter: function(args) {
                    try {
                        var sockaddr = args[1];
                        var family = sockaddr.readU16();
                        
                        if (family == 2) { // AF_INET
                            var portRaw = sockaddr.add(2).readU16();
                            var port = ((portRaw & 0xFF) << 8) | ((portRaw >> 8) & 0xFF);
                            
                            var b0 = sockaddr.add(4).readU8();
                            var b1 = sockaddr.add(5).readU8();
                            var b2 = sockaddr.add(6).readU8();
                            var b3 = sockaddr.add(7).readU8();
                            var ip = b0 + '.' + b1 + '.' + b2 + '.' + b3;
                            
                            send({t: 'connect', ip: ip, port: port});
                        }
                    } catch(e) {
                        send('[!] connect error: ' + e);
                    }
                }
            });
            send('[+] connect hooked');
        }
    } catch(e) {
        send('[!] connect hook failed: ' + e);
    }
    
    // Method 2: Hook WSAConnect
    try {
        var wsaConnectAddr = Module.findExportByName('ws2_32.dll', 'WSAConnect');
        if (wsaConnectAddr) {
            Interceptor.attach(wsaConnectAddr, {
                onEnter: function(args) {
                    try {
                        var sockaddr = args[1];
                        var family = sockaddr.readU16();
                        
                        if (family == 2) {
                            var portRaw = sockaddr.add(2).readU16();
                            var port = ((portRaw & 0xFF) << 8) | ((portRaw >> 8) & 0xFF);
                            
                            var ip = sockaddr.add(4).readU8() + '.' +
                                    sockaddr.add(5).readU8() + '.' +
                                    sockaddr.add(6).readU8() + '.' +
                                    sockaddr.add(7).readU8();
                            
                            send({t: 'wsa_connect', ip: ip, port: port});
                        }
                    } catch(e) {}
                }
            });
            send('[+] WSAConnect hooked');
        }
    } catch(e) {}
    
    // Method 3: Hook getaddrinfo
    try {
        var getaddrinfoAddr = Module.findExportByName('ws2_32.dll', 'getaddrinfo');
        if (getaddrinfoAddr) {
            Interceptor.attach(getaddrinfoAddr, {
                onEnter: function(args) {
                    try {
                        var hostname = args[0].readCString();
                        var service = args[1].isNull() ? 'null' : args[1].readCString();
                        if (hostname && hostname.length > 0) {
                            send({t: 'dns', host: hostname, service: service});
                        }
                    } catch(e) {}
                }
            });
            send('[+] getaddrinfo hooked');
        }
    } catch(e) {}
    
    send('[*] Ready! Start an account...');
    
}, 500);
'''

connections = []

def on_message(msg, _):
    if msg['type'] == 'send':
        p = msg['payload']
        
        if isinstance(p, str):
            print(p)
        elif p.get('t') == 'connect':
            print(f"[CONNECT] {p['ip']}:{p['port']}")
            connections.append(f"{p['ip']}:{p['port']}")
        elif p.get('t') == 'wsa_connect':
            print(f"[WSA_CONNECT] {p['ip']}:{p['port']}")
            connections.append(f"WSA:{p['ip']}:{p['port']}")
        elif p.get('t') == 'dns':
            print(f"[DNS] {p['host']} -> {p['service']}")
            connections.append(f"DNS:{p['host']}")

def main():
    print("="*60)
    print(" Find Proxy Server")
    print("="*60)
    print("\n1. Run this")
    print("2. Start ONE account")
    print("3. Watch for [CONNECT] messages!")
    print("\nPress Ctrl+C to stop\n")
    
    try:
        session = frida.attach("LordsMobileBot.exe")
        print("[+] Attached!")
        
        script = session.create_script(HOOK_SCRIPT)
        script.on('message', on_message)
        script.load()
        
        while True:
            time.sleep(1)
            
    except frida.ProcessNotFoundError:
        print("[!] Bot not running!")
    except KeyboardInterrupt:
        print("\n[*] Stopped")
    
    print("\n" + "="*60)
    print(" CONNECTIONS FOUND:")
    print("="*60)
    for c in connections[:20]:
        print(f"  - {c}")

if __name__ == "__main__":
    main()
