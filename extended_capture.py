"""
Extended Capture - Find where handshake tokens come from
Hooks HTTP, DNS, and socket functions to capture the full flow
"""

import frida
import json
import time

HOOK_SCRIPT = r'''
send('[*] Extended capture loaded!');

var allData = [];

setTimeout(function() {
    
    // Hook DNS resolution
    try {
        var getaddrinfo = Module.findExportByName('ws2_32.dll', 'getaddrinfo');
        if (getaddrinfo) {
            Interceptor.attach(getaddrinfo, {
                onEnter: function(args) {
                    try {
                        var host = args[0].readCString();
                        if (host) {
                            send({t:'dns', host: host});
                        }
                    } catch(e) {}
                }
            });
            send('[+] DNS hooked');
        }
    } catch(e) {}
    
    // Hook connect to see where bot connects first
    try {
        var connect = Module.findExportByName('ws2_32.dll', 'connect');
        if (connect) {
            Interceptor.attach(connect, {
                onEnter: function(args) {
                    try {
                        var sockaddr = args[1];
                        var family = sockaddr.readU16();
                        if (family == 2) { // AF_INET
                            var port = sockaddr.add(2).readU16();
                            port = ((port & 0xFF) << 8) | ((port >> 8) & 0xFF); // swap bytes
                            var ip = sockaddr.add(4).readU8() + '.' +
                                    sockaddr.add(5).readU8() + '.' +
                                    sockaddr.add(6).readU8() + '.' +
                                    sockaddr.add(7).readU8();
                            send({t:'connect', ip: ip, port: port});
                        }
                    } catch(e) {}
                }
            });
            send('[+] connect hooked');
        }
    } catch(e) {}
    
    // Hook send with full context
    try {
        var ws2 = Process.getModuleByName('ws2_32.dll');
        var sendAddr = ws2.getExportByName('send');
        
        Interceptor.attach(sendAddr, {
            onEnter: function(args) {
                var len = args[2].toInt32();
                if (len > 5 && len < 5000) {
                    try {
                        var bytes = args[1].readByteArray(Math.min(len, 500));
                        var hex = Array.from(new Uint8Array(bytes))
                            .map(b => b.toString(16).padStart(2, '0'))
                            .join('');
                        send({t:'send', len: len, hex: hex});
                    } catch(e) {}
                }
            }
        });
        send('[+] send hooked');
    } catch(e) {}
    
    // Hook recv to see server responses
    try {
        var ws2 = Process.getModuleByName('ws2_32.dll');
        var recvAddr = ws2.getExportByName('recv');
        
        Interceptor.attach(recvAddr, {
            onLeave: function(retval) {
                var len = retval.toInt32();
                if (len > 0) {
                    send({t:'recv', len: len});
                }
            }
        });
        send('[+] recv hooked');
    } catch(e) {}
    
    // Hook WinHTTP functions for HTTP traffic
    try {
        var winhttp = Process.getModuleByName('winhttp.dll');
        if (winhttp) {
            var WinHttpOpen = winhttp.getExportByName('WinHttpOpen');
            var WinHttpConnect = winhttp.getExportByName('WinHttpConnect');
            var WinHttpOpenRequest = winhttp.getExportByName('WinHttpOpenRequest');
            var WinHttpSendRequest = winhttp.getExportByName('WinHttpSendRequest');
            
            if (WinHttpConnect) {
                Interceptor.attach(WinHttpConnect, {
                    onEnter: function(args) {
                        try {
                            var server = args[1].readUtf16String();
                            var port = args[2].toInt32();
                            send({t:'http_connect', server: server, port: port});
                        } catch(e) {}
                    }
                });
            }
            
            if (WinHttpOpenRequest) {
                Interceptor.attach(WinHttpOpenRequest, {
                    onEnter: function(args) {
                        try {
                            var verb = args[1].readUtf16String();
                            var path = args[2].readUtf16String();
                            send({t:'http_req', verb: verb, path: path});
                        } catch(e) {}
                    }
                });
            }
            send('[+] WinHTTP hooked');
        }
    } catch(e) {
        send('[!] WinHTTP not loaded');
    }
    
    send('[*] All hooks ready! START an account in the bot...');
    
}, 1000);
'''

data = {"dns": [], "connect": [], "send": [], "recv": [], "http": []}

def on_message(msg, _):
    if msg['type'] == 'send':
        p = msg['payload']
        
        if isinstance(p, str):
            print(p)
        elif p.get('t') == 'dns':
            print(f"[DNS] {p['host']}")
            data['dns'].append(p['host'])
        elif p.get('t') == 'connect':
            print(f"[CONNECT] {p['ip']}:{p['port']}")
            data['connect'].append(f"{p['ip']}:{p['port']}")
        elif p.get('t') == 'send':
            hex_preview = p['hex'][:60]
            print(f"[SEND] {p['len']} bytes: {hex_preview}...")
            data['send'].append(p)
        elif p.get('t') == 'recv':
            print(f"[RECV] {p['len']} bytes")
            data['recv'].append(p['len'])
        elif p.get('t') == 'http_connect':
            print(f"[HTTP] Connect to {p['server']}:{p['port']}")
            data['http'].append(p)
        elif p.get('t') == 'http_req':
            print(f"[HTTP] {p['verb']} {p['path']}")
            data['http'].append(p)

def main():
    print("="*60)
    print(" Extended Capture - Find Token Source")
    print("="*60)
    print("\n1. Make sure bot is running but NO accounts started")
    print("2. Run this script")
    print("3. START one account in the bot")
    print("4. Watch for the first packets sent")
    print("\nPress Ctrl+C when done\n")
    
    try:
        session = frida.attach("LordsMobileBot.exe")
        print("[+] Attached!")
        
        script = session.create_script(HOOK_SCRIPT)
        script.on('message', on_message)
        script.load()
        
        print("\n[*] Waiting... START an account now!\n")
        
        while True:
            time.sleep(1)
            
    except frida.ProcessNotFoundError:
        print("[!] Bot not running!")
    except KeyboardInterrupt:
        print("\n[*] Stopped")
    
    # Save data
    with open('extended_capture.json', 'w') as f:
        json.dump(data, f, indent=2)
    
    print("\n" + "="*60)
    print(" ANALYSIS")
    print("="*60)
    print(f"\nDNS lookups: {len(data['dns'])}")
    for d in data['dns'][:10]:
        print(f"  - {d}")
    
    print(f"\nConnections: {len(data['connect'])}")
    for c in data['connect'][:10]:
        print(f"  - {c}")
    
    print("\nSaved to extended_capture.json")

if __name__ == "__main__":
    main()
