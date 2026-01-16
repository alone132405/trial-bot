"""
Full Traffic Capture - Both directions
Captures what the bot SENDS and what it RECEIVES
"""

import frida
import json
import time

HOOK_SCRIPT = r'''
send('[*] Full traffic capture loaded!');

setTimeout(function() {
    
    // Hook send
    try {
        var ws2 = Process.getModuleByName('ws2_32.dll');
        var sendAddr = ws2.getExportByName('send');
        
        Interceptor.attach(sendAddr, {
            onEnter: function(args) {
                this.sock = args[0].toInt32();
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function(retval) {
                var sent = retval.toInt32();
                if (sent > 0 && sent < 5000) {
                    try {
                        var bytes = this.buf.readByteArray(sent);
                        var hex = Array.from(new Uint8Array(bytes))
                            .map(b => b.toString(16).padStart(2, '0')).join('');
                        send({dir: 'OUT', sock: this.sock, len: sent, hex: hex});
                    } catch(e) {}
                }
            }
        });
        send('[+] send hooked');
    } catch(e) {
        send('[!] send hook failed: ' + e);
    }
    
    // Hook recv - capture INCOMING data
    try {
        var ws2 = Process.getModuleByName('ws2_32.dll');
        var recvAddr = ws2.getExportByName('recv');
        
        Interceptor.attach(recvAddr, {
            onEnter: function(args) {
                this.sock = args[0].toInt32();
                this.buf = args[1];
                this.bufSize = args[2].toInt32();
            },
            onLeave: function(retval) {
                var received = retval.toInt32();
                if (received > 0 && received < 5000) {
                    try {
                        var bytes = this.buf.readByteArray(received);
                        var hex = Array.from(new Uint8Array(bytes))
                            .map(b => b.toString(16).padStart(2, '0')).join('');
                        send({dir: 'IN', sock: this.sock, len: received, hex: hex});
                    } catch(e) {}
                }
            }
        });
        send('[+] recv hooked');
    } catch(e) {
        send('[!] recv hook failed: ' + e);
    }
    
    // Also hook WSARecv for async receives
    try {
        var ws2 = Process.getModuleByName('ws2_32.dll');
        var wsaRecvAddr = ws2.getExportByName('WSARecv');
        if (wsaRecvAddr) {
            send('[+] Found WSARecv');
        }
    } catch(e) {}
    
    send('[*] Ready! Start an account to capture full traffic...');
    
}, 500);
'''

traffic = {"out": [], "in": []}

def on_message(msg, _):
    if msg['type'] == 'send':
        p = msg['payload']
        
        if isinstance(p, str):
            print(p)
        elif p.get('dir') == 'OUT':
            preview = p['hex'][:60] if len(p['hex']) > 60 else p['hex']
            print(f"[OUT] sock={p['sock']} len={p['len']}: {preview}")
            traffic['out'].append(p)
        elif p.get('dir') == 'IN':
            preview = p['hex'][:60] if len(p['hex']) > 60 else p['hex']
            print(f"[IN]  sock={p['sock']} len={p['len']}: {preview}")
            traffic['in'].append(p)
            
        # Save every 10 packets
        if (len(traffic['out']) + len(traffic['in'])) % 10 == 0:
            with open('full_traffic.json', 'w') as f:
                json.dump(traffic, f, indent=2)

def main():
    print("="*60)
    print(" Full Traffic Capture - Both Directions")
    print("="*60)
    print("\n1. Make sure bot is running")
    print("2. Start ONE account")
    print("3. Watch for [IN] packets - server responses!")
    print("4. Press Ctrl+C to stop\n")
    
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
    
    with open('full_traffic.json', 'w') as f:
        json.dump(traffic, f, indent=2)
    
    print(f"\nCaptured: {len(traffic['out'])} OUT, {len(traffic['in'])} IN")
    print("Saved to full_traffic.json")
    
    # Analyze first few exchanges
    if traffic['in']:
        print("\n" + "="*60)
        print(" First Server Responses:")
        print("="*60)
        for i, pkt in enumerate(traffic['in'][:5]):
            print(f"\n[IN #{i+1}] {pkt['len']} bytes:")
            print(f"  {pkt['hex'][:100]}")

if __name__ == "__main__":
    main()
