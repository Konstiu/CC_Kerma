#!/usr/bin/env python3
"""Manual test with your actual block and transaction data"""

import socket
import json
import time

# Genesis
GENESIS_ID = '00002fa163c7dab0991544424b9fd302bb1782b185e5a3bbdf12afb758e57dee'

# Coinbase transactions
coinbase1_id = 'b3d1bda7c7c79918bccba7d5f6be86c8a2fc24d472010f46f1a155f5fa0b82ed'
coinbase1 = {
    'type': 'transaction',
    'height': 1,
    'outputs': [{'pubkey': 'af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d', 'value': 50000000000000}]
}

coinbase2_id = 'd7c01da0005c18f7594700cbcb8f5f7ac75e6816989adf313fe8b478d6a44e02'
coinbase2 = {
    'type': 'transaction',
    'height': 2,
    'outputs': [{'pubkey': 'af06a3e3291714e4f356c19c9b15cd1951ec6e6662aa77be07547f289383341d', 'value': 50000000000000}]
}

# Blocks
block1_id = '00001a313b16eb23947302f0f9b32c80bfb8cffdf1d801c64c2698bbe44e08ca'
block1 = {
    'type': 'block',
    'txids': ['b3d1bda7c7c79918bccba7d5f6be86c8a2fc24d472010f46f1a155f5fa0b82ed'],
    'nonce': '0000000000000000000000000000000000000000000000000000000000022354',
    'previd': '00002fa163c7dab0991544424b9fd302bb1782b185e5a3bbdf12afb758e57dee',
    'created': 1671062500,
    'T': '0000abc000000000000000000000000000000000000000000000000000000000',
    'miner': 'test',
    'note': 'test'
}

block2_id = '000019f275894695e9299282a37a296067a1061e5153ed5537ac13c8a7db3f50'
block2 = {
    'type': 'block',
    'txids': ['d7c01da0005c18f7594700cbcb8f5f7ac75e6816989adf313fe8b478d6a44e02'],
    'nonce': '0000000000000000000000000000000000000000000000000000000000014e11',
    'previd': '00001a313b16eb23947302f0f9b32c80bfb8cffdf1d801c64c2698bbe44e08ca',
    'created': 1671062600,
    'T': '0000abc000000000000000000000000000000000000000000000000000000000',
    'miner': 'test',
    'note': 'test'
}

def send_msg(sock, msg):
    data = json.dumps(msg).encode('utf-8') + b'\n'
    sock.sendall(data)
    msg_type = msg.get('type', 'unknown')
    if msg_type == 'object':
        obj_type = msg['object'].get('type', '?')
        print(f"→ SENT: {msg_type} ({obj_type})")
    else:
        print(f"→ SENT: {msg_type}")

def recv_msg(sock, timeout=2):
    sock.settimeout(timeout)
    try:
        data = b''
        while b'\n' not in data:
            chunk = sock.recv(4096)
            if not chunk:
                print("← RECV: connection closed")
                return None
            data += chunk
        
        line = data.split(b'\n')[0]
        msg = json.loads(line.decode('utf-8'))
        msg_type = msg.get('type', 'unknown')
        
        if msg_type == 'getobject':
            print(f"← RECV: {msg_type} (wants: {msg['objectid'][:16]}...)")
        elif msg_type == 'ihaveobject':
            print(f"← RECV: {msg_type} (has: {msg['objectid'][:16]}...)")
        elif msg_type == 'error':
            print(f"← RECV: ERROR - {msg.get('error', 'unknown')}")
        else:
            print(f"← RECV: {msg_type}")
        
        return msg
    except socket.timeout:
        print("← RECV: timeout (no message)")
        return None
    except json.JSONDecodeError as e:
        print(f"← RECV: JSON error - {e}")
        print(f"  Raw data: {data[:200]}")
        return None
    except Exception as e:
        print(f"← RECV: error - {e}")
        return None

def main():
    print("=" * 60)
    print("Manual Block Chain Test")
    print("=" * 60)
    
    # Connect
    print("\n[1] Connecting to node...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(('localhost', 18018))
        print("    ✓ Connected")
    except Exception as e:
        print(f"    ✗ Connection failed: {e}")
        return
    
    # Handshake
    print("\n[2] Handshaking...")
    send_msg(sock, {"type": "hello", "version": "0.10.0", "agent": "manual-test"})
    resp = recv_msg(sock)
    
    if not resp or resp.get('type') != 'hello':
        print("    ✗ Handshake failed")
        return
    print("    ✓ Handshake complete")
    
    # Clear initial messages
    print("\n[3] Clearing initial messages...")
    time.sleep(0.5)
    sock.settimeout(0.1)
    count = 0
    while True:
        try:
            data = sock.recv(4096)
            if data:
                count += 1
            else:
                break
        except:
            break
    print(f"    Cleared {count} messages")
    
    # Send block2 first (triggers recursive fetch)
    print("\n[4] Sending block2 (should trigger getobject requests)...")
    send_msg(sock, {"type": "object", "object": block2})
    
    print("\n[5] Handling getobject requests...")
    time.sleep(0.3)
    
    for i in range(15):  # Allow up to 15 back-and-forth messages
        msg = recv_msg(sock, timeout=1)
        if not msg:
            break
        
        if msg.get('type') == 'getobject':
            obj_id = msg['objectid']
            
            if obj_id == block1_id:
                print("    → Sending block1")
                send_msg(sock, {"type": "object", "object": block1})
            elif obj_id == coinbase1_id:
                print("    → Sending coinbase1")
                send_msg(sock, {"type": "object", "object": coinbase1})
            elif obj_id == coinbase2_id:
                print("    → Sending coinbase2")
                send_msg(sock, {"type": "object", "object": coinbase2})
            else:
                print(f"    ⚠ Unknown object requested: {obj_id}")
        
        elif msg.get('type') == 'ihaveobject':
            obj_id = msg['objectid']
            print(f"    ✓ Node confirmed: {obj_id[:16]}...")
        
        elif msg.get('type') == 'error':
            print(f"    ✗ ERROR: {msg}")
            break
    
    print("\n[6] Waiting for block validation...")
    time.sleep(2)
    
    print("\n[7] Checking chain tip...")
    send_msg(sock, {"type": "getchaintip"})
    tip_msg = recv_msg(sock, timeout=2)
    
    print("\n" + "=" * 60)
    print("RESULT")
    print("=" * 60)
    
    if tip_msg and tip_msg.get('type') == 'chaintip':
        tip = tip_msg.get('blockid')
        print(f"Current tip: {tip}")
        print()
        
        if tip == block2_id:
            print("✓✓✓ SUCCESS! Block2 is the chain tip!")
            print("    The 2-block chain was accepted and adopted.")
        elif tip == block1_id:
            print("⚠ PARTIAL: Block1 adopted but not block2")
            print("    Block2 may have failed validation.")
        elif tip == GENESIS_ID:
            print("✗ FAILED: Still at genesis")
            print("    Neither block was adopted.")
        else:
            print(f"? UNKNOWN: Unexpected tip")
            print(f"    Expected: {block2_id}")
            print(f"    Got:      {tip}")
    else:
        print("✗ No chaintip response received")
        print(f"   Got: {tip_msg}")
    
    print("=" * 60)
    
    sock.close()
    print("\nConnection closed.")

if __name__ == '__main__':
    main()
