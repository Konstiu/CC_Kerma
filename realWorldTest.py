#!/usr/bin/env python3
"""
Real-world scenario test for Kerma Task 4
Simulates multiple bootstrap nodes with different chains
"""

import socket
import json
import time
import threading
import hashlib
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from nacl.signing import SigningKey

# Reuse these from your main test file
HOST = 'localhost' # 128.130.122.73
PORT = 18018
TIMEOUT = 10
GENESIS_ID = "00002fa163c7dab0991544424b9fd302bb1782b185e5a3bbdf12afb758e57dee"
TARGET = "0000abc000000000000000000000000000000000000000000000000000000000"

def canonicalize_json(obj) -> str:
    return json.dumps(obj, separators=(',', ':'), sort_keys=True)

def object_id(obj: Dict) -> str:
    canonical = canonicalize_json(obj)
    h = hashlib.blake2s(canonical.encode('utf-8'), digest_size=32)
    return h.hexdigest()

def mine_block(block_template: Dict, max_iterations: int = 10000000) -> Optional[Dict]:
    target = int(TARGET, 16)
    for i in range(max_iterations):
        nonce = format(i, '064x')
        block_template['nonce'] = nonce
        block_id = object_id(block_template)
        block_id_int = int(block_id, 16)
        if block_id_int < target:
            return block_template
        if i > 0 and i % 100000 == 0:
            print(f"      Mining... tried {i} nonces...")
    return None

def create_and_mine_block(txids: List[str], previd: Optional[str], 
                          created: int, miner: str = "test", note: str = "test") -> Optional[Dict]:
    block_template = {
        "type": "block",
        "txids": txids,
        "nonce": "0" * 64,
        "previd": previd,
        "created": created,
        "T": TARGET,
        "miner": miner,
        "note": note
    }
    return mine_block(block_template)

def create_coinbase_tx(height: int, pubkey: str, value: int = 50000000000000) -> Dict:
    return {
        "type": "transaction",
        "height": height,
        "outputs": [{
            "pubkey": pubkey,
            "value": value
        }]
    }

class MockBootstrapNode:
    """A mock bootstrap node that serves a specific chain"""
    
    def __init__(self, port: int, chain: List[Dict], coinbases: List[Dict], 
                 is_valid: bool, node_name: str):
        self.port = port
        self.chain = chain  # List of blocks
        self.coinbases = coinbases  # List of coinbase transactions
        self.is_valid = is_valid
        self.node_name = node_name
        self.sock = None
        self.server_sock = None
        self.client_sock = None
        self.running = False
        self.thread = None
        
        # Build object store
        self.objects = {}
        for block in chain:
            self.objects[object_id(block)] = block
        for cb in coinbases:
            self.objects[object_id(cb)] = cb
    
    def start(self):
        """Start the mock node server"""
        self.running = True
        self.thread = threading.Thread(target=self._run_server, daemon=True)
        self.thread.start()
        time.sleep(0.2)  # Give it time to start
    
    def stop(self):
        """Stop the mock node server"""
        self.running = False
        if self.client_sock:
            try:
                self.client_sock.close()
            except:
                pass
        if self.server_sock:
            try:
                self.server_sock.close()
            except:
                pass
    
    def _run_server(self):
        """Run the server loop"""
        try:
            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind(('localhost', self.port))
            self.server_sock.listen(1)
            self.server_sock.settimeout(1.0)
            
            print(f"    [{self.node_name}] Listening on port {self.port}")
            
            while self.running:
                try:
                    self.client_sock, addr = self.server_sock.accept()
                    print(f"    [{self.node_name}] Client connected from {addr}")
                    self._handle_client()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"    [{self.node_name}] Accept error: {e}")
                    break
        except Exception as e:
            print(f"    [{self.node_name}] Server error: {e}")
    
    def _handle_client(self):
        """Handle a client connection"""
        try:
            self.client_sock.settimeout(1.0)
            
            # Send hello
            hello = {
                "type": "hello",
                "version": "0.10.0",
                "agent": f"MockNode-{self.node_name}"
            }
            self._send_message(hello)
            
            # Receive client hello
            msg = self._receive_message()
            if not msg or msg.get('type') != 'hello':
                print(f"    [{self.node_name}] Invalid handshake")
                return
            
            print(f"    [{self.node_name}] Handshake complete")
            
            # Handle messages
            while self.running:
                msg = self._receive_message()
                if not msg:
                    break
                
                msg_type = msg.get('type')
                
                if msg_type == 'getpeers':
                    self._send_message({"type": "peers", "peers": []})
                
                elif msg_type == 'getchaintip':
                    tip_id = object_id(self.chain[-1]) if self.chain else GENESIS_ID
                    self._send_message({"type": "chaintip", "blockid": tip_id})
                    print(f"    [{self.node_name}] Sent chaintip: {tip_id[:16]}...")
                
                elif msg_type == 'getobject':
                    obj_id = msg.get('objectid')
                    if obj_id in self.objects:
                        self._send_message({"type": "object", "object": self.objects[obj_id]})
                        print(f"    [{self.node_name}] Sent object: {obj_id[:16]}...")
                    else:
                        self._send_message({
                            "type": "error",
                            "name": "UNKNOWN_OBJECT",
                            "objectid": obj_id
                        })
                
                elif msg_type == 'ihaveobject':
                    obj_id = msg.get('objectid')
                    print(f"    [{self.node_name}] Received ihaveobject: {obj_id[:16]}...")
                
                elif msg_type == 'object':
                    obj = msg.get('object')
                    obj_id = object_id(obj)
                    print(f"    [{self.node_name}] Received object: {obj_id[:16]}...")
        
        except Exception as e:
            if self.running:
                print(f"    [{self.node_name}] Client handler error: {e}")
    
    def _send_message(self, msg: Dict):
        data = json.dumps(msg, separators=(',', ':'))
        self.client_sock.sendall((data + '\n').encode('utf-8'))
    
    def _receive_message(self) -> Optional[Dict]:
        try:
            buffer = b''
            while b'\n' not in buffer:
                chunk = self.client_sock.recv(4096)
                if not chunk:
                    return None
                buffer += chunk
            line = buffer.split(b'\n', 1)[0]
            return json.loads(line.decode('utf-8'))
        except socket.timeout:
            return None
        except Exception:
            return None

def test_real_world_scenario() -> Dict:
    """
    Real-world scenario test:
    1. Create multiple mock bootstrap nodes with different chains
    2. Connect to your node
    3. Send peers message
    4. Your node should connect to all peers, download chains, validate
    5. Verify your node adopted the longest valid chain
    6. Verify your node filtered out invalid peers
    """
    
    print("\n" + "="*70)
    print("REAL-WORLD SCENARIO TEST")
    print("="*70)
    
    # Generate keypair
    signing_key = SigningKey(b'a' * 32)
    pubkey = signing_key.verify_key.encode().hex()
    
    print("\n[1/5] Mining chains for mock bootstrap nodes...")
    print("     (This will take a while...)")
    
    # Chain A: Valid, length 3 (genesis -> A1 -> A2 -> A3)
    print("  Chain A (VALID, length 3):")
    cb_a1 = create_coinbase_tx(1, pubkey)
    b_a1 = create_and_mine_block([object_id(cb_a1)], GENESIS_ID, 1671062500, note="A1")
    if not b_a1:
        return {"success": False, "error": "Failed to mine block A1"}
    
    cb_a2 = create_coinbase_tx(2, pubkey)
    b_a2 = create_and_mine_block([object_id(cb_a2)], object_id(b_a1), 1671062600, note="A2")
    if not b_a2:
        return {"success": False, "error": "Failed to mine block A2"}
    
    cb_a3 = create_coinbase_tx(3, pubkey)
    b_a3 = create_and_mine_block([object_id(cb_a3)], object_id(b_a2), 1671062700, note="A3")
    if not b_a3:
        return {"success": False, "error": "Failed to mine block A3"}
    
    chain_a = [b_a1, b_a2, b_a3]
    coinbases_a = [cb_a1, cb_a2, cb_a3]
    
    # Chain B: Valid, length 2 (genesis -> B1 -> B2)
    print("  Chain B (VALID, length 2):")
    cb_b1 = create_coinbase_tx(1, pubkey)
    b_b1 = create_and_mine_block([object_id(cb_b1)], GENESIS_ID, 1671062501, note="B1")
    if not b_b1:
        return {"success": False, "error": "Failed to mine block B1"}
    
    cb_b2 = create_coinbase_tx(2, pubkey)
    b_b2 = create_and_mine_block([object_id(cb_b2)], object_id(b_b1), 1671062601, note="B2")
    if not b_b2:
        return {"success": False, "error": "Failed to mine block B2"}
    
    chain_b = [b_b1, b_b2]
    coinbases_b = [cb_b1, cb_b2]
    
    # Chain C: Invalid (bad PoW in first block), length 2
    print("  Chain C (INVALID - bad PoW):")
    cb_c1 = create_coinbase_tx(1, pubkey)
    b_c1_invalid = {
        "type": "block",
        "txids": [object_id(cb_c1)],
        "nonce": "0" * 64,  # Invalid nonce
        "previd": GENESIS_ID,
        "created": 1671062502,
        "T": TARGET,
        "miner": "test",
        "note": "C1_invalid"
    }
    
    cb_c2 = create_coinbase_tx(2, pubkey)
    b_c2 = create_and_mine_block([object_id(cb_c2)], object_id(b_c1_invalid), 1671062602, note="C2")
    if not b_c2:
        return {"success": False, "error": "Failed to mine block C2"}
    
    chain_c = [b_c1_invalid, b_c2]
    coinbases_c = [cb_c1, cb_c2]
    
    # Chain D: Invalid (wrong coinbase height), length 1
    print("  Chain D (INVALID - wrong coinbase height):")
    cb_d1_wrong = create_coinbase_tx(999, pubkey)  # Should be height 1!
    b_d1 = create_and_mine_block([object_id(cb_d1_wrong)], GENESIS_ID, 1671062503, note="D1")
    if not b_d1:
        return {"success": False, "error": "Failed to mine block D1"}
    
    chain_d = [b_d1]
    coinbases_d = [cb_d1_wrong]
    
    print("\n[2/5] Starting mock bootstrap nodes...")
    
    # Create mock bootstrap nodes on different ports
    nodes = [
        MockBootstrapNode(18019, chain_a, coinbases_a, True, "NodeA-Valid3"),
        MockBootstrapNode(18020, chain_b, coinbases_b, True, "NodeB-Valid2"),
        MockBootstrapNode(18021, chain_c, coinbases_c, False, "NodeC-Invalid"),
        MockBootstrapNode(18022, chain_d, coinbases_d, False, "NodeD-Invalid"),
    ]
    
    for node in nodes:
        node.start()
    
    time.sleep(1)
    
    try:
        print("\n[3/5] Connecting to your node and sending peers...")
        
        # Connect to the student's node
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(10)
        client.connect((HOST, PORT))
        
        # Handshake
        msg = client.recv(4096)
        hello_response = {
            "type": "hello",
            "version": "0.10.0",
            "agent": "Grader"
        }
        client.sendall((json.dumps(hello_response) + '\n').encode())
        
        # Wait for getpeers
        buffer = b''
        client.settimeout(5)
        try:
            while b'\n' not in buffer:
                chunk = client.recv(4096)
                if not chunk:
                    print("      Connection closed before getpeers")
                    return {"success": False, "error": "Connection closed"}
                buffer += chunk
            
            # Check for any messages (getpeers or getchaintip)
            lines = buffer.split(b'\n')
            for line in lines:
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                    print(f"     Received: {msg.get('type')}")
                    
                    if msg.get('type') == 'getchaintip':
                        # Node is asking for our tip, respond with genesis
                        response = {"type": "chaintip", "blockid": GENESIS_ID}
                        client.sendall((json.dumps(response) + '\n').encode())
                        print(f"     Sent chaintip response")
                except:
                    pass
        except socket.timeout:
            print("¸ Timeout waiting for initial messages (this is okay)")
        
        # Clear any remaining messages
        client.settimeout(0.5)
        try:
            while True:
                chunk = client.recv(4096)
                if not chunk:
                    break
        except:
            pass
        
        # Send peers message with all bootstrap nodes
        peers_msg = {
            "type": "peers",
            "peers": [
                f"localhost:18019",
                f"localhost:18020",
                f"localhost:18021",
                f"localhost:18022"
            ]
        }
        client.sendall((json.dumps(peers_msg) + '\n').encode())
        
        print("     Sent peers list with 4 nodes (2 valid, 2 invalid)")
        
        print("\n[4/5] Waiting for your node to download and validate chains...")
        print("     (Waiting 15 seconds for all downloads and validation...)")
        time.sleep(15)
        
        print("\n[5/5] Checking results...")
        
        # Helper function to receive message with timeout
        def receive_message(sock, timeout=5):
            sock.settimeout(timeout)
            try:
                buffer = b''
                while b'\n' not in buffer:
                    chunk = sock.recv(4096)
                    if not chunk:
                        return None
                    buffer += chunk
                return json.loads(buffer.split(b'\n')[0])
            except socket.timeout:
                print(f"Timeout waiting for response")
                return None
            except Exception as e:
                print(f"      Error receiving: {e}")
                return None
        
        # Test 1: Check chaintip (should be chain A tip)
        getchaintip_msg = {"type": "getchaintip"}
        client.sendall((json.dumps(getchaintip_msg) + '\n').encode())
        
        response = receive_message(client)
        
        if response:
            received_tip = response.get('blockid')
            expected_tip = object_id(b_a3)
            
            print(f"\nChaintip check:")
            print(f"     Expected: {expected_tip[:16]}... (Chain A, length 3)")
            print(f"     Received: {received_tip[:16] if received_tip else 'None'}...")
            
            chaintip_correct = (received_tip == expected_tip)
            
            if not chaintip_correct:
                if received_tip == object_id(b_b2):
                    print(f"      WRONG: Got Chain B (length 2) instead of Chain A (length 3)")
                elif received_tip == object_id(b_c2):
                    print(f"      WRONG: Got invalid Chain C!")
                elif received_tip == object_id(b_d1):
                    print(f"      WRONG: Got invalid Chain D!")
                elif received_tip == GENESIS_ID:
                    print(f"      WRONG: Still at genesis (no chain adopted)")
                else:
                    print(f"      WRONG: Unknown chaintip")
        else:
            print("      Failed to get chaintip response")
            chaintip_correct = False
        
        # Test 2: Check peers (should only include valid nodes)
        print(f"\nPeers filtering check:")
        getpeers_msg = {"type": "getpeers"}
        client.sendall((json.dumps(getpeers_msg) + '\n').encode())
        
        response = receive_message(client)
        
        if response:
            peers_list = response.get('peers', [])
            
            print(f"     Received {len(peers_list)} peers")
            
            # Check if invalid peers are filtered out
            has_invalid_c = any('18021' in p for p in peers_list)
            has_invalid_d = any('18022' in p for p in peers_list)
            has_valid_a = any('18019' in p for p in peers_list)
            has_valid_b = any('18020' in p for p in peers_list)
            
            if has_invalid_c or has_invalid_d:
                print(f"      WRONG: Invalid peers still in list!")
                peers_correct = False
            elif has_valid_a and has_valid_b:
                print(f"      CORRECT: Only valid peers in list")
                peers_correct = True
            else:
                print(f"  PARTIAL: Some valid peers missing")
                peers_correct = False
        else:
            print("      Failed to get peers response")
            peers_correct = False
        
        # Test 3: Request invalid block (should get UNKNOWN_OBJECT)
        print(f"\n  Invalid object request check:")
        invalid_block_id = object_id(b_c1_invalid)
        getobject_msg = {"type": "getobject", "objectid": invalid_block_id}
        client.sendall((json.dumps(getobject_msg) + '\n').encode())
        
        response = receive_message(client)
        
        if response:
            if response.get('type') == 'error' and response.get('name') == 'UNKNOWN_OBJECT':
                print(f"      CORRECT: Got UNKNOWN_OBJECT for invalid block")
                unknown_correct = True
            else:
                print(f"      WRONG: Expected UNKNOWN_OBJECT, got {response.get('type')}")
                unknown_correct = False
        else:
            print("      No response")
            unknown_correct = False
        
        # Test 4: Request valid block from Chain A (should get the block)
        print(f"\n Valid object request check:")
        valid_block_id = object_id(b_a2)
        getobject_msg = {"type": "getobject", "objectid": valid_block_id}
        client.sendall((json.dumps(getobject_msg) + '\n').encode())
        
        response = receive_message(client)
        
        if response:
            if response.get('type') == 'object':
                print(f"   CORRECT: Got valid block from Chain A")
                object_correct = True
            else:
                print(f"      WRONG: Expected object, got {response.get('type')}")
                object_correct = False
        else:
            print("      No response")
            object_correct = False
        
        client.close()
        
        # Summary
        print("\n" + "="*70)
        print("RESULTS SUMMARY:")
        print("="*70)
        print(f"  Chaintip (longest valid):  {'" PASS' if chaintip_correct else ' FAIL'}")
        print(f"  Peers filtering:            {'" PASS' if peers_correct else ' FAIL'}")
        print(f"  Invalid object request:     {'" PASS' if unknown_correct else ' FAIL'}")
        print(f"  Valid object request:       {'" PASS' if object_correct else ' FAIL'}")
        
        all_pass = chaintip_correct and peers_correct and unknown_correct and object_correct
        print(f"\n  Overall: {'" ALL TESTS PASSED' if all_pass else ' SOME TESTS FAILED'}")
        print("="*70)
        
        return {
            "success": all_pass,
            "chaintip_correct": chaintip_correct,
            "peers_correct": peers_correct,
            "unknown_correct": unknown_correct,
            "object_correct": object_correct
        }
    
    finally:
        print("\n[Cleanup] Stopping mock bootstrap nodes...")
        for node in nodes:
            node.stop()
        time.sleep(0.5)

if __name__ == "__main__":
    import sys
    
    print("Kerma Real-World Scenario Test")
    print(f"Target: {HOST}:{PORT}\n")
    
    # Check if node is running
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((HOST, PORT))
        sock.close()
    except Exception as e:
        print(f" Cannot connect to node at {HOST}:{PORT}")
        print(f"  Make sure your node is running first!")
        sys.exit(1)
    
    result = test_real_world_scenario()
    
    sys.exit(0 if result.get("success") else 1)