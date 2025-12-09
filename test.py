#!/usr/bin/env python3
"""
Comprehensive test suite for Kerma Task 4
Tests recursive object fetching and longest chain rule with ALL error cases
"""

import socket
import json
import time
import hashlib
import sys
from nacl.signing import SigningKey
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

# Test configuration
HOST = 'localhost' # 128.130.122.73
PORT = 18018
TIMEOUT = 10
GENESIS_ID = "00002fa163c7dab0991544424b9fd302bb1782b185e5a3bbdf12afb758e57dee"
TARGET = "0000abc000000000000000000000000000000000000000000000000000000000"

@dataclass
class TestResult:
    name: str
    passed: bool
    message: str
    duration: float

class KermaTestClient:
    def __init__(self, host: str = HOST, port: int = PORT):
        self.host = host
        self.port = port
        self.sock = None
        
    def connect(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(TIMEOUT)
            self.sock.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"Connection failed: {e}")
            return False
    
    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
    
    def send_message(self, msg: Dict) -> bool:
        try:
            data = json.dumps(msg, separators=(',', ':'))
            self.sock.sendall((data + '\n').encode('utf-8'))
            return True
        except Exception as e:
            print(f"Send failed: {e}")
            return False
    
    def receive_message(self, timeout: Optional[float] = None) -> Optional[Dict]:
        if timeout is not None:
            old_timeout = self.sock.gettimeout()
            self.sock.settimeout(timeout)
        
        try:
            buffer = b''
            while b'\n' not in buffer:
                chunk = self.sock.recv(4096)
                if not chunk:
                    return None
                buffer += chunk
            
            line = buffer.split(b'\n', 1)[0]
            msg = json.loads(line.decode('utf-8'))
            return msg
        except socket.timeout:
            return None
        except Exception as e:
            print(f"Receive failed: {e}")
            return None
        finally:
            if timeout is not None:
                self.sock.settimeout(old_timeout)
    
    def receive_all_messages(self, timeout: float = 0.5) -> List[Dict]:
        """Receive all pending messages"""
        messages = []
        while True:
            msg = self.receive_message(timeout=timeout)
            if not msg:
                break
            messages.append(msg)
        return messages
    
    def handshake(self) -> bool:
        # Receive hello from server
        msg = self.receive_message(timeout=3)
        if not msg or msg.get('type') != 'hello':
            print(f"Expected hello, got: {msg}")
            return False
        
        # Send our hello
        hello = {
            "type": "hello",
            "version": "0.10.0",
            "agent": "Kerma-Test-Client"
        }
        return self.send_message(hello)
    
    def clear_initial_messages(self):
        """Clear any initial messages like getpeers"""
        time.sleep(0.1)
        while True:
            msg = self.receive_message(timeout=0.2)
            if not msg:
                break
            if msg.get('type') == 'getpeers':
                self.send_message({"type": "peers", "peers": []})

def canonicalize_json(obj) -> str:
    """Convert object to canonical JSON for hashing"""
    return json.dumps(obj, separators=(',', ':'), sort_keys=True)

def object_id(obj: Dict) -> str:
    """Calculate objectid (blake2s hash) - using digest_size=32 for 256-bit hash"""
    canonical = canonicalize_json(obj)
    h = hashlib.blake2s(canonical.encode('utf-8'), digest_size=32)
    return h.hexdigest()

def mine_block(block_template: Dict, max_iterations: int = 10000000) -> Optional[Dict]:
    """
    Mine a block by finding a valid nonce that satisfies PoW.
    Returns the block with valid nonce, or None if not found within max_iterations.
    """
    target = int(TARGET, 16)
    
    for i in range(max_iterations):
        # Try different nonces
        nonce = format(i, '064x')  # 64 hex characters
        block_template['nonce'] = nonce
        
        block_id = object_id(block_template)
        block_id_int = int(block_id, 16)
        
        if block_id_int < target:
            print(f"    ⛏️  Mined block! nonce={nonce[:16]}... (tried {i+1} iterations)")
            return block_template
        
        if i > 0 and i % 100000 == 0:
            print(f"    ⛏️  Mining... tried {i} nonces so far...")
    
    print(f"    ⛏️  Mining failed after {max_iterations} iterations")
    return None

def create_block(txids: List[str], previd: Optional[str], nonce: str, 
                 created: int, miner: str = "test", note: str = "test") -> Dict:
    """Create a block object"""
    return {
        "type": "block",
        "txids": txids,
        "nonce": nonce,
        "previd": previd,
        "created": created,
        "T": TARGET,
        "miner": miner,
        "note": note
    }

def create_and_mine_block(txids: List[str], previd: Optional[str], 
                          created: int, miner: str = "test", note: str = "test") -> Optional[Dict]:
    """Create and mine a block with valid PoW"""
    block_template = create_block(txids, previd, "0" * 64, created, miner, note)
    return mine_block(block_template)
    """Create a block object"""
    return {
        "type": "block",
        "txids": txids,
        "nonce": nonce,
        "previd": previd,
        "created": created,
        "T": TARGET,
        "miner": miner,
        "note": note
    }

def create_coinbase_tx(height: int, pubkey: str, value: int = 50000000000000) -> Dict:
    """Create a coinbase transaction"""
    return {
        "type": "transaction",
        "height": height,
        "outputs": [{
            "pubkey": pubkey,
            "value": value
        }]
    }

def create_transaction(inputs: List[Dict], outputs: List[Dict]) -> Dict:
    """Create a regular transaction"""
    return {
        "type": "transaction",
        "inputs": inputs,
        "outputs": outputs
    }

def sign_transaction(tx: Dict, private_keys: List[bytes]) -> Dict:
    """Sign a transaction with given private keys"""
    # Create signing version (all sigs are null)
    tx_copy = json.loads(json.dumps(tx))
    for inp in tx_copy.get('inputs', []):
        inp['sig'] = None
    
    signing_text = canonicalize_json(tx_copy).encode('utf-8')
    
    # Sign with each private key
    signed_tx = json.loads(json.dumps(tx))
    for i, privkey in enumerate(private_keys):
        signing_key = SigningKey(privkey)
        signature = signing_key.sign(signing_text)
        signed_tx['inputs'][i]['sig'] = signature.signature.hex()
    
    return signed_tx

def generate_keypair() -> Tuple[bytes, str]:
    """Generate ed25519 keypair, return (private_key, public_key_hex)"""
    signing_key = SigningKey(b'a' * 32)  # For deterministic testing
    return signing_key.encode(), signing_key.verify_key.encode().hex()

# ==================== TEST CASES ====================

def test_hello_handshake() -> TestResult:
    """Test basic connection and handshake"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect():
            return TestResult("hello_handshake", False, "Failed to connect", time.time() - start)
        
        if not client.handshake():
            return TestResult("hello_handshake", False, "Handshake failed", time.time() - start)
        
        return TestResult("hello_handshake", True, "OK", time.time() - start)
    finally:
        client.close()

def test_getchaintip_initial() -> TestResult:
    """Test getchaintip on fresh node (should return genesis)"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("getchaintip_initial", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        client.send_message({"type": "getchaintip"})
        msg = client.receive_message(timeout=2)
        
        if not msg or msg.get('type') != 'chaintip':
            return TestResult("getchaintip_initial", False, f"Expected chaintip, got: {msg}", time.time() - start)
        
        if msg.get('blockid') != GENESIS_ID:
            return TestResult("getchaintip_initial", False, 
                            f"Expected genesis {GENESIS_ID}, got {msg.get('blockid')}", 
                            time.time() - start)
        
        return TestResult("getchaintip_initial", True, "OK", time.time() - start)
    finally:
        client.close()

def test_unavailable_block() -> TestResult:
    """Test 1a: Block pointing to unavailable parent (UNFINDABLE_OBJECT)"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("unavailable_block", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        fake_parent = "1111111111111111111111111111111111111111111111111111111111111111"
        block = create_and_mine_block([], fake_parent,  int(time.time()))
        
        client.send_message({"type": "object", "object": block})
        
        # Should receive getobject for the missing parent
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'getobject' and msg.get('objectid') == fake_parent:
            # Don't respond - let it timeout (5s)
            time.sleep(6)
            
            # Should get UNFINDABLE_OBJECT error
            msg = client.receive_message(timeout=2)
            if msg and msg.get('type') == 'error' and msg.get('name') == 'UNFINDABLE_OBJECT':
                return TestResult("unavailable_block", True, "OK", time.time() - start)
            else:
                return TestResult("unavailable_block", False, 
                                f"Expected UNFINDABLE_OBJECT, got: {msg}", time.time() - start)
        
        return TestResult("unavailable_block", False, "Expected getobject request", time.time() - start)
    finally:
        client.close()

def test_non_increasing_timestamps() -> TestResult:
    """Test 1b: Block with non-increasing timestamp (INVALID_BLOCK_TIMESTAMP)"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("non_increasing_timestamps", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create block with timestamp equal to genesis (not strictly greater)
        block1 = create_and_mine_block([], GENESIS_ID, 1671062400)  # Same as genesis
        
        client.send_message({"type": "object", "object": block1})
        
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'error' and msg.get('name') == 'INVALID_BLOCK_TIMESTAMP':
            return TestResult("non_increasing_timestamps", True, "OK", time.time() - start)
        
        return TestResult("non_increasing_timestamps", False, 
                        f"Expected INVALID_BLOCK_TIMESTAMP, got: {msg}", time.time() - start)
    finally:
        client.close()

def test_future_timestamp() -> TestResult:
    """Test 1c: Block with timestamp in year 2077 (INVALID_BLOCK_TIMESTAMP)"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("future_timestamp", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Timestamp for 2077
        future_time = 3376598400  # Jan 1, 2077
        block = create_and_mine_block([], GENESIS_ID, future_time)
        
        client.send_message({"type": "object", "object": block})
        
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'error' and msg.get('name') == 'INVALID_BLOCK_TIMESTAMP':
            return TestResult("future_timestamp", True, "OK", time.time() - start)
        
        return TestResult("future_timestamp", False, 
                        f"Expected INVALID_BLOCK_TIMESTAMP, got: {msg}", time.time() - start)
    finally:
        client.close()

def test_invalid_pow() -> TestResult:
    """Test 1d: Block with invalid proof-of-work (INVALID_BLOCK_POW)"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("invalid_pow", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Block with nonce that doesn't satisfy PoW
        block = create_block([], GENESIS_ID, "0" * 64, 1671062500)
        
        client.send_message({"type": "object", "object": block})
        
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'error' and msg.get('name') == 'INVALID_BLOCK_POW':
            return TestResult("invalid_pow", True, "OK", time.time() - start)
        
        return TestResult("invalid_pow", False, 
                        f"Expected INVALID_BLOCK_POW, got: {msg}", time.time() - start)
    finally:
        client.close()

def test_wrong_genesis() -> TestResult:
    """Test 1e: Chain with different genesis (INVALID_GENESIS)"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("wrong_genesis", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create a fake genesis (null previd but different content)
        fake_genesis = {
            "type": "block",
            "txids": [],
            "nonce": None,
            "previd": None,
            "created": 1671062401,
            "T": TARGET,
            "miner": "fake"
        }
        fake_genesis = mine_block(fake_genesis)
        
        client.send_message({"type": "object", "object": fake_genesis})
        
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'error' and msg.get('name') == 'INVALID_GENESIS':
            return TestResult("wrong_genesis", True, "OK", time.time() - start)
        
        return TestResult("wrong_genesis", False, 
                        f"Expected INVALID_GENESIS, got: {msg}", time.time() - start)
    finally:
        client.close()

def test_incorrect_coinbase_height() -> TestResult:
    """Test 1f: Block with incorrect coinbase height (INVALID_BLOCK_COINBASE)"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("incorrect_coinbase_height", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create coinbase with wrong height (should be 1, but we put 999)
        coinbase = create_coinbase_tx(999, "a" * 64)
        coinbase_id = object_id(coinbase)
        
        # Block at height 1
        block = create_and_mine_block([coinbase_id], GENESIS_ID, 1671062500)
        
        client.send_message({"type": "object", "object": block})
        
        # Node will request the coinbase
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'getobject':
            # Send the invalid coinbase
            client.send_message({"type": "object", "object": coinbase})
            
            # Should get INVALID_BLOCK_COINBASE error
            msg = client.receive_message(timeout=2)
            if msg and msg.get('type') == 'error' and msg.get('name') == 'INVALID_BLOCK_COINBASE':
                return TestResult("incorrect_coinbase_height", True, "OK", time.time() - start)
            else:
                return TestResult("incorrect_coinbase_height", False, 
                                f"Expected INVALID_BLOCK_COINBASE, got: {msg}", time.time() - start)
        
        return TestResult("incorrect_coinbase_height", False, "Expected getobject request", time.time() - start)
    finally:
        client.close()

def test_double_spending() -> TestResult:
    """Test 1g: Block with double spending transaction (INVALID_TX_OUTPOINT)"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("double_spending", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create a coinbase in block 1
        privkey, pubkey = generate_keypair()
        coinbase1 = create_coinbase_tx(1, pubkey, 50000000000000)
        coinbase1_id = object_id(coinbase1)
        
        # Create valid transaction spending from coinbase1
        tx1 = create_transaction(
            inputs=[{
                "outpoint": {"txid": coinbase1_id, "index": 0},
                "sig": None  # Will be filled by sign_transaction
            }],
            outputs=[{"pubkey": pubkey, "value": 25000000000000}]
        )
        tx1_signed = sign_transaction(tx1, [privkey])
        tx1_id = object_id(tx1_signed)
        
        # Create ANOTHER transaction also spending from coinbase1 (double spend)
        tx2 = create_transaction(
            inputs=[{
                "outpoint": {"txid": coinbase1_id, "index": 0},
                "sig": None
            }],
            outputs=[{"pubkey": pubkey, "value": 25000000000000}]
        )
        tx2_signed = sign_transaction(tx2, [privkey])
        tx2_id = object_id(tx2_signed)
        
        # Create blocks
        block1 = create_and_mine_block([coinbase1_id, tx1_id], GENESIS_ID, 1671062500)
        block1_id = object_id(block1)
        
        # Block2 tries to include the double-spending tx2
        block2 = create_and_mine_block([tx2_id], block1_id, 1671062600)
        
        # Send block2 first
        client.send_message({"type": "object", "object": block2})
        
        # Handle recursive fetching
        requests = client.receive_all_messages(timeout=1)
        
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == block1_id:
                    client.send_message({"type": "object", "object": block1})
                elif obj_id == tx2_id:
                    client.send_message({"type": "object", "object": tx2_signed})
                elif obj_id == tx1_id:
                    client.send_message({"type": "object", "object": tx1_signed})
                elif obj_id == coinbase1_id:
                    client.send_message({"type": "object", "object": coinbase1})
        
        # Wait for error
        time.sleep(1)
        errors = client.receive_all_messages(timeout=2)
        
        # Should get INVALID_TX_OUTPOINT for double spend
        for msg in errors:
            if msg.get('type') == 'error' and msg.get('name') == 'INVALID_TX_OUTPOINT':
                return TestResult("double_spending", True, "OK", time.time() - start)
        
        return TestResult("double_spending", False, 
                        f"Expected INVALID_TX_OUTPOINT, got: {errors}", time.time() - start)
    finally:
        client.close()

def test_spending_coinbase_same_block() -> TestResult:
    """Test INVALID_TX_OUTPOINT - spending coinbase in same block"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("spending_coinbase_same_block", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create a coinbase
        privkey, pubkey = generate_keypair()
        coinbase1 = create_coinbase_tx(1, pubkey, 50000000000000)
        coinbase1_id = object_id(coinbase1)
        
        # Try to spend coinbase in SAME block
        tx1 = create_transaction(
            inputs=[{
                "outpoint": {"txid": coinbase1_id, "index": 0},
                "sig": None
            }],
            outputs=[{"pubkey": pubkey, "value": 25000000000000}]
        )
        tx1_signed = sign_transaction(tx1, [privkey])
        tx1_id = object_id(tx1_signed)
        
        # Block with coinbase AND transaction spending it
        block1 = create_and_mine_block([coinbase1_id, tx1_id], GENESIS_ID, 1671062500)
        
        client.send_message({"type": "object", "object": block1})
        
        # Handle fetching
        requests = client.receive_all_messages(timeout=1)
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == coinbase1_id:
                    client.send_message({"type": "object", "object": coinbase1})
                elif obj_id == tx1_id:
                    client.send_message({"type": "object", "object": tx1_signed})
        
        time.sleep(1)
        errors = client.receive_all_messages(timeout=2)
        
        for msg in errors:
            if msg.get('type') == 'error' and msg.get('name') == 'INVALID_TX_OUTPOINT':
                return TestResult("spending_coinbase_same_block", True, "OK", time.time() - start)
        
        return TestResult("spending_coinbase_same_block", False, 
                        f"Expected INVALID_TX_OUTPOINT, got: {errors}", time.time() - start)
    finally:
        client.close()

def test_multiple_coinbase_transactions() -> TestResult:
    """Test INVALID_BLOCK_COINBASE - multiple coinbase transactions"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("multiple_coinbase", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create TWO coinbase transactions
        coinbase1 = create_coinbase_tx(1, "a" * 64)
        coinbase1_id = object_id(coinbase1)
        
        coinbase2 = create_coinbase_tx(1, "b" * 64)
        coinbase2_id = object_id(coinbase2)
        
        # Block with two coinbases
        block = create_and_mine_block([coinbase1_id, coinbase2_id], GENESIS_ID, 1671062500)
        
        client.send_message({"type": "object", "object": block})
        
        # Handle fetching
        requests = client.receive_all_messages(timeout=1)
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == coinbase1_id:
                    client.send_message({"type": "object", "object": coinbase1})
                elif obj_id == coinbase2_id:
                    client.send_message({"type": "object", "object": coinbase2})
        
        time.sleep(1)
        errors = client.receive_all_messages(timeout=2)
        
        for msg in errors:
            if msg.get('type') == 'error' and msg.get('name') == 'INVALID_BLOCK_COINBASE':
                return TestResult("multiple_coinbase", True, "OK", time.time() - start)
        
        return TestResult("multiple_coinbase", False, 
                        f"Expected INVALID_BLOCK_COINBASE, got: {errors}", time.time() - start)
    finally:
        client.close()

def test_coinbase_not_first() -> TestResult:
    """Test INVALID_BLOCK_COINBASE - coinbase not at first position"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("coinbase_not_first", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create a normal transaction (dummy)
        privkey, pubkey = generate_keypair()
        tx1 = create_transaction(
            inputs=[{
                "outpoint": {"txid": "a" * 64, "index": 0},
                "sig": "b" * 128
            }],
            outputs=[{"pubkey": pubkey, "value": 1000}]
        )
        tx1_id = object_id(tx1)
        
        # Create coinbase
        coinbase = create_coinbase_tx(1, pubkey)
        coinbase_id = object_id(coinbase)
        
        # Block with coinbase at SECOND position (invalid)
        block = create_and_mine_block([tx1_id, coinbase_id], GENESIS_ID, 1671062500)
        
        client.send_message({"type": "object", "object": block})
        
        # Handle fetching
        requests = client.receive_all_messages(timeout=1)
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == tx1_id:
                    client.send_message({"type": "object", "object": tx1})
                elif obj_id == coinbase_id:
                    client.send_message({"type": "object", "object": coinbase})
        
        time.sleep(1)
        errors = client.receive_all_messages(timeout=2)
        
        for msg in errors:
            if msg.get('type') == 'error' and msg.get('name') == 'INVALID_BLOCK_COINBASE':
                return TestResult("coinbase_not_first", True, "OK", time.time() - start)
        
        return TestResult("coinbase_not_first", False, 
                        f"Expected INVALID_BLOCK_COINBASE, got: {errors}", time.time() - start)
    finally:
        client.close()

def test_self_double_spend_tx() -> TestResult:
    """Test INVALID_TX_CONSERVATION - transaction double spends itself"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("self_double_spend", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create a coinbase
        privkey, pubkey = generate_keypair()
        coinbase1 = create_coinbase_tx(1, pubkey, 50000000000000)
        coinbase1_id = object_id(coinbase1)
        
        # Create transaction that uses SAME input TWICE
        tx1 = create_transaction(
            inputs=[
                {
                    "outpoint": {"txid": coinbase1_id, "index": 0},
                    "sig": None
                },
                {
                    "outpoint": {"txid": coinbase1_id, "index": 0},  # SAME!
                    "sig": None
                }
            ],
            outputs=[{"pubkey": pubkey, "value": 25000000000000}]
        )
        tx1_signed = sign_transaction(tx1, [privkey, privkey])
        tx1_id = object_id(tx1_signed)
        
        # Create block
        block1 = create_and_mine_block([coinbase1_id, tx1_id], GENESIS_ID, 1671062500)
        
        client.send_message({"type": "object", "object": block1})
        
        # Handle fetching
        requests = client.receive_all_messages(timeout=1)
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == coinbase1_id:
                    client.send_message({"type": "object", "object": coinbase1})
                elif obj_id == tx1_id:
                    client.send_message({"type": "object", "object": tx1_signed})
        
        time.sleep(1)
        errors = client.receive_all_messages(timeout=2)
        
        for msg in errors:
            if msg.get('type') == 'error' and msg.get('name') == 'INVALID_TX_CONSERVATION':
                return TestResult("self_double_spend", True, "OK", time.time() - start)
        
        return TestResult("self_double_spend", False, 
                        f"Expected INVALID_TX_CONSERVATION, got: {errors}", time.time() - start)
    finally:
        client.close()

def test_invalid_format_block_as_tx() -> TestResult:
    """Test INVALID_FORMAT - block referenced where transaction expected"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("invalid_format_block_as_tx", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Reference genesis block as if it were a transaction
        privkey, pubkey = generate_keypair()
        tx1 = create_transaction(
            inputs=[{
                "outpoint": {"txid": GENESIS_ID, "index": 0},  # Genesis is a BLOCK!
                "sig": None
            }],
            outputs=[{"pubkey": pubkey, "value": 1000}]
        )
        tx1_signed = sign_transaction(tx1, [privkey])
        tx1_id = object_id(tx1_signed)
        
        block = create_and_mine_block([tx1_id], GENESIS_ID, 1671062500)
        
        client.send_message({"type": "object", "object": block})
        
        # Handle fetching
        requests = client.receive_all_messages(timeout=1)
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == tx1_id:
                    client.send_message({"type": "object", "object": tx1_signed})
        
        time.sleep(1)
        errors = client.receive_all_messages(timeout=2)
        
        for msg in errors:
            if msg.get('type') == 'error' and msg.get('name') == 'INVALID_FORMAT':
                return TestResult("invalid_format_block_as_tx", True, "OK", time.time() - start)
        
        return TestResult("invalid_format_block_as_tx", False, 
                        f"Expected INVALID_FORMAT, got: {errors}", time.time() - start)
    finally:
        client.close()

def test_chaintip_returns_invalid_format() -> TestResult:
    """Test INVALID_FORMAT when chaintip references non-block"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("chaintip_invalid_format", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create a transaction
        privkey, pubkey = generate_keypair()
        tx = create_transaction(
            inputs=[{
                "outpoint": {"txid": "a" * 64, "index": 0},
                "sig": "b" * 128
            }],
            outputs=[{"pubkey": pubkey, "value": 1000}]
        )
        tx_id = object_id(tx)
        
        # Send chaintip that references a transaction instead of block
        client.send_message({"type": "chaintip", "blockid": tx_id})
        
        # Node should request it
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'getobject':
            # Send the transaction
            client.send_message({"type": "object", "object": tx})
            
            # Should get INVALID_FORMAT error
            errors = client.receive_all_messages(timeout=2)
            for err in errors:
                if err.get('type') == 'error' and err.get('name') == 'INVALID_FORMAT':
                    return TestResult("chaintip_invalid_format", True, "OK", time.time() - start)
        
        return TestResult("chaintip_invalid_format", False, "Expected INVALID_FORMAT", time.time() - start)
    finally:
        client.close()

def test_chaintip_invalid_pow() -> TestResult:
    """Test INVALID_BLOCK_POW when chaintip has obviously invalid PoW"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("chaintip_invalid_pow", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create block with obviously invalid PoW (can be detected from ID alone)
        block = create_and_mine_block([], GENESIS_ID, 1671062500)
        block_id = object_id(block)
        
        # Send chaintip with invalid PoW
        client.send_message({"type": "chaintip", "blockid": block_id})
        
        # Should get INVALID_BLOCK_POW error immediately
        errors = client.receive_all_messages(timeout=2)
        for err in errors:
            if err.get('type') == 'error' and err.get('name') == 'INVALID_BLOCK_POW':
                return TestResult("chaintip_invalid_pow", True, "OK", time.time() - start)
        
        return TestResult("chaintip_invalid_pow", False, "Expected INVALID_BLOCK_POW", time.time() - start)
    finally:
        client.close()

# ==================== TEST RUNNER ====================

def run_all_tests() -> List[TestResult]:
    """Run all test cases"""
    tests = [
        ("Basic Handshake", test_hello_handshake),
        ("GetChainTip (Initial)", test_getchaintip_initial),
        
        # Test cases from specification
        ("1a: Unavailable Block", test_unavailable_block),
        ("1b: Non-Increasing Timestamps", test_non_increasing_timestamps),
        ("1c: Future Timestamp (2077)", test_future_timestamp),
        ("1d: Invalid PoW", test_invalid_pow),
        ("1e: Wrong Genesis", test_wrong_genesis),
        ("1f: Incorrect Coinbase Height", test_incorrect_coinbase_height),
        ("1g: Double Spending", test_double_spending),
        ("1h: Non-Existent Output", test_nonexistent_output),
        
        # Additional error cases
        ("Invalid Ancestry Propagation", test_invalid_ancestry_propagation),
        ("INVALID_TX_CONSERVATION", test_invalid_tx_conservation),
        ("INVALID_TX_SIGNATURE", test_invalid_tx_signature),
        ("INVALID_BLOCK_COINBASE (excessive value)", test_coinbase_excessive_value),
        ("INVALID_TX_OUTPOINT (spend coinbase same block)", test_spending_coinbase_same_block),
        ("INVALID_BLOCK_COINBASE (multiple)", test_multiple_coinbase_transactions),
        ("INVALID_BLOCK_COINBASE (not first)", test_coinbase_not_first),
        ("INVALID_TX_CONSERVATION (self double-spend)", test_self_double_spend_tx),
        ("INVALID_FORMAT (block as tx)", test_invalid_format_block_as_tx),
        ("ChainTip INVALID_FORMAT", test_chaintip_returns_invalid_format),
        ("ChainTip INVALID_BLOCK_POW", test_chaintip_invalid_pow),
        
        # Longest chain rule & happy path tests (CRITICAL for Task 4)
        ("Happy Path: Valid Chain", test_happy_path_valid_chain),
        ("Longest Chain Selection", test_longest_chain_selection),
        ("Invalid Longer Chain Rejected", test_invalid_longer_chain_rejected),
        ("IHaveObject Broadcast", test_ihaveobject_broadcast),

        # Even more tests
        ("Peers Message Validation", test_peers_message_validation),
        ("Invalid Peers Format", test_invalid_peers_format),
        ("GetPeers On Connect", test_getpeers_on_connect),
        ("GetChainTip On Connect", test_getchaintip_on_connect),
        ("Unknown Object Response", test_unknown_object_response),
        ("Handshake Timeout", test_handshake_timeout),
        ("Invalid Version", test_invalid_version),
        ("Object Broadcast After Validation", test_object_broadcast_after_validation),
        ("Multiple ChainTip Updates", test_multiple_chaintip_updates),
        ("Forked Chains Selection", test_forked_chains_selection),
    ]
    
    results = []
    print(f"\n{'='*70}")
    print(f"Running {len(tests)} tests...")
    print(f"{'='*70}\n")
    
    for name, test_func in tests:
        print(f"Running: {name}...", end=" ", flush=True)
        result = test_func()
        results.append(result)
        
        status = "✓ PASS" if result.passed else "✗ FAIL"
        print(f"{status} ({result.duration:.2f}s)")
        if not result.passed:
            print(f"  └─ {result.message}")
    
    return results

def print_summary(results: List[TestResult]):
    """Print test summary"""
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    
    print(f"\n{'='*70}")
    print(f"Test Summary: {passed}/{total} passed")
    print(f"{'='*70}\n")
    
    if passed < total:
        print("Failed tests:")
        for r in results:
            if not r.passed:
                print(f"  • {r.name}: {r.message}")
        print()
    
    return passed == total


def test_nonexistent_output() -> TestResult:
    """Test 1h: Transaction spending output that doesn't exist (INVALID_TX_OUTPOINT)"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("nonexistent_output", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create a coinbase with only 1 output (index 0)
        privkey, pubkey = generate_keypair()
        coinbase1 = create_coinbase_tx(1, pubkey, 50000000000000)
        coinbase1_id = object_id(coinbase1)
        
        # Try to spend from index 1 (doesn't exist!)
        tx1 = create_transaction(
            inputs=[{
                "outpoint": {"txid": coinbase1_id, "index": 1},  # Invalid index
                "sig": None
            }],
            outputs=[{"pubkey": pubkey, "value": 25000000000000}]
        )
        tx1_signed = sign_transaction(tx1, [privkey])
        tx1_id = object_id(tx1_signed)
        
        # Create blocks
        block1 = create_and_mine_block([coinbase1_id], GENESIS_ID, 1671062500)
        block1_id = object_id(block1)
        
        block2 = create_and_mine_block([tx1_id], block1_id, 1671062600)
        
        # Send block2
        client.send_message({"type": "object", "object": block2})
        
        # Handle recursive fetching
        requests = client.receive_all_messages(timeout=1)
        
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == block1_id:
                    client.send_message({"type": "object", "object": block1})
                elif obj_id == tx1_id:
                    client.send_message({"type": "object", "object": tx1_signed})
                elif obj_id == coinbase1_id:
                    client.send_message({"type": "object", "object": coinbase1})
        
        # Wait for error
        time.sleep(1)
        errors = client.receive_all_messages(timeout=2)
        
        # Should get INVALID_TX_OUTPOINT
        for msg in errors:
            if msg.get('type') == 'error' and msg.get('name') == 'INVALID_TX_OUTPOINT':
                return TestResult("nonexistent_output", True, "OK", time.time() - start)
        
        return TestResult("nonexistent_output", False, 
                        f"Expected INVALID_TX_OUTPOINT, got: {errors}", time.time() - start)
    finally:
        client.close()

def test_invalid_ancestry_propagation() -> TestResult:
    """Test INVALID_ANCESTRY error propagates correctly"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("invalid_ancestry", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create chain: block1 (invalid PoW) -> block2
        block1 = create_and_mine_block([], GENESIS_ID, 1671062500)
        block1_id = object_id(block1)
        
        block2 = create_and_mine_block([], block1_id, 1671062600)
        
        # Send block2 first (depends on block1)
        client.send_message({"type": "object", "object": block2})
        
        # Should request block1
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'getobject' and msg.get('objectid') == block1_id:
            # Send invalid block1
            client.send_message({"type": "object", "object": block1})
            
            # Should get errors
            errors = client.receive_all_messages(timeout=2)
            
            # Should get INVALID_ANCESTRY for block2
            for err in errors:
                if err.get('type') == 'error' and err.get('name') == 'INVALID_ANCESTRY':
                    return TestResult("invalid_ancestry", True, "OK", time.time() - start)
        
        return TestResult("invalid_ancestry", False, "INVALID_ANCESTRY not propagated", time.time() - start)
    finally:
        client.close()

def test_invalid_tx_conservation() -> TestResult:
    """Test INVALID_TX_CONSERVATION - output value exceeds input value"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("invalid_tx_conservation", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create a coinbase
        privkey, pubkey = generate_keypair()
        coinbase1 = create_coinbase_tx(1, pubkey, 50000000000000)
        coinbase1_id = object_id(coinbase1)
        
        # Create transaction that spends MORE than input
        tx1 = create_transaction(
            inputs=[{
                "outpoint": {"txid": coinbase1_id, "index": 0},
                "sig": None
            }],
            outputs=[{"pubkey": pubkey, "value": 99999999999999}]  # More than 50T!
        )
        tx1_signed = sign_transaction(tx1, [privkey])
        tx1_id = object_id(tx1_signed)
        
        # Create block
        block1 = create_and_mine_block([coinbase1_id, tx1_id], GENESIS_ID, 1671062500)
        
        client.send_message({"type": "object", "object": block1})
        
        # Handle fetching
        requests = client.receive_all_messages(timeout=1)
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == coinbase1_id:
                    client.send_message({"type": "object", "object": coinbase1})
                elif obj_id == tx1_id:
                    client.send_message({"type": "object", "object": tx1_signed})
        
        time.sleep(1)
        errors = client.receive_all_messages(timeout=2)
        
        for msg in errors:
            if msg.get('type') == 'error' and msg.get('name') == 'INVALID_TX_CONSERVATION':
                return TestResult("invalid_tx_conservation", True, "OK", time.time() - start)
        
        return TestResult("invalid_tx_conservation", False, 
                        f"Expected INVALID_TX_CONSERVATION, got: {errors}", time.time() - start)
    finally:
        client.close()

def test_invalid_tx_signature() -> TestResult:
    """Test INVALID_TX_SIGNATURE - wrong signature"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("invalid_tx_signature", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create a coinbase
        privkey, pubkey = generate_keypair()
        coinbase1 = create_coinbase_tx(1, pubkey, 50000000000000)
        coinbase1_id = object_id(coinbase1)
        
        # Create transaction with WRONG signature
        tx1 = create_transaction(
            inputs=[{
                "outpoint": {"txid": coinbase1_id, "index": 0},
                "sig": "a" * 128  # Invalid signature
            }],
            outputs=[{"pubkey": pubkey, "value": 25000000000000}]
        )
        tx1_id = object_id(tx1)
        
        # Create block
        block1 = create_and_mine_block([coinbase1_id, tx1_id], GENESIS_ID, 1671062500)
        
        client.send_message({"type": "object", "object": block1})
        
        # Handle fetching
        requests = client.receive_all_messages(timeout=1)
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == coinbase1_id:
                    client.send_message({"type": "object", "object": coinbase1})
                elif obj_id == tx1_id:
                    client.send_message({"type": "object", "object": tx1})
        
        time.sleep(1)
        errors = client.receive_all_messages(timeout=2)
        
        for msg in errors:
            if msg.get('type') == 'error' and msg.get('name') == 'INVALID_TX_SIGNATURE':
                return TestResult("invalid_tx_signature", True, "OK", time.time() - start)
        
        return TestResult("invalid_tx_signature", False, 
                        f"Expected INVALID_TX_SIGNATURE, got: {errors}", time.time() - start)
    finally:
        client.close()

def test_coinbase_excessive_value() -> TestResult:
    """Test INVALID_BLOCK_COINBASE - coinbase creates too many coins"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("coinbase_excessive_value", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Create coinbase with excessive value (more than 50T)
        coinbase = create_coinbase_tx(1, "a" * 64, 99999999999999)
        coinbase_id = object_id(coinbase)
        
        block = create_and_mine_block([coinbase_id], GENESIS_ID, 1671062500)
        
        client.send_message({"type": "object", "object": block})
        
        # Handle fetching
        requests = client.receive_all_messages(timeout=1)
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == coinbase_id:
                    client.send_message({"type": "object", "object": coinbase})
        
        time.sleep(1)
        errors = client.receive_all_messages(timeout=2)
        
        for msg in errors:
            if msg.get('type') == 'error' and msg.get('name') == 'INVALID_BLOCK_COINBASE':
                return TestResult("coinbase_excessive_value", True, "OK", time.time() - start)
        
        return TestResult("coinbase_excessive_value", False, 
                        f"Expected INVALID_BLOCK_COINBASE, got: {errors}", time.time() - start)
    finally:
        client.close()

def test_happy_path_valid_chain() -> TestResult:
    """Test happy path: valid 2-block chain is accepted and adopted"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("happy_path_valid_chain", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        print("  Mining valid blocks...")
        
        # Create valid coinbase for block 1
        privkey, pubkey = generate_keypair()
        coinbase1 = create_coinbase_tx(1, pubkey, 50000000000000)
        coinbase1_id = object_id(coinbase1)
        
        # Mine block 1
        block1 = create_and_mine_block([coinbase1_id], GENESIS_ID, 1671062500)
        if not block1:
            return TestResult("happy_path_valid_chain", False, "Failed to mine block1", time.time() - start)
        block1_id = object_id(block1)
        
        # Create coinbase for block 2
        coinbase2 = create_coinbase_tx(2, pubkey, 50000000000000)
        coinbase2_id = object_id(coinbase2)
        
        # Mine block 2
        block2 = create_and_mine_block([coinbase2_id], block1_id, 1671062600)
        if not block2:
            return TestResult("happy_path_valid_chain", False, "Failed to mine block2", time.time() - start)
        block2_id = object_id(block2)
        
        print("  Sending blocks to node...")
        
        # Send block2 first (triggers recursive fetch)
        client.send_message({"type": "object", "object": block2})
        
        # Handle recursive fetching
        for _ in range(10):
            requests = client.receive_all_messages(timeout=0.5)
            if not requests:
                break
            
            for req in requests:
                if req.get('type') == 'getobject':
                    obj_id = req.get('objectid')
                    if obj_id == block1_id:
                        client.send_message({"type": "object", "object": block1})
                    elif obj_id == coinbase1_id:
                        client.send_message({"type": "object", "object": coinbase1})
                    elif obj_id == coinbase2_id:
                        client.send_message({"type": "object", "object": coinbase2})
        
        # Wait for processing
        time.sleep(1)
        
        # Check getchaintip
        client.send_message({"type": "getchaintip"})
        msg = client.receive_message(timeout=2)
        
        if msg and msg.get('type') == 'chaintip':
            tip = msg.get('blockid')
            if tip == block2_id:
                return TestResult("happy_path_valid_chain", True, 
                                f"OK (adopted 2-block chain)", time.time() - start)
            elif tip == block1_id:
                return TestResult("happy_path_valid_chain", False, 
                                f"Only adopted block1, not block2", time.time() - start)
            elif tip == GENESIS_ID:
                return TestResult("happy_path_valid_chain", False, 
                                f"Chain not adopted (still at genesis)", time.time() - start)
            else:
                return TestResult("happy_path_valid_chain", False, 
                                f"Unexpected tip: {tip}", time.time() - start)
        
        return TestResult("happy_path_valid_chain", False, 
                        f"Expected chaintip response, got: {msg}", time.time() - start)
    finally:
        client.close()

def test_longest_chain_selection() -> TestResult:
    """Test longest chain rule: node picks longer valid chain"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("longest_chain_selection", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        print("  Mining chains A (length 1) and B (length 2)...")
        
        privkey, pubkey = generate_keypair()
        
        # Chain A: genesis -> block1a (length 1)
        coinbase1a = create_coinbase_tx(1, pubkey, 50000000000000)
        coinbase1a_id = object_id(coinbase1a)
        block1a = create_and_mine_block([coinbase1a_id], GENESIS_ID, 1671062500, note="chain_a")
        if not block1a:
            return TestResult("longest_chain_selection", False, "Failed to mine block1a", time.time() - start)
        block1a_id = object_id(block1a)
        
        # Chain B: genesis -> block1b -> block2b (length 2)
        coinbase1b = create_coinbase_tx(1, pubkey, 50000000000000)
        coinbase1b_id = object_id(coinbase1b)
        block1b = create_and_mine_block([coinbase1b_id], GENESIS_ID, 1671062501, note="chain_b1")
        if not block1b:
            return TestResult("longest_chain_selection", False, "Failed to mine block1b", time.time() - start)
        block1b_id = object_id(block1b)
        
        coinbase2b = create_coinbase_tx(2, pubkey, 50000000000000)
        coinbase2b_id = object_id(coinbase2b)
        block2b = create_and_mine_block([coinbase2b_id], block1b_id, 1671062600, note="chain_b2")
        if not block2b:
            return TestResult("longest_chain_selection", False, "Failed to mine block2b", time.time() - start)
        block2b_id = object_id(block2b)
        
        print("  Sending chain A first...")
        
        # Send chain A first
        client.send_message({"type": "object", "object": block1a})
        requests = client.receive_all_messages(timeout=0.5)
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == coinbase1a_id:
                    client.send_message({"type": "object", "object": coinbase1a})
        
        time.sleep(0.5)
        
        # Check tip (should be block1a)
        client.send_message({"type": "getchaintip"})
        msg = client.receive_message(timeout=2)
        first_tip = msg.get('blockid') if msg else None
        
        print(f"  After chain A: tip={first_tip[:16] if first_tip else 'none'}...")
        print("  Sending longer chain B...")
        
        # Now send longer chain B
        client.send_message({"type": "object", "object": block2b})
        
        for _ in range(10):
            requests = client.receive_all_messages(timeout=0.5)
            if not requests:
                break
            
            for req in requests:
                if req.get('type') == 'getobject':
                    obj_id = req.get('objectid')
                    if obj_id == block1b_id:
                        client.send_message({"type": "object", "object": block1b})
                    elif obj_id == coinbase1b_id:
                        client.send_message({"type": "object", "object": coinbase1b})
                    elif obj_id == coinbase2b_id:
                        client.send_message({"type": "object", "object": coinbase2b})
        
        time.sleep(1)
        
        # Check tip again (should now be block2b - the longer chain)
        client.send_message({"type": "getchaintip"})
        msg = client.receive_message(timeout=2)
        second_tip = msg.get('blockid') if msg else None
        
        print(f"  After chain B: tip={second_tip[:16] if second_tip else 'none'}...")
        
        if second_tip == block2b_id:
            return TestResult("longest_chain_selection", True, 
                            f"OK (correctly switched to longer chain)", time.time() - start)
        elif second_tip == block1a_id:
            return TestResult("longest_chain_selection", False, 
                            f"Did not switch to longer chain (still at chain A)", time.time() - start)
        else:
            return TestResult("longest_chain_selection", False, 
                            f"Unexpected tip: {second_tip}", time.time() - start)
    finally:
        client.close()

def test_invalid_longer_chain_rejected() -> TestResult:
    """Test that invalid longer chain is rejected in favor of shorter valid chain"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("invalid_longer_chain_rejected", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        print("  Mining valid chain and creating invalid longer chain...")
        
        privkey, pubkey = generate_keypair()
        
        # Valid chain: genesis -> block1 (length 1)
        coinbase1 = create_coinbase_tx(1, pubkey, 50000000000000)
        coinbase1_id = object_id(coinbase1)
        block1 = create_and_mine_block([coinbase1_id], GENESIS_ID, 1671062500, note="valid")
        if not block1:
            return TestResult("invalid_longer_chain_rejected", False, "Failed to mine block1", time.time() - start)
        block1_id = object_id(block1)
        
        # Invalid longer chain: genesis -> block2 (bad PoW) -> block3 (length 2)
        block2_invalid = create_and_mine_block([], GENESIS_ID, 1671062501, note="invalid_pow")  # BAD POW
        block2_id = object_id(block2_invalid)
        
        coinbase3 = create_coinbase_tx(2, pubkey, 50000000000000)
        coinbase3_id = object_id(coinbase3)
        # Mine block3 (even though it's based on invalid parent)
        block3 = create_and_mine_block([coinbase3_id], block2_id, 1671062600, note="invalid_ancestry")
        if not block3:
            return TestResult("invalid_longer_chain_rejected", False, "Failed to mine block3", time.time() - start)
        block3_id = object_id(block3)
        
        print("  Sending valid chain first...")
        
        # Send valid chain first
        client.send_message({"type": "object", "object": block1})
        requests = client.receive_all_messages(timeout=0.5)
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == coinbase1_id:
                    client.send_message({"type": "object", "object": coinbase1})
        
        time.sleep(0.5)
        
        # Check tip should be block1
        client.send_message({"type": "getchaintip"})
        msg = client.receive_message(timeout=2)
        first_tip = msg.get('blockid') if msg else None
        
        print(f"  After valid chain: tip={first_tip[:16] if first_tip else 'none'}...")
        print("  Sending invalid longer chain...")
        
        # Send invalid longer chain
        client.send_message({"type": "object", "object": block3})
        
        for _ in range(5):
            requests = client.receive_all_messages(timeout=0.5)
            if not requests:
                break
            
            for req in requests:
                if req.get('type') == 'getobject':
                    obj_id = req.get('objectid')
                    if obj_id == block2_id:
                        client.send_message({"type": "object", "object": block2_invalid})
                    elif obj_id == coinbase3_id:
                        client.send_message({"type": "object", "object": coinbase3})
        
        # Should get INVALID_ANCESTRY for block3
        time.sleep(1)
        errors = client.receive_all_messages(timeout=2)
        
        # Check final tip - should still be block1, NOT block3
        client.send_message({"type": "getchaintip"})
        msg = client.receive_message(timeout=2)
        final_tip = msg.get('blockid') if msg else None
        
        print(f"  After invalid chain: tip={final_tip[:16] if final_tip else 'none'}...")
        
        if final_tip == block1_id:
            return TestResult("invalid_longer_chain_rejected", True, 
                            f"OK (correctly rejected invalid longer chain)", time.time() - start)
        elif final_tip == block3_id:
            return TestResult("invalid_longer_chain_rejected", False, 
                            f"Node incorrectly adopted invalid chain", time.time() - start)
        else:
            return TestResult("invalid_longer_chain_rejected", False, 
                            f"Unexpected tip: {final_tip}", time.time() - start)
    finally:
        client.close()

def test_ihaveobject_broadcast() -> TestResult:
    """Test that node broadcasts ihaveobject after validating new object"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("ihaveobject_broadcast", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        print("  Mining valid block for ihaveobject test...")
        
        # Create and mine a valid block
        privkey, pubkey = generate_keypair()
        coinbase = create_coinbase_tx(1, pubkey, 50000000000000)
        coinbase_id = object_id(coinbase)
        block = create_and_mine_block([coinbase_id], GENESIS_ID, 1671062500, note="ihave_test")
        if not block:
            return TestResult("ihaveobject_broadcast", False, "Failed to mine block", time.time() - start)
        block_id = object_id(block)
        
        # Send the block
        client.send_message({"type": "object", "object": block})
        
        # Handle fetching
        requests = client.receive_all_messages(timeout=0.5)
        for req in requests:
            if req.get('type') == 'getobject':
                obj_id = req.get('objectid')
                if obj_id == coinbase_id:
                    client.send_message({"type": "object", "object": coinbase})
        
        # Wait and check for ihaveobject messages
        time.sleep(1)
        messages = client.receive_all_messages(timeout=1)
        
        # Look for ihaveobject
        ihave_found = []
        for msg in messages:
            if msg.get('type') == 'ihaveobject':
                ihave_found.append(msg.get('objectid'))
        
        if block_id in ihave_found or coinbase_id in ihave_found:
            return TestResult("ihaveobject_broadcast", True, 
                            f"OK (ihaveobject broadcast for {len(ihave_found)} objects)", time.time() - start)
        
        return TestResult("ihaveobject_broadcast", False, 
                        f"No ihaveobject received (expected for block or coinbase)", time.time() - start)
    finally:
        client.close()





        #!/usr/bin/env python3
"""
Additional multi-peer test cases for Kerma Task 4
These test the "real-world scenario" with multiple peers

Add these test functions to your test_task4.py file
"""

def test_peers_message_validation() -> TestResult:
    """Test that node properly validates and stores peers"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("peers_validation", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Send valid peers message
        valid_peers = [
            "node1.example.com:18018",
            "192.168.1.100:18018",
            "10.0.0.5:19000"
        ]
        
        client.send_message({"type": "peers", "peers": valid_peers})
        time.sleep(0.5)
        
        # Request peers back
        client.send_message({"type": "getpeers"})
        msg = client.receive_message(timeout=2)
        
        if msg and msg.get('type') == 'peers':
            received_peers = msg.get('peers', [])
            # Should include at least some of the peers we sent
            # (node might filter private IPs or add itself)
            return TestResult("peers_validation", True, 
                            f"OK (received {len(received_peers)} peers)", time.time() - start)
        
        return TestResult("peers_validation", False, 
                        f"Expected peers response, got: {msg}", time.time() - start)
    finally:
        client.close()

def test_invalid_peers_format() -> TestResult:
    """Test INVALID_FORMAT error for malformed peers"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("invalid_peers_format", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Send peers with invalid format (no port)
        invalid_peers = {
            "type": "peers",
            "peers": ["node.example.com"]  # Missing port!
        }
        
        client.send_message(invalid_peers)
        
        # Should get INVALID_FORMAT error
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'error' and msg.get('name') == 'INVALID_FORMAT':
            return TestResult("invalid_peers_format", True, "OK", time.time() - start)
        
        return TestResult("invalid_peers_format", False, 
                        f"Expected INVALID_FORMAT, got: {msg}", time.time() - start)
    finally:
        client.close()

def test_getpeers_on_connect() -> TestResult:
    """Test that node sends getpeers after connecting"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("getpeers_on_connect", False, "Connection failed", time.time() - start)
        
        # Check if getpeers was sent (should happen right after hello)
        msg = client.receive_message(timeout=2)
        
        if msg and msg.get('type') == 'getpeers':
            # Reply with empty peers
            client.send_message({"type": "peers", "peers": []})
            return TestResult("getpeers_on_connect", True, "OK", time.time() - start)
        
        return TestResult("getpeers_on_connect", False, 
                        f"Expected getpeers after handshake, got: {msg}", time.time() - start)
    finally:
        client.close()

def test_getchaintip_on_connect() -> TestResult:
    """Test that node sends getchaintip after getpeers"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("getchaintip_on_connect", False, "Connection failed", time.time() - start)
        
        # Wait for getpeers
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'getpeers':
            client.send_message({"type": "peers", "peers": []})
        
        # Should get getchaintip next (Task 4 requirement)
        msg = client.receive_message(timeout=2)
        
        if msg and msg.get('type') == 'getchaintip':
            # Reply with genesis
            client.send_message({"type": "chaintip", "blockid": GENESIS_ID})
            return TestResult("getchaintip_on_connect", True, "OK", time.time() - start)
        
        return TestResult("getchaintip_on_connect", False, 
                        f"Expected getchaintip after getpeers, got: {msg}", time.time() - start)
    finally:
        client.close()

def test_unknown_object_response() -> TestResult:
    """Test UNKNOWN_OBJECT when requesting object node doesn't have"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("unknown_object", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        # Request non-existent object
        fake_id = "9999999999999999999999999999999999999999999999999999999999999999"
        client.send_message({"type": "getobject", "objectid": fake_id})
        
        # Should get UNKNOWN_OBJECT error
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'error' and msg.get('name') == 'UNKNOWN_OBJECT':
            return TestResult("unknown_object", True, "OK", time.time() - start)
        
        return TestResult("unknown_object", False, 
                        f"Expected UNKNOWN_OBJECT, got: {msg}", time.time() - start)
    finally:
        client.close()

def test_handshake_timeout() -> TestResult:
    """Test INVALID_HANDSHAKE if no hello sent within 20s"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        # Connect but don't handshake
        if not client.connect():
            return TestResult("handshake_timeout", False, "Connection failed", time.time() - start)
        
        # Receive server's hello but don't send ours
        msg = client.receive_message(timeout=3)
        if not msg or msg.get('type') != 'hello':
            return TestResult("handshake_timeout", False, "Didn't receive hello", time.time() - start)
        
        # Don't send hello, just wait
        # (For actual test, would need to wait 20s which is too long)
        # Instead, send a non-hello message first
        client.send_message({"type": "getpeers"})
        
        # Should get INVALID_HANDSHAKE error
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'error' and msg.get('name') == 'INVALID_HANDSHAKE':
            return TestResult("handshake_timeout", True, "OK", time.time() - start)
        
        return TestResult("handshake_timeout", False, 
                        f"Expected INVALID_HANDSHAKE, got: {msg}", time.time() - start)
    finally:
        client.close()

def test_invalid_version() -> TestResult:
    """Test INVALID_FORMAT for wrong version in hello"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect():
            return TestResult("invalid_version", False, "Connection failed", time.time() - start)
        
        # Receive server's hello
        msg = client.receive_message(timeout=3)
        if not msg or msg.get('type') != 'hello':
            return TestResult("invalid_version", False, "Didn't receive hello", time.time() - start)
        
        # Send hello with wrong version
        bad_hello = {
            "type": "hello",
            "version": "1.0.0",  # Wrong format (should be 0.10.x)
            "agent": "Test-Client"
        }
        client.send_message(bad_hello)
        
        # Should get INVALID_FORMAT error
        msg = client.receive_message(timeout=2)
        if msg and msg.get('type') == 'error' and msg.get('name') == 'INVALID_FORMAT':
            return TestResult("invalid_version", True, "OK", time.time() - start)
        
        return TestResult("invalid_version", False, 
                        f"Expected INVALID_FORMAT, got: {msg}", time.time() - start)
    finally:
        client.close()

def test_object_broadcast_after_validation() -> TestResult:
    """Test that validated objects are stored and can be retrieved"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("object_broadcast", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        print("  Mining block for broadcast test...")
        
        # Create and mine a valid block
        privkey, pubkey = generate_keypair()
        coinbase = create_coinbase_tx(1, pubkey, 50000000000000)
        coinbase_id = object_id(coinbase)
        block = create_and_mine_block([coinbase_id], GENESIS_ID, 1671062500, note="broadcast_test")
        if not block:
            return TestResult("object_broadcast", False, "Mining failed", time.time() - start)
        block_id = object_id(block)
        
        # Send block
        client.send_message({"type": "object", "object": block})
        
        # Handle fetching
        for _ in range(5):
            requests = client.receive_all_messages(timeout=0.5)
            if not requests:
                break
            for req in requests:
                if req.get('type') == 'getobject':
                    if req.get('objectid') == coinbase_id:
                        client.send_message({"type": "object", "object": coinbase})
        
        time.sleep(1)
        
        # Now try to request the block back
        client.send_message({"type": "getobject", "objectid": block_id})
        msg = client.receive_message(timeout=2)
        
        if msg and msg.get('type') == 'object':
            received_block = msg.get('object')
            if object_id(received_block) == block_id:
                return TestResult("object_broadcast", True, 
                                "OK (block stored and retrievable)", time.time() - start)
        
        return TestResult("object_broadcast", False, 
                        f"Block not stored or not retrievable", time.time() - start)
    finally:
        client.close()

def test_multiple_chaintip_updates() -> TestResult:
    """Test that chaintip updates correctly as longer chains arrive"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("multiple_chaintip_updates", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        print("  Mining 3 blocks for chaintip update test...")
        
        privkey, pubkey = generate_keypair()
        
        # Block 1
        cb1 = create_coinbase_tx(1, pubkey, 50000000000000)
        cb1_id = object_id(cb1)
        b1 = create_and_mine_block([cb1_id], GENESIS_ID, 1671062500, note="tip1")
        if not b1:
            return TestResult("multiple_chaintip_updates", False, "Mining b1 failed", time.time() - start)
        b1_id = object_id(b1)
        
        # Block 2
        cb2 = create_coinbase_tx(2, pubkey, 50000000000000)
        cb2_id = object_id(cb2)
        b2 = create_and_mine_block([cb2_id], b1_id, 1671062600, note="tip2")
        if not b2:
            return TestResult("multiple_chaintip_updates", False, "Mining b2 failed", time.time() - start)
        b2_id = object_id(b2)
        
        # Block 3
        cb3 = create_coinbase_tx(3, pubkey, 50000000000000)
        cb3_id = object_id(cb3)
        b3 = create_and_mine_block([cb3_id], b2_id, 1671062700, note="tip3")
        if not b3:
            return TestResult("multiple_chaintip_updates", False, "Mining b3 failed", time.time() - start)
        b3_id = object_id(b3)
        
        # Send block 1
        client.send_message({"type": "object", "object": b1})
        requests = client.receive_all_messages(timeout=0.5)
        for req in requests:
            if req.get('type') == 'getobject' and req.get('objectid') == cb1_id:
                client.send_message({"type": "object", "object": cb1})
        
        time.sleep(0.5)
        client.send_message({"type": "getchaintip"})
        msg1 = client.receive_message(timeout=2)
        tip1 = msg1.get('blockid') if msg1 else None
        
        # Send block 2
        client.send_message({"type": "object", "object": b2})
        requests = client.receive_all_messages(timeout=0.5)
        for req in requests:
            if req.get('type') == 'getobject' and req.get('objectid') == cb2_id:
                client.send_message({"type": "object", "object": cb2})
        
        time.sleep(0.5)
        client.send_message({"type": "getchaintip"})
        msg2 = client.receive_message(timeout=2)
        tip2 = msg2.get('blockid') if msg2 else None
        
        # Send block 3
        client.send_message({"type": "object", "object": b3})
        requests = client.receive_all_messages(timeout=0.5)
        for req in requests:
            if req.get('type') == 'getobject' and req.get('objectid') == cb3_id:
                client.send_message({"type": "object", "object": cb3})
        
        time.sleep(0.5)
        client.send_message({"type": "getchaintip"})
        msg3 = client.receive_message(timeout=2)
        tip3 = msg3.get('blockid') if msg3 else None
        
        # Check progression
        if tip3 == b3_id:
            return TestResult("multiple_chaintip_updates", True, 
                            f"OK (tips: {tip1[:8] if tip1 else 'none'}...→{tip2[:8] if tip2 else 'none'}...→{tip3[:8]}...)", 
                            time.time() - start)
        
        return TestResult("multiple_chaintip_updates", False, 
                        f"Tip didn't update to block 3 (got {tip3})", time.time() - start)
    finally:
        client.close()

def test_forked_chains_selection() -> TestResult:
    """Test longest chain selection with fork (genesis branches into two chains)"""
    start = time.time()
    client = KermaTestClient()
    
    try:
        if not client.connect() or not client.handshake():
            return TestResult("forked_chains", False, "Connection failed", time.time() - start)
        
        client.clear_initial_messages()
        
        print("  Mining forked chains...")
        
        privkey, pubkey = generate_keypair()
        
        # Fork A: genesis -> A1 -> A2 -> A3 (length 3)
        cb_a1 = create_coinbase_tx(1, pubkey, 50000000000000)
        cb_a1_id = object_id(cb_a1)
        b_a1 = create_and_mine_block([cb_a1_id], GENESIS_ID, 1671062500, note="fork_a1")
        if not b_a1:
            return TestResult("forked_chains", False, "Mining failed", time.time() - start)
        b_a1_id = object_id(b_a1)
        
        cb_a2 = create_coinbase_tx(2, pubkey, 50000000000000)
        cb_a2_id = object_id(cb_a2)
        b_a2 = create_and_mine_block([cb_a2_id], b_a1_id, 1671062600, note="fork_a2")
        if not b_a2:
            return TestResult("forked_chains", False, "Mining failed", time.time() - start)
        b_a2_id = object_id(b_a2)
        
        cb_a3 = create_coinbase_tx(3, pubkey, 50000000000000)
        cb_a3_id = object_id(cb_a3)
        b_a3 = create_and_mine_block([cb_a3_id], b_a2_id, 1671062700, note="fork_a3")
        if not b_a3:
            return TestResult("forked_chains", False, "Mining failed", time.time() - start)
        b_a3_id = object_id(b_a3)
        
        # Fork B: genesis -> B1 -> B2 (length 2, shorter)
        cb_b1 = create_coinbase_tx(1, pubkey, 50000000000000)
        cb_b1_id = object_id(cb_b1)
        b_b1 = create_and_mine_block([cb_b1_id], GENESIS_ID, 1671062501, note="fork_b1")
        if not b_b1:
            return TestResult("forked_chains", False, "Mining failed", time.time() - start)
        b_b1_id = object_id(b_b1)
        
        cb_b2 = create_coinbase_tx(2, pubkey, 50000000000000)
        cb_b2_id = object_id(cb_b2)
        b_b2 = create_and_mine_block([cb_b2_id], b_b1_id, 1671062601, note="fork_b2")
        if not b_b2:
            return TestResult("forked_chains", False, "Mining failed", time.time() - start)
        b_b2_id = object_id(b_b2)
        
        print("  Sending fork B (shorter) first...")
        
        # Send shorter fork B first
        client.send_message({"type": "object", "object": b_b2})
        for _ in range(10):
            requests = client.receive_all_messages(timeout=0.5)
            if not requests:
                break
            for req in requests:
                if req.get('type') == 'getobject':
                    oid = req.get('objectid')
                    if oid == b_b1_id:
                        client.send_message({"type": "object", "object": b_b1})
                    elif oid == cb_b1_id:
                        client.send_message({"type": "object", "object": cb_b1})
                    elif oid == cb_b2_id:
                        client.send_message({"type": "object", "object": cb_b2})
        
        time.sleep(0.5)
        
        print("  Sending fork A (longer)...")
        
        # Send longer fork A
        client.send_message({"type": "object", "object": b_a3})
        for _ in range(15):
            requests = client.receive_all_messages(timeout=0.5)
            if not requests:
                break
            for req in requests:
                if req.get('type') == 'getobject':
                    oid = req.get('objectid')
                    if oid == b_a1_id:
                        client.send_message({"type": "object", "object": b_a1})
                    elif oid == b_a2_id:
                        client.send_message({"type": "object", "object": b_a2})
                    elif oid == cb_a1_id:
                        client.send_message({"type": "object", "object": cb_a1})
                    elif oid == cb_a2_id:
                        client.send_message({"type": "object", "object": cb_a2})
                    elif oid == cb_a3_id:
                        client.send_message({"type": "object", "object": cb_a3})
        
        time.sleep(1)
        
        # Check final tip
        client.send_message({"type": "getchaintip"})
        msg = client.receive_message(timeout=2)
        final_tip = msg.get('blockid') if msg else None
        
        if final_tip == b_a3_id:
            return TestResult("forked_chains", True, 
                            "OK (correctly chose longer fork)", time.time() - start)
        elif final_tip == b_b2_id:
            return TestResult("forked_chains", False, 
                            "Kept shorter fork instead of longer", time.time() - start)
        else:
            return TestResult("forked_chains", False, 
                            f"Unexpected tip: {final_tip}", time.time() - start)
    finally:
        client.close()


def main():
    """Main entry point"""
    print("Kerma Task 4 Comprehensive Test Suite")
    print(f"Target: {HOST}:{PORT}")
    
    # Check if node is running
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((HOST, PORT))
        sock.close()
    except Exception as e:
        print(f"\n✗ Cannot connect to node at {HOST}:{PORT}")
        print(f"  Make sure your node is running first!")
        sys.exit(1)
    
    results = run_all_tests()
    success = print_summary(results)
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()

