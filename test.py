#!/usr/bin/env python3
"""
Kerma Mempool Test Suite
Tests the mempool functionality of a Kerma node using netcat (nc)
Uses a persistent connection in a background thread for better reliability.
"""

import json
import subprocess
import time
import hashlib
from typing import List, Dict, Any, Optional, Tuple
import sys
import threading
import queue
from nacl.signing import SigningKey

# Configuration
#NODE_HOST = 'localhost'
NODE_HOST = '128.130.122.73'
NODE_PORT = 18018
TIMEOUT = 10  # seconds for network operations
RESPONSE_WAIT_TIME = 2.0  # seconds to wait for responses
BLOCK_PROCESSING_WAIT = 3.0  # seconds to wait after sending blocks
GENESIS_ID = "00002fa163c7dab0991544424b9fd302bb1782b185e5a3bbdf12afb758e57dee"
TARGET = "0000abc000000000000000000000000000000000000000000000000000000000"


# ============================================================================
# CRYPTOGRAPHIC UTILITIES
# ============================================================================

def blake2s_hash(data: str) -> str:
    """Calculate blake2s hash of canonical JSON"""
    return hashlib.blake2s(data.encode()).hexdigest()


def canonicalize(obj: Dict) -> str:
    """Convert object to canonical JSON format"""
    return json.dumps(obj, separators=(',', ':'), sort_keys=True)


def object_id(obj: Dict) -> str:
    """Calculate objectid (blake2s hash of canonical JSON)"""
    canonical = canonicalize(obj)
    h = hashlib.blake2s(canonical.encode('utf-8'), digest_size=32)
    return h.hexdigest()


def generate_keypair() -> Tuple[bytes, str]:
    """Generate ed25519 keypair"""
    signing_key = SigningKey.generate()
    return signing_key.encode(), signing_key.verify_key.encode().hex()


# ============================================================================
# MINING UTILITIES
# ============================================================================

def mine_block(block_template: Dict, max_iterations: int = 10000000) -> Optional[Dict]:
    """Mine a block by finding a valid nonce"""
    target = int(TARGET, 16)
    
    for i in range(max_iterations):
        nonce = format(i, '064x')
        block_template['nonce'] = nonce
        
        block_id = object_id(block_template)
        block_id_int = int(block_id, 16)
        
        if block_id_int < target:
            print(f"    ⛏️  Mined! nonce={nonce[:16]}... ({i+1} iterations)")
            return block_template
        
        if i > 0 and i % 100000 == 0:
            print(f"    ⛏️  Mining... {i} nonces...")
    
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


# ============================================================================
# TRANSACTION UTILITIES
# ============================================================================

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
    tx_copy = json.loads(json.dumps(tx))
    for inp in tx_copy.get('inputs', []):
        inp['sig'] = None
    
    signing_text = canonicalize(tx_copy).encode('utf-8')
    
    signed_tx = json.loads(json.dumps(tx))
    for i, privkey in enumerate(private_keys):
        signing_key = SigningKey(privkey)
        signature = signing_key.sign(signing_text)
        signed_tx['inputs'][i]['sig'] = signature.signature.hex()
    
    return signed_tx


def create_spending_tx(coinbase_txid: str, privkey: bytes, pubkey: str, 
                       value: int = 40000000000000) -> Dict:
    """Helper to create and sign a transaction spending from a coinbase"""
    tx = create_transaction(
        inputs=[{
            "outpoint": {"txid": coinbase_txid, "index": 0},
            "sig": None
        }],
        outputs=[{"pubkey": pubkey, "value": value}]
    )
    return sign_transaction(tx, [privkey])


# ============================================================================
# PERSISTENT CONNECTION MANAGER
# ============================================================================

class NodeConnection:
    """Manages persistent connection to Kerma node in background thread"""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.process = None
        self.thread = None
        self.running = False
        
        # Queues for communication between main thread and connection thread
        self.send_queue = queue.Queue()
        self.response_queue = queue.Queue()
        
        # Lock for thread safety
        self.lock = threading.Lock()
    
    def start(self):
        """Start the connection thread"""
        self.running = True
        self.thread = threading.Thread(target=self._connection_loop, daemon=True)
        self.thread.start()
        
        # Wait for connection to be established
        max_wait = 2.0
        waited = 0
        while waited < max_wait and (not self.process or self.process.poll() is not None):
            time.sleep(0.1)
            waited += 0.1
        
        if not self.process or self.process.poll() is not None:
            raise Exception("Failed to establish connection to node")
        
        # Give reader thread time to start
        time.sleep(0.3)
    
    def stop(self):
        """Stop the connection thread"""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=1)
            except:
                try:
                    self.process.kill()
                except:
                    pass
    
    def _connection_loop(self):
        """Main loop running in background thread"""
        try:
            # Start netcat process
            self.process = subprocess.Popen(
                ['nc', self.host, str(self.port)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1  # Line buffered
            )
            
            # Check if process started successfully
            time.sleep(0.1)
            if self.process.poll() is not None:
                stderr = self.process.stderr.read()
                raise Exception(f"Failed to connect to {self.host}:{self.port}. Error: {stderr}")
            
            # Start reader thread for responses
            reader_thread = threading.Thread(target=self._read_responses, daemon=True)
            reader_thread.start()
            
            # Process send queue
            while self.running:
                try:
                    # Get message to send (with timeout so we can check self.running)
                    msg = self.send_queue.get(timeout=0.1)
                    
                    if msg is None:  # Poison pill to stop
                        break
                    
                    # Send message
                    msg_str = canonicalize(msg) + '\n'
                    self.process.stdin.write(msg_str)
                    self.process.stdin.flush()
                    
                except queue.Empty:
                    continue
                except Exception as e:
                    print(f"Error sending message: {e}")
                    break
        
        except Exception as e:
            print(f"Connection thread error: {e}")
        finally:
            self.running = False
    
    def _read_responses(self):
        """Read responses from node (runs in separate thread)"""
        try:
            while self.running and self.process:
                line = self.process.stdout.readline()
                if not line:
                    break
                
                line = line.strip()
                if line:
                    try:
                        response = json.loads(line)
                        self.response_queue.put(response)
                    except json.JSONDecodeError as e:
                        print(f"Failed to parse response: {line}")
        except Exception as e:
            if self.running:  # Only print if we're not shutting down
                print(f"Error reading responses: {e}")
    
    def send(self, msg: Dict):
        """Send a message to the node"""
        self.send_queue.put(msg)
    
    def send_multiple(self, messages: List[Dict]):
        """Send multiple messages to the node"""
        for msg in messages:
            self.send_queue.put(msg)
    
    def get_responses(self, timeout: float = RESPONSE_WAIT_TIME, 
                     expected_count: Optional[int] = None,
                     debug: bool = False) -> List[Dict]:
        """
        Get all accumulated responses from the node
        
        This drains the response queue and returns everything that has been received
        since the last call to get_responses().
        
        Args:
            timeout: Maximum time to wait for NEW responses after the initial batch
            expected_count: If set, wait until we get this many responses total or timeout
            debug: If True, print debug information
        """
        responses = []
        
        # First, drain any responses that are already in the queue
        while True:
            try:
                response = self.response_queue.get_nowait()
                responses.append(response)
                if debug:
                    print(f"  [DEBUG] Got queued: {response.get('type', 'unknown')}")
            except queue.Empty:
                break
        
        if debug:
            print(f"  [DEBUG] Drained {len(responses)} queued responses")
        
        # If we already have enough responses, return
        if expected_count and len(responses) >= expected_count:
            if debug:
                print(f"  [DEBUG] Already have {len(responses)} >= {expected_count} expected")
            return responses
        
        # Now wait for additional responses up to timeout
        deadline = time.time() + timeout
        last_response_time = time.time()
        no_response_timeout = 0.5  # If no response for this long, likely done
        
        while time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            
            try:
                response = self.response_queue.get(timeout=0.05)
                responses.append(response)
                last_response_time = time.time()
                
                if debug:
                    print(f"  [DEBUG] Received new: {response.get('type', 'unknown')}")
                
                # If we got the expected count, return immediately
                if expected_count and len(responses) >= expected_count:
                    if debug:
                        print(f"  [DEBUG] Got expected {expected_count} responses")
                    break
                    
            except queue.Empty:
                # If we have responses and haven't seen one in a while, we're probably done
                if responses and (time.time() - last_response_time) > no_response_timeout:
                    if debug:
                        print(f"  [DEBUG] No response for {no_response_timeout}s, returning {len(responses)} responses")
                    break
                continue
        
        if debug:
            print(f"  [DEBUG] Returning {len(responses)} total responses")
        
        return responses
    
    def clear_responses(self):
        """Clear any pending responses"""
        while not self.response_queue.empty():
            try:
                self.response_queue.get_nowait()
            except queue.Empty:
                break


# ============================================================================
# NETWORK UTILITIES (explicit connection passing)
# ============================================================================

def create_connection() -> NodeConnection:
    """Create a new connection to the node"""
    conn = NodeConnection(NODE_HOST, NODE_PORT)
    conn.start()
    conn.send({"type": "hello", "version": "0.10.0", "agent": "TestAgent"})
    return conn


def send_message(conn: NodeConnection, msg: Dict, wait_for_response: bool = True, debug: bool = False) -> List[Dict]:
    """Send a single message and optionally wait for response"""
    conn.clear_responses()
    conn.send(msg)
    
    if wait_for_response:
        time.sleep(0.1)  # Give message time to reach node and be processed
        return conn.get_responses(debug=debug)
    return []


def send_messages(conn: NodeConnection, messages: List[Dict], wait_time: float = RESPONSE_WAIT_TIME, debug: bool = False) -> List[Dict]:
    """Send multiple messages and collect responses"""
    print(f"  [send_messages] Sending {messages}")
    conn.send_multiple(messages)
    time.sleep(0.2)  # Give messages time to reach node
    return conn.get_responses(timeout=wait_time, debug=debug)


def get_mempool_txids(conn: NodeConnection) -> List[str]:
    """Helper function to get current mempool transaction IDs"""
    responses = send_messages(conn, [
        #{"type": "hello", "version": "0.10.0", "agent": "TestAgent"},
        {"type": "getmempool"}
    ])
    
    for resp in responses:
        if resp.get('type') == 'mempool':
            return resp.get('txids', [])
    
    return []



def send_objects_and_wait(conn: NodeConnection, objects: List[Dict], wait_time: float = BLOCK_PROCESSING_WAIT, debug: bool = False):
    """Helper to send objects to node and wait for processing"""
    messages = [] # [{"type": "hello", "version": "0.10.0", "agent": "TestAgent"}]
    messages.extend([{"type": "object", "object": obj} for obj in objects])
    
    if debug:
        print(f"  [send_objects_and_wait] Sending {len(messages)} messages ({len(objects)} objects)")
    
    send_messages(conn, messages, wait_time=wait_time, debug=debug)


# ============================================================================
# CHAIN BUILDING UTILITIES
# ============================================================================
def clear_mempool_by_including_txs(conn: NodeConnection, pubkey: str):
    """
    Clear mempool by mining a block that INCLUDES all mempool transactions
    """
    print("  Clearing mempool by including transactions in block...")
    
    # Get current mempool
    mempool_txids = get_mempool_txids(conn)
    
    if not mempool_txids:
        print("  Mempool already empty")
        return
    
    print(f"  Mempool has {len(mempool_txids)} transactions")
    
    # Get current tip
    current_tip, tip_height, tip_created = get_chaintip(conn)
    
    if not current_tip or not isinstance(tip_created, int):
        print("  Could not get chain tip")
        return
    
    # Create block that includes ALL mempool transactions
    block_timestamp = tip_created + 60
    height = (tip_height + 1) if isinstance(tip_height, int) else 1
    
    # Create coinbase
    coinbase = create_coinbase_tx(height=height, pubkey=pubkey)
    coinbase_id = object_id(coinbase)
    
    # Mine block with coinbase + ALL mempool transactions
    print(f"  Mining block with coinbase + {len(mempool_txids)} mempool transactions...")
    all_txids = [coinbase_id] + mempool_txids
    
    block = create_and_mine_block(
        txids=all_txids,
        previd=current_tip,
        created=block_timestamp,
        miner="cleaner",
        note="Clear mempool"
    )
    
    if not block:
        print("  ⚠️  Failed to mine clearing block")
        return
    
    block_id = object_id(block)
    print(f"  Mined block: {block_id}")
    
    # Send coinbase and block
    print("  Sending block with mempool transactions...")
    send_messages(
        conn,
        [{"type": "object", "object": coinbase},
         {"type": "object", "object": block}],
        wait_time=BLOCK_PROCESSING_WAIT
    )
    
    time.sleep(1.0)
    
    # Verify mempool is cleared
    new_mempool = get_mempool_txids(conn)
    print(f"  Mempool now has {len(new_mempool)} transactions")
    print(f"  Removed {len(mempool_txids) - len(new_mempool)} transactions")
    
    return len(new_mempool) == 0

def build_chain_with_coinbase(privkey: bytes, pubkey: str, chain_length: int = 2, 
                              base_timestamp: Optional[int] = None,
                              miner: str = "test") -> Tuple[List[Dict], str, str]:
    """
    Build a chain with a coinbase transaction that can be spent.
    
    Returns:
        (objects_to_send, coinbase_txid, tip_blockid)
        objects_to_send: List of all objects (coinbase tx and blocks)
        coinbase_txid: ID of the coinbase transaction
        tip_blockid: ID of the chain tip block
    """
    if base_timestamp is None:
        # Use current time minus a bit to ensure it's in the past
        base_timestamp = int(time.time()) - 6000
    
    # Create coinbase transaction
    coinbase_tx = create_coinbase_tx(height=1, pubkey=pubkey)
    coinbase_txid = object_id(coinbase_tx)
    print(f"  Coinbase txid: {coinbase_txid}")
    
    # Mine first block with coinbase
    # Use base_timestamp for first block
    block1 = create_and_mine_block(
        txids=[coinbase_txid],
        previd=GENESIS_ID,
        created=base_timestamp,
        miner=miner,
        note=f"Block 1 - {miner}"
    )
    
    if not block1:
        print("  ⚠️  Failed to mine block 1")
        return [], "", ""
    
    block1_id = object_id(block1)
    print(f"  Block 1 id: {block1_id}")
    
    objects = [coinbase_tx, block1]
    prev_id = block1_id
    
    # Mine additional empty blocks
    # Each subsequent block is 60 seconds after the previous
    for i in range(2, chain_length + 1):
        block_timestamp = base_timestamp + (i - 1) * 60

        coinbase_tx_h = create_coinbase_tx(height=i, pubkey=pubkey)
        coinbase_tx_h_id = object_id(coinbase_tx_h)

        block = create_and_mine_block(
            txids=[coinbase_tx_h_id],   # ✅ include coinbase
            previd=prev_id,
            created=block_timestamp,
            miner=miner,
            note=f"Block {i} - {miner}"
        )

        if not block:
            return [], "", ""

        block_id = object_id(block)
        print(f"  Coinbase(h={i}) txid: {coinbase_tx_h_id}")
        print(f"  Block {i} id: {block_id}")

        objects.append(coinbase_tx_h)   # ✅ send tx object too
        objects.append(block)

        prev_id = block_id
    
    return objects, coinbase_txid, prev_id


def get_chaintip_blockid(conn: NodeConnection) -> Optional[str]:
    conn.clear_responses()
    #conn.send({"type": "hello", "version": "0.10.0", "agent": "TestAgent"})
    conn.send({"type": "getchaintip"})
    time.sleep(0.3)
    resps = conn.get_responses(timeout=1.0)
    for r in resps:
        if r.get("type") == "chaintip":
            return r.get("blockid")
    return None

def build_chain_appending_to_tip(
    conn: NodeConnection,
    pubkey: str,
    chain_length: int = 2,
    miner: str = "test",
    base_timestamp: Optional[int] = None,
) -> Tuple[List[Dict], str, str]:

    tip, tip_height, tip_created = get_chaintip(conn)
    if not tip:
        print("  ⚠️  Could not fetch chaintip from node")
        return [], "", ""

    # CRITICAL FIX: make sure our new blocks are AFTER the tip's timestamp
    if tip_created is None:
        # fallback if tip block couldn't be fetched
        tip_created = int(time.time()) - 1

    if base_timestamp is None:
        # first appended block should be strictly after tip
        base_timestamp = tip_created + 1
    else:
        # enforce it even if user passed something older
        base_timestamp = max(base_timestamp, tip_created + 1)

    objects: List[Dict] = []
    prev_id = tip
    first_coinbase_txid = ""

    # If we know height, align; otherwise just use 1..N (many nodes don't validate this field)
    height_base = tip_height if isinstance(tip_height, int) else 0

    for i in range(1, chain_length + 1):
        cb_height = (height_base + i) if height_base > 0 else i
        cb = create_coinbase_tx(height=cb_height, pubkey=pubkey)
        cb_id = object_id(cb)
        if i == 1:
            first_coinbase_txid = cb_id

        created = base_timestamp + (i - 1) * 60  # keep increasing
        block = create_and_mine_block(
            txids=[cb_id],
            previd=prev_id,
            created=created,
            miner=miner,
            note=f"Append block {i} - {miner}"
        )
        if not block:
            return [], "", ""

        block_id = object_id(block)

        objects.append(cb)     # tx first
        objects.append(block)  # then block

        prev_id = block_id

        print(f"  Appended coinbase(h={cb_height}) txid: {cb_id}")
        print(f"  Appended block {i} id: {block_id} (created={created})")

    return objects, first_coinbase_txid, prev_id


def get_tip_block(conn: NodeConnection, tip: str) -> Optional[Dict]:
    resps = send_messages(conn, [{"type": "getobject", "objectid": tip}], wait_time=1.0)
    for r in resps:
        if r.get("type") == "object" and r.get("object", {}).get("type") == "block":
            return r["object"]
    return None


def find_height_by_walking_back(conn: NodeConnection, start_blockid: str, max_steps: int = 300) -> Optional[int]:
    """
    Walk back via previd until we find ANY tx object that contains a 'height' field.
    This is more robust than assuming coinbase is present/first.
    """
    cur = start_blockid
    for _ in range(max_steps):
        blk = get_tip_block(conn, cur)
        if not blk:
            return None

        for txid in blk.get("txids", []):
            tx_resps = send_messages(conn, [{"type": "getobject", "objectid": txid}], wait_time=1.0)
            for r in tx_resps:
                if r.get("type") != "object":
                    continue
                tx = r.get("object", {})
                if tx.get("type") == "transaction" and "height" in tx:
                    return tx["height"]

        print(f"  Walking back from block {cur}...")
        cur = blk.get("previd")
        if not cur:
            return None

    return None


def get_chaintip(conn: NodeConnection) -> Tuple[Optional[str], Optional[int], Optional[int]]:
    """
    Returns (tip_blockid, height_or_None, tip_created_or_None)
    """
    resps = send_messages(conn, [{"type": "getchaintip"}], wait_time=1.0)

    tip = None
    for r in resps:
        if r.get("type") == "chaintip":
            tip = r.get("blockid")
            break
    if not tip:
        return None, None, None

    tip_block = get_tip_block(conn, tip)
    tip_created = tip_block.get("created") if tip_block else None

    # Best effort height: walk back until we find any tx with a 'height' field
    h = find_height_by_walking_back(conn, tip)

    print(f"  Chain tip: {tip} (height={h}, created={tip_created})")
    return tip, h, tip_created



# ============================================================================
# TEST SUITE
# ============================================================================

class KermaTestSuite:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        
    def assert_true(self, condition: bool, test_name: str, message: str = ""):
        """Assert that condition is true"""
        if condition:
            print(f"✓ {test_name}")
            self.passed += 1
        else:
            print(f"✗ {test_name}: {message}")
            self.failed += 1
    
    def assert_in(self, item: Any, container: Any, test_name: str):
        """Assert that item is in container"""
        self.assert_true(item in container, test_name, f"{item} not in {container}")
    
    def assert_not_in(self, item: Any, container: Any, test_name: str):
        """Assert that item is not in container"""
        self.assert_true(item not in container, test_name, f"{item} should not be in container")
    
    def print_summary(self):
        """Print test summary"""
        total = self.passed + self.failed
        print(f"\n{'='*50}")
        print(f"Test Summary: {self.passed}/{total} passed")
        if self.failed > 0:
            print(f"Failed: {self.failed}")
        print(f"{'='*50}")
        return self.failed == 0



def build_fork_from_base(
    base_blockid: str,
    base_height: int,
    base_created: int,
    pubkey: str,
    length: int,
    miner: str,
    created_start: int,
) -> Tuple[List[Dict], str, str]:
    """
    Build a fork of `length` blocks starting from base_blockid.
    Heights are base_height+1 ... base_height+length.
    Returns (objects_to_send, first_coinbase_txid, fork_tip_blockid)
    """
    objects: List[Dict] = []
    prev_id = base_blockid
    first_coinbase_txid = ""

    for i in range(1, length + 1):
        h = base_height + i
        cb = create_coinbase_tx(height=h, pubkey=pubkey)
        cb_id = object_id(cb)
        if i == 1:
            first_coinbase_txid = cb_id

        created = created_start + (i - 1) * 60
        block = create_and_mine_block(
            txids=[cb_id],
            previd=prev_id,
            created=created,
            miner=miner,
            note=f"Fork {miner} block {i}"
        )
        if not block:
            return [], "", ""

        block_id = object_id(block)

        # tx first, then the block that includes it
        objects.append(cb)
        objects.append(block)

        print(f"  Fork {miner}: coinbase(h={h}) txid={cb_id}")
        print(f"  Fork {miner}: block {i} id={block_id} (created={created})")

        prev_id = block_id

    return objects, first_coinbase_txid, prev_id



# ============================================================================
# TEST CASES
# ============================================================================

def test_initial_mempool(conn: NodeConnection, suite: KermaTestSuite):
    """Test 2: Initial mempool should be empty"""
    print("\n--- Test 2: Initial Mempool ---")
    
    txids = get_mempool_txids(conn)
    suite.assert_true(len(txids) == 0, "Initial mempool: Mempool is empty", 
                     f"Expected empty, got {len(txids)} transactions")


def test_chain_tip(conn: NodeConnection, suite: KermaTestSuite):
    """Test 3: Get chain tip"""
    print("\n--- Test 3: Chain Tip ---")
    
    responses = send_messages(conn, [
        #{"type": "hello", "version": "0.10.0", "agent": "TestAgent"},
        {"type": "getchaintip"}
    ])
    
    chaintip_resp = None
    for resp in responses:
        if resp.get('type') == 'chaintip':
            chaintip_resp = resp
            break
    
    suite.assert_true(chaintip_resp is not None, "Chain tip: Got chaintip response")
    
    if chaintip_resp:
        blockid = chaintip_resp.get('blockid')
        suite.assert_true(blockid is not None, "Chain tip: Has blockid")
        print(f"  Current chain tip: {blockid}")


def test_getpeers(conn: NodeConnection, suite: KermaTestSuite):
    """Test 4: Get peers"""
    print("\n--- Test 4: Get Peers ---")
    
    responses = send_messages(conn, [
        #{"type": "hello", "version": "0.10.0", "agent": "TestAgent"},
        {"type": "getpeers"}
    ])
    
    peers_resp = None
    for resp in responses:
        if resp.get('type') == 'peers':
            peers_resp = resp
            break
    
    suite.assert_true(peers_resp is not None, "Get peers: Got peers response")
    
    if peers_resp:
        peers = peers_resp.get('peers', [])
        suite.assert_true(isinstance(peers, list), "Get peers: Peers is a list")
        print(f"  Known peers: {len(peers)}")


def test_error_handling(conn: NodeConnection, suite: KermaTestSuite):
    """Test 5: Invalid format handling"""
    print("\n--- Test 5: Error Handling ---")
    
    # Send hello first, then invalid message
    #conn.send({"type": "hello", "version": "0.10.0", "agent": "TestAgent"})
    time.sleep(0.2)
    
    # Send invalid message (using raw JSON to bypass canonicalize)
    try:
        conn.process.stdin.write('{"invalid": "message"}\n')
        conn.process.stdin.flush()
    except:
        pass
    
    time.sleep(0.3)
    responses = conn.get_responses(timeout=1)
    
    error_received = any(r.get('type') == 'error' for r in responses)
    suite.assert_true(error_received, "Error handling: Received error for invalid message")


def test_coinbase_rejection(conn: NodeConnection, suite: KermaTestSuite):
    """Test 6: Coinbase transactions should not be in mempool"""
    print("\n--- Test 6: Coinbase Transaction Rejection ---")
    
    _, pubkey = generate_keypair()
    coinbase_tx = create_coinbase_tx(height=1, pubkey=pubkey)
    coinbase_id = object_id(coinbase_tx)
    
    send_objects_and_wait(conn, [coinbase_tx])
    time.sleep(0.5)
    
    txids = get_mempool_txids(conn)
    suite.assert_not_in(coinbase_id, txids, "Coinbase rejection: Coinbase not in mempool")


def test_valid_transaction_addition(conn: NodeConnection, suite: KermaTestSuite):
    """Test 7: Add valid transaction to mempool"""
    print("\n--- Test 7: Valid Transaction Addition ---")

    privkey, pubkey = generate_keypair()
    print(f"  Test pubkey: {pubkey}")

    print("  Fetching current tip and building extension...")
    objects, coinbase_txid, new_tip = build_chain_appending_to_tip(
        conn, pubkey, chain_length=2, miner="test"
    )
    if not objects:
        suite.assert_true(False, "Valid transaction: Could not build chain extension")
        return

    # 1) Send ONLY the chain objects once
    print("\n  Sending chain extension (coinbases + blocks)...")
    responses_chain = send_messages(
        conn,
        #[{"type": "hello", "version": "0.10.0", "agent": "TestAgent"}] +
        [{"type": "object", "object": obj} for obj in objects],
        wait_time=BLOCK_PROCESSING_WAIT,
        debug=False
    )

    print(responses_chain)
    chain_errors = [r for r in responses_chain if r.get("type") == "error"]
    if chain_errors:
        print(f"  ⚠️  Chain send produced {len(chain_errors)} error(s):")
        for err in chain_errors:
            print(f"      Error: {err.get('error', 'unknown')}  Name: {err.get('name', '')}")

        suite.assert_true(False, "Valid transaction: Chain objects accepted",
                         "Node returned errors while sending chain extension")
        return

    # Give node a moment to connect UTXO set
    time.sleep(0.8)

    # 2) Create + send ONLY the spending tx
    spending_tx = create_spending_tx(coinbase_txid, privkey, pubkey)
    spending_txid = object_id(spending_tx)

    print(f"\n  Sending spending tx: {spending_txid}")
    responses_tx = send_messages(
        conn,
        [#{"type": "hello", "version": "0.10.0", "agent": "TestAgent"},
         {"type": "object", "object": spending_tx}],
        wait_time=RESPONSE_WAIT_TIME,
        debug=False
    )

    tx_errors = [r for r in responses_tx if r.get("type") == "error"]
    if tx_errors:
        print(f"  ⚠️  Spending tx produced {len(tx_errors)} error(s):")
        for err in tx_errors:
            print(f"      Error: {err.get('error', 'unknown')}  Name: {err.get('name', '')}")

    # 3) Poll mempool a few times (nodes often update async)
    print("\n  Querying mempool (with retries)...")
    found = False
    last_txids = []
    for attempt in range(6):
        txids = get_mempool_txids(conn)
        last_txids = txids
        if spending_txid in txids:
            found = True
            break
        time.sleep(0.4)

    print(f"  Mempool contains {len(last_txids)} transaction(s)")
    for txid in last_txids[:10]:
        match = "✓ MATCH!" if txid == spending_txid else ""
        print(f"    - {txid} {match}")
    if len(last_txids) > 10:
        print("    ...")

    suite.assert_true(found, "Valid transaction: Transaction in mempool",
                      f"Expected {spending_txid} not found. tx_errors={len(tx_errors)}")


def test_double_spend_rejection(conn: NodeConnection, suite: KermaTestSuite):
    """Test 8: Reject double-spending transaction in mempool"""
    print("\n--- Test 8: Double Spend Rejection ---")
    
    privkey, pubkey = generate_keypair()
    
    print("  Setting up test chain...")
    objects, coinbase_txid, _ = build_chain_with_coinbase(privkey, pubkey, chain_length=2)
    
    if not objects:
        print("  ⚠️  Failed to build chain, skipping test")
        return
    
    # Create two transactions spending the same output
    tx1 = create_spending_tx(coinbase_txid, privkey, pubkey, value=30000000000000)
    tx1_id = object_id(tx1)
    
    tx2 = create_spending_tx(coinbase_txid, privkey, pubkey, value=35000000000000)
    tx2_id = object_id(tx2)
    
    print(f"  Transaction 1 id: {tx1_id}")
    print(f"  Transaction 2 id: {tx2_id}")
    
    # Send chain and both transactions
    send_objects_and_wait(conn, objects + [tx1, tx2])
    time.sleep(0.5)
    
    # Check mempool - only one should be present
    txids = get_mempool_txids(conn)
    in_mempool = [tx1_id in txids, tx2_id in txids]
    suite.assert_true(
        sum(in_mempool) <= 1, 
        "Double spend: Only one transaction in mempool",
        f"Both transactions in mempool: tx1={tx1_id in txids}, tx2={tx2_id in txids}"
    )


def test_mempool_reorg(conn: NodeConnection, suite: KermaTestSuite):
    """Test 9: Test mempool update after chain reorg"""
    print("\n--- Test 9: Mempool Reorg ---")

    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()

    # 0) Snapshot the current base tip (the common ancestor for both forks)
    base_tip, base_h, base_created = get_chaintip(conn)
    suite.assert_true(base_tip is not None, "Reorg: Got base tip")
    suite.assert_true(isinstance(base_h, int), "Reorg: Got base height")
    suite.assert_true(isinstance(base_created, int), "Reorg: Got base created")

    if not base_tip or not isinstance(base_h, int) or not isinstance(base_created, int):
        return

    print(f"  Base: {base_tip} (h={base_h}, created={base_created})")

    # 1) Build & send fork A (shorter)
    # created MUST be > base_created
    forkA_created_start = base_created + 1
    forkA_objs, forkA_cb_txid, forkA_tip = build_fork_from_base(
        base_blockid=base_tip,
        base_height=base_h,
        base_created=base_created,
        pubkey=pub_a,
        length=2,
        miner="A",
        created_start=forkA_created_start,
    )
    if not forkA_objs:
        suite.assert_true(False, "Reorg: Built fork A")
        return

    print("\n  Sending fork A...")
    respA = send_messages(conn, [{"type": "object", "object": o} for o in forkA_objs],
                          wait_time=BLOCK_PROCESSING_WAIT)
    errA = [r for r in respA if r.get("type") == "error"]
    suite.assert_true(len(errA) == 0, "Reorg: Fork A accepted",
                      f"errors={errA[:1]}")
    if errA:
        return

    time.sleep(0.8)

    # 2) Add a tx to mempool spending fork A's first coinbase
    spendA = create_spending_tx(forkA_cb_txid, priv_a, pub_a)
    spendA_id = object_id(spendA)

    print(f"\n  Sending mempool tx spending forkA coinbase: {spendA_id}")
    respTx = send_messages(conn, [{"type": "object", "object": spendA}],
                           wait_time=RESPONSE_WAIT_TIME)
    errTx = [r for r in respTx if r.get("type") == "error"]
    suite.assert_true(len(errTx) == 0, "Reorg: Spending tx accepted (no error)",
                      f"errors={errTx[:1]}")

    # Wait until it actually shows up in mempool
    in_before = False
    for _ in range(8):
        mp = get_mempool_txids(conn)
        if spendA_id in mp:
            in_before = True
            break
        time.sleep(0.3)
    suite.assert_true(in_before, "Reorg: Tx is in mempool before reorg")

    # 3) Build & send fork B (longer) FROM THE SAME BASE TIP => should reorg
    # Ensure timestamps are valid and not earlier than base; can overlap A, but must be > base.
    forkB_created_start = base_created + 2  # just to differ slightly
    forkB_objs, _, forkB_tip = build_fork_from_base(
        base_blockid=base_tip,
        base_height=base_h,
        base_created=base_created,
        pubkey=pub_b,
        length=3,          # longer => reorg
        miner="B",
        created_start=forkB_created_start,
    )
    if not forkB_objs:
        suite.assert_true(False, "Reorg: Built fork B")
        return

    print("\n  Sending fork B (longer, should trigger reorg)...")
    respB = send_messages(conn, [{"type": "object", "object": o} for o in forkB_objs],
                          wait_time=BLOCK_PROCESSING_WAIT)
    errB = [r for r in respB if r.get("type") == "error"]
    suite.assert_true(len(errB) == 0, "Reorg: Fork B accepted",
                      f"errors={errB[:1]}")
    if errB:
        return

    time.sleep(1.0)

    # Optional sanity: did tip change?
    new_tip, new_h, _ = get_chaintip(conn)
    print(f"  After B: tip={new_tip} h={new_h}")

    # 4) Mempool should drop the tx because its input UTXO got orphaned
    gone_after = False
    for _ in range(10):
        mp2 = get_mempool_txids(conn)
        if spendA_id not in mp2:
            gone_after = True
            break
        time.sleep(0.3)

    suite.assert_true(gone_after, "Reorg: Tx removed from mempool after reorg",
                      "Tx still present after fork B became best chain")

def test_transaction_removed_when_mined(conn: NodeConnection, suite: KermaTestSuite):
    """Test: Transaction removed from mempool when included in block"""
    print("\n--- Test: Transaction Removed When Mined ---")
    
    privkey, pubkey = generate_keypair()
    print(f"  Test pubkey: {pubkey}")
    
    # 1. Build chain with spendable coinbase
    print("  Building chain with spendable coinbase...")
    objects, coinbase_txid, tip = build_chain_appending_to_tip(
        conn, pubkey, chain_length=2, miner="test"
    )
    if not objects:
        suite.assert_true(False, "Tx removed when mined: Could not build chain")
        return
    
    # Send chain objects
    print("  Sending chain objects...")
    resp_chain = send_messages(
        conn,
        [{"type": "object", "object": obj} for obj in objects],
        wait_time=BLOCK_PROCESSING_WAIT,
        debug=False
    )
    
    chain_errors = [r for r in resp_chain if r.get("type") == "error"]
    if chain_errors:
        suite.assert_true(False, "Tx removed when mined: Chain accepted",
                         f"Chain errors: {chain_errors[:1]}")
        return
    
    time.sleep(0.8)
    
    # 2. Create and add spending transaction to mempool
    spending_tx = create_spending_tx(coinbase_txid, privkey, pubkey)
    spending_txid = object_id(spending_tx)
    
    print(f"  Sending spending tx to mempool: {spending_txid}")
    resp_tx = send_messages(
        conn,
        [{"type": "object", "object": spending_tx}],
        wait_time=RESPONSE_WAIT_TIME,
        debug=False
    )
    
    tx_errors = [r for r in resp_tx if r.get("type") == "error"]
    if tx_errors:
        print(f"  ⚠️  Tx errors: {tx_errors[:1]}")
    
    # Verify transaction is in mempool
    in_mempool_before = False
    for _ in range(6):
        txids = get_mempool_txids(conn)
        if spending_txid in txids:
            in_mempool_before = True
            break
        time.sleep(0.3)
    
    suite.assert_true(in_mempool_before, "Tx removed when mined: Tx initially in mempool",
                     "Transaction not added to mempool before mining")
    
    if not in_mempool_before:
        return
    
    print(f"  ✓ Transaction in mempool before mining")
    
    # 3. Mine a block containing that transaction
    print("  Mining block containing the transaction...")
    
    # Get current tip to build on
    current_tip, tip_height, tip_created = get_chaintip(conn)
    if not current_tip or not isinstance(tip_created, int):
        suite.assert_true(False, "Tx removed when mined: Could not get current tip")
        return
    
    # Create block with the spending transaction
    block_timestamp = tip_created + 60
    height = (tip_height + 1) if isinstance(tip_height, int) else 1
    
    # Need a coinbase for this block
    new_coinbase = create_coinbase_tx(height=height, pubkey=pubkey)
    new_coinbase_id = object_id(new_coinbase)
    
    # Mine block with both coinbase and spending tx
    block = create_and_mine_block(
        txids=[new_coinbase_id, spending_txid],
        previd=current_tip,
        created=block_timestamp,
        miner="test",
        note="Block with mempool tx"
    )
    
    if not block:
        suite.assert_true(False, "Tx removed when mined: Could not mine block")
        return
    
    block_id = object_id(block)
    print(f"  Mined block: {block_id}")
    
    # Send the new coinbase and block
    print("  Sending block to node...")
    resp_block = send_messages(
        conn,
        [{"type": "object", "object": new_coinbase},
         {"type": "object", "object": block}],
        wait_time=BLOCK_PROCESSING_WAIT,
        debug=False
    )
    
    block_errors = [r for r in resp_block if r.get("type") == "error"]
    if block_errors:
        print(f"  ⚠️  Block errors: {block_errors[:1]}")
    
    time.sleep(1.0)
    
    # 4. Verify transaction is no longer in mempool
    print("  Checking if transaction removed from mempool...")
    removed = False
    for _ in range(8):
        txids = get_mempool_txids(conn)
        if spending_txid not in txids:
            removed = True
            break
        time.sleep(0.3)
    
    suite.assert_true(removed, "Tx removed when mined: Tx removed from mempool after mining",
                     "Transaction still in mempool after being included in block")
    
    if removed:
        print(f"  ✓ Transaction removed from mempool after mining")


def test_transaction_invalidated_by_block(conn: NodeConnection, suite: KermaTestSuite):
    """Test: Transaction removed when its inputs are spent by block"""
    print("\n--- Test: Transaction Invalidated By Block ---")
    
    privkey, pubkey = generate_keypair()
    privkey2, pubkey2 = generate_keypair()
    print(f"  Test pubkey: {pubkey}")
    
    # 1. Build chain with spendable coinbase
    print("  Building chain with spendable coinbase...")
    objects, coinbase_txid, tip = build_chain_appending_to_tip(
        conn, pubkey, chain_length=2, miner="test"
    )
    if not objects:
        suite.assert_true(False, "Tx invalidated by block: Could not build chain")
        return
    
    # Send chain objects
    print("  Sending chain objects...")
    resp_chain = send_messages(
        conn,
        [{"type": "object", "object": obj} for obj in objects],
        wait_time=BLOCK_PROCESSING_WAIT,
        debug=False
    )
    
    chain_errors = [r for r in resp_chain if r.get("type") == "error"]
    if chain_errors:
        suite.assert_true(False, "Tx invalidated by block: Chain accepted",
                         f"Chain errors: {chain_errors[:1]}")
        return
    
    time.sleep(0.8)
    
    # 2. Create two transactions spending the same UTXO
    tx1 = create_spending_tx(coinbase_txid, privkey, pubkey, value=30000000000000)
    tx1_id = object_id(tx1)
    
    tx2 = create_spending_tx(coinbase_txid, privkey, pubkey2, value=35000000000000)
    tx2_id = object_id(tx2)
    
    print(f"  Transaction 1 (for mempool): {tx1_id}")
    print(f"  Transaction 2 (for block): {tx2_id}")
    
    # 3. Add TX1 to mempool
    print("  Adding TX1 to mempool...")
    resp_tx1 = send_messages(
        conn,
        [{"type": "object", "object": tx1}],
        wait_time=RESPONSE_WAIT_TIME,
        debug=False
    )
    
    tx1_errors = [r for r in resp_tx1 if r.get("type") == "error"]
    if tx1_errors:
        print(f"  ⚠️  TX1 errors: {tx1_errors[:1]}")
    
    # Verify TX1 is in mempool
    tx1_in_mempool = False
    for _ in range(6):
        txids = get_mempool_txids(conn)
        if tx1_id in txids:
            tx1_in_mempool = True
            break
        time.sleep(0.3)
    
    suite.assert_true(tx1_in_mempool, "Tx invalidated by block: TX1 initially in mempool",
                     "TX1 not added to mempool")
    
    if not tx1_in_mempool:
        return
    
    print(f"  ✓ TX1 in mempool")
    
    # 4. Mine block containing TX2 (different spend of same UTXO)
    print("  Mining block with TX2 (conflicts with TX1)...")
    
    # Get current tip
    current_tip, tip_height, tip_created = get_chaintip(conn)
    if not current_tip or not isinstance(tip_created, int):
        suite.assert_true(False, "Tx invalidated by block: Could not get current tip")
        return
    
    # Create block with TX2
    block_timestamp = tip_created + 60
    height = (tip_height + 1) if isinstance(tip_height, int) else 1
    
    # Need a coinbase for this block
    new_coinbase = create_coinbase_tx(height=height, pubkey=pubkey)
    new_coinbase_id = object_id(new_coinbase)
    
    # Mine block with coinbase and TX2
    block = create_and_mine_block(
        txids=[new_coinbase_id, tx2_id],
        previd=current_tip,
        created=block_timestamp,
        miner="test",
        note="Block with conflicting tx"
    )
    
    if not block:
        suite.assert_true(False, "Tx invalidated by block: Could not mine block")
        return
    
    block_id = object_id(block)
    print(f"  Mined block: {block_id}")
    
    # Send TX2, new coinbase, and block
    print("  Sending TX2 and block to node...")
    resp_block = send_messages(
        conn,
        [{"type": "object", "object": tx2},
         {"type": "object", "object": new_coinbase},
         {"type": "object", "object": block}],
        wait_time=BLOCK_PROCESSING_WAIT,
        debug=False
    )
    
    block_errors = [r for r in resp_block if r.get("type") == "error"]
    if block_errors:
        print(f"  ⚠️  Block errors: {block_errors[:1]}")
    
    time.sleep(1.0)
    
    # 5. Verify TX1 is removed from mempool (now invalid)
    print("  Checking if TX1 removed from mempool...")
    tx1_removed = False
    for _ in range(8):
        txids = get_mempool_txids(conn)
        if tx1_id not in txids:
            tx1_removed = True
            break
        time.sleep(0.3)
    
    suite.assert_true(tx1_removed, "Tx invalidated by block: TX1 removed after conflict",
                     "TX1 still in mempool after its input was spent by block")
    
    if tx1_removed:
        print(f"  ✓ TX1 removed from mempool (invalidated by block)")


def test_reorg_moves_transaction_to_mempool(conn: NodeConnection, suite: KermaTestSuite):
    """Test: Transaction from orphaned chain moves back to mempool"""
    print("\n--- Test: Reorg Moves Transaction To Mempool ---")
    
    priv_a, pub_a = generate_keypair()
    priv_b, pub_b = generate_keypair()
    
    # 0) FIRST: Create a spendable UTXO in the base chain
    print("  Creating spendable UTXO in base chain...")
    setup_objs, setup_coinbase_txid, setup_tip = build_chain_appending_to_tip(
        conn, pub_a, chain_length=2, miner="setup"
    )
    
    if not setup_objs:
        suite.assert_true(False, "Reorg tx to mempool: Built setup chain")
        return
    
    # Send setup chain
    print("  Sending setup chain...")
    resp_setup = send_messages(
        conn,
        [{"type": "object", "object": o} for o in setup_objs],
        wait_time=BLOCK_PROCESSING_WAIT
    )
    
    err_setup = [r for r in resp_setup if r.get("type") == "error"]
    if err_setup:
        suite.assert_true(False, "Reorg tx to mempool: Setup chain accepted")
        return
    
    time.sleep(1.0)
    
    # Get the new base (this is where both forks will branch from)
    base_tip, base_h, base_created = get_chaintip(conn)
    suite.assert_true(base_tip is not None, "Reorg tx to mempool: Got base tip")
    suite.assert_true(isinstance(base_h, int), "Reorg tx to mempool: Got base height")
    suite.assert_true(isinstance(base_created, int), "Reorg tx to mempool: Got base created")
    
    if not base_tip or not isinstance(base_h, int) or not isinstance(base_created, int):
        return
    
    print(f"  Base (with spendable UTXO): {base_tip} (h={base_h}, created={base_created})")
    print(f"  Spendable coinbase: {setup_coinbase_txid}")
    
    # Create the spending transaction NOW (spends from base chain, valid in both forks)
    spending_tx = create_spending_tx(setup_coinbase_txid, priv_a, pub_a)
    spending_tx_id = object_id(spending_tx)
    print(f"  Created spending tx: {spending_tx_id}")
    
    # 1) Build fork A that INCLUDES the spending transaction
    print("\n  Building fork A (includes spending transaction)...")
    forkA_created_start = base_created + 1
    forkA_objs = []
    
    # Fork A Block 1: includes the spending transaction
    cb_a1 = create_coinbase_tx(height=base_h + 1, pubkey=pub_a)
    cb_a1_id = object_id(cb_a1)
    
    block_a1 = create_and_mine_block(
        txids=[cb_a1_id, spending_tx_id],  # Include spending tx
        previd=base_tip,
        created=forkA_created_start,
        miner="A",
        note="Fork A block 1 with tx"
    )
    if not block_a1:
        suite.assert_true(False, "Reorg tx to mempool: Built fork A block 1")
        return
    
    block_a1_id = object_id(block_a1)
    forkA_objs.extend([spending_tx, cb_a1, block_a1])
    
    print(f"  Fork A block 1: {block_a1_id} (contains tx: {spending_tx_id})")
    
    # Send fork A
    print("\n  Sending fork A (length 1, contains transaction)...")
    respA = send_messages(
        conn,
        [{"type": "object", "object": o} for o in forkA_objs],
        wait_time=BLOCK_PROCESSING_WAIT
    )
    
    errA = [r for r in respA if r.get("type") == "error"]
    suite.assert_true(len(errA) == 0, "Reorg tx to mempool: Fork A accepted",
                     f"errors={errA[:1]}")
    if errA:
        return
    
    time.sleep(1.0)
    
    # Verify transaction is NOT in mempool (it's in a block)
    txids_before = get_mempool_txids(conn)
    tx_in_mempool_before = spending_tx_id in txids_before
    suite.assert_true(not tx_in_mempool_before, 
                     "Reorg tx to mempool: Tx not in mempool when in block",
                     "Transaction should be in block, not mempool")
    
    if tx_in_mempool_before:
        print(f"  ⚠️  Transaction unexpectedly in mempool before reorg")
        return
    
    print(f"  ✓ Transaction in block, not in mempool")
    
    # 2) Build fork B (longer, without the transaction) from same base
    print("\n  Building fork B (longer, no transaction)...")
    forkB_created_start = base_created + 2
    forkB_objs, _, forkB_tip = build_fork_from_base(
        base_blockid=base_tip,
        base_height=base_h,
        base_created=base_created,
        pubkey=pub_b,
        length=2,  # longer than fork A (which is 1 block)
        miner="B",
        created_start=forkB_created_start,
    )
    
    if not forkB_objs:
        suite.assert_true(False, "Reorg tx to mempool: Built fork B")
        return
    
    # Send fork B (should trigger reorg)
    print("\n  Sending fork B (longer, should trigger reorg)...")
    respB = send_messages(
        conn,
        [{"type": "object", "object": o} for o in forkB_objs],
        wait_time=BLOCK_PROCESSING_WAIT
    )
    
    errB = [r for r in respB if r.get("type") == "error"]
    suite.assert_true(len(errB) == 0, "Reorg tx to mempool: Fork B accepted",
                     f"errors={errB[:1]}")
    if errB:
        return
    
    time.sleep(1.5)
    
    # 3) Verify transaction is now IN mempool
    print("\n  Checking if transaction moved to mempool after reorg...")
    tx_in_mempool_after = False
    final_txids = []
    
    for attempt in range(10):
        txids_after = get_mempool_txids(conn)
        final_txids = txids_after
        if spending_tx_id in txids_after:
            tx_in_mempool_after = True
            break
        time.sleep(0.4)
    
    print(f"  Mempool after reorg: {len(final_txids)} transaction(s)")
    for txid in final_txids[:10]:
        match = "✓ MATCH!" if txid == spending_tx_id else ""
        print(f"    - {txid} {match}")
    
    suite.assert_true(tx_in_mempool_after,
                     "Reorg tx to mempool: Tx moved to mempool after reorg",
                     f"Expected {spending_tx_id} in mempool after reorg")
    
    if tx_in_mempool_after:
        print(f"  ✓ Transaction successfully moved to mempool after reorg")

def test_with_mempool_cleanup(conn: NodeConnection, suite: KermaTestSuite):
    """Example test that cleans up mempool first"""
    print("\n--- Test with Mempool Cleanup ---")
    
    # Generate keypair for cleanup
    privkey, pubkey = generate_keypair()
    
    # Clear any existing mempool transactions
    clear_mempool_by_including_txs(conn, pubkey)
    
    # Verify it's clean
    txids = get_mempool_txids(conn)
    suite.assert_true(len(txids) == 0, "Mempool cleared before test")

def test_node_sends_getmempool_after_hello(suite: KermaTestSuite):
    """Test: Node sends getmempool immediately after receiving hello"""
    print("\n--- Test: Node Sends Getmempool After Hello ---")
    
    # We need to create a raw connection without sending hello first
    # so we can observe what the node does when it receives hello
    
    print("  Creating raw connection to node...")
    
    try:
        import socket
        import json
        
        # Create a raw TCP socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((NODE_HOST, NODE_PORT))
        
        print("  ✓ Connected to node")
        
        # Send hello message
        hello_msg = {
            "type": "hello",
            "version": "0.10.0",
            "agent": "TestAgent-GetmempoolCheck"
        }
        
        hello_json = canonicalize(hello_msg) + '\n'
        sock.sendall(hello_json.encode('utf-8'))
        
        print("  Sent hello message to node")
        print("  Waiting for node's response...")
        
        # Collect responses for a few seconds
        responses = []
        start_time = time.time()
        buffer = ""
        
        while time.time() - start_time < 3.0:
            try:
                sock.settimeout(0.5)
                data = sock.recv(4096).decode('utf-8')
                if not data:
                    break
                
                buffer += data
                
                # Process complete lines
                while '\n' in buffer:
                    line, buffer = buffer.split('\n', 1)
                    line = line.strip()
                    if line:
                        try:
                            response = json.loads(line)
                            responses.append(response)
                            print(f"    Received: {response.get('type', 'unknown')}")
                        except json.JSONDecodeError:
                            print(f"    Failed to parse: {line}")
            except socket.timeout:
                # No more data for now
                if responses:
                    break
                continue
        
        sock.close()
        
        print(f"\n  Received {len(responses)} response(s) from node")
        
        # Check if node sent hello back
        hello_received = False
        getmempool_received = False
        
        for resp in responses:
            resp_type = resp.get('type', '')
            
            if resp_type == 'hello':
                hello_received = True
                print(f"  ✓ Node sent hello back")
            
            if resp_type == 'getmempool':
                getmempool_received = True
                print(f"  ✓ Node sent getmempool!")
        
        if not hello_received:
            print(f"  ⚠️  Node did not send hello back")
        
        if not getmempool_received:
            print(f"  ⚠️  Node did not send getmempool after hello")
            print(f"  Note: Node should send getmempool immediately after hello handshake")
        
        suite.assert_true(
            hello_received,
            "Getmempool after hello: Node sends hello back",
            "Node should respond to hello with hello"
        )
        
        suite.assert_true(
            getmempool_received,
            "Getmempool after hello: Node sends getmempool",
            "Node should send getmempool after hello handshake"
        )
        
    except Exception as e:
        print(f"  ⚠️  Error during test: {e}")
        import traceback
        traceback.print_exc()
        suite.assert_true(False, "Getmempool after hello: Test completed", str(e))

def test_request_unknown_mempool_transactions(conn: NodeConnection, suite: KermaTestSuite):
    """Test: Node requests unknown transactions from mempool message"""
    print("\n--- Test: Request Unknown Mempool Transactions ---")
    
    privkey, pubkey = generate_keypair()
    
    # Build a chain with a transaction
    print("  Building chain with transaction...")
    objects, coinbase_txid, tip = build_chain_appending_to_tip(
        conn, pubkey, chain_length=2, miner="test"
    )
    
    if not objects:
        suite.assert_true(False, "Request unknown: Could not build chain")
        return
    
    # Send chain
    send_messages(conn, [{"type": "object", "object": obj} for obj in objects],
                  wait_time=BLOCK_PROCESSING_WAIT)
    time.sleep(0.8)
    
    # Create a transaction but DON'T send it yet
    spending_tx = create_spending_tx(coinbase_txid, privkey, pubkey)
    spending_txid = object_id(spending_tx)
    
    print(f"  Created transaction: {spending_txid}")
    print(f"  (NOT sending it to the node yet)")
    
    # Verify the node doesn't know about this transaction
    mempool_before = get_mempool_txids(conn)
    if spending_txid in mempool_before:
        print(f"  ⚠️  Transaction already in mempool (unexpected)")
        suite.assert_true(False, "Request unknown: Tx not in mempool initially")
        return
    
    print(f"  ✓ Transaction not in node's mempool (as expected)")
    
    # Now tell the node about this transaction via a mempool message
    print(f"\n  Sending mempool message with unknown txid...")
    conn.clear_responses()
    
    # Send mempool message with the unknown txid
    fake_mempool = {"type": "mempool", "txids": [spending_txid]}
    conn.send(fake_mempool)
    
    # Give node time to process and send getobject request
    time.sleep(0.5)
    
    # Check if node sent getobject request for the unknown transaction
    responses = conn.get_responses(timeout=2.0, debug=True)
    
    print(f"\n  Received {len(responses)} response(s) from node:")
    
    getobject_sent = False
    for resp in responses:
        resp_type = resp.get('type', 'unknown')
        print(f"    - Response type: {resp_type}")
        
        if resp_type == 'getobject':
            objectid = resp.get('objectid', '')
            print(f"      Requesting object: {objectid}")
            
            if objectid == spending_txid:
                getobject_sent = True
                print(f"      ✓ Node requested the unknown transaction!")
    
    if getobject_sent:
        print(f"\n  ✓ Node correctly requested unknown transaction with getobject")
        
        # Now send the transaction object back to complete the exchange
        print(f"  Sending the transaction object back to node...")
        conn.send({"type": "object", "object": spending_tx})
        time.sleep(0.5)
        
        # Verify it's now in the mempool
        mempool_after = get_mempool_txids(conn)
        if spending_txid in mempool_after:
            print(f"  ✓ Transaction now in mempool after providing it")
        else:
            print(f"  ⚠️  Transaction not in mempool (might be timing issue)")
    else:
        print(f"\n  ⚠️  Node did not request the unknown transaction")
        print(f"  This could mean:")
        print(f"    - Node doesn't implement automatic getobject for unknown mempool txs")
        print(f"    - Node needs more time to process")
        print(f"    - Node has different behavior")
    
    suite.assert_true(
        getobject_sent,
        "Request unknown: Node sends getobject for unknown mempool tx",
        "Node should request unknown transactions from mempool message"
    )

# ============================================================================
# MAIN
# ============================================================================

def run_test(test_func, suite: KermaTestSuite, test_delay: float = 0.5):
    """Run a single test with its own connection"""
    print(f"\n🔌 Starting connection for {test_func.__name__}...")
    conn = create_connection()
    
    try:
        test_func(conn, suite)
    finally:
        conn.stop()
        print(f"✓ Connection closed for {test_func.__name__}")
    
    time.sleep(test_delay)


def main():
    """Run all tests"""
    print("=" * 50)
    print("Kerma Mempool Test Suite (Explicit Connection)")
    print("=" * 50)
    print(f"Testing node at {NODE_HOST}:{NODE_PORT}")
    
    # Check dependencies
    try:
        subprocess.run(['nc', '-h'], capture_output=True, timeout=1)
    except FileNotFoundError:
        print("Error: 'nc' (netcat) not found. Please install it first.")
        print("  Ubuntu/Debian: sudo apt-get install netcat")
        print("  macOS: brew install netcat")
        sys.exit(1)
    except:
        pass
    
    try:
        import nacl
    except ImportError:
        print("Error: PyNaCl not found. Please install it first.")
        print("  pip install pynacl")
        sys.exit(1)
    
    suite = KermaTestSuite()
    
    try:
        # Run basic protocol tests
        print("\n" + "=" * 50)
        print("BASIC PROTOCOL TESTS")
        print("=" * 50)
        
        run_test(test_initial_mempool, suite)
        run_test(test_chain_tip, suite)
        run_test(test_getpeers, suite)
        run_test(test_error_handling, suite)
        
        # Run mempool functionality tests
        print("\n" + "=" * 50)
        print("MEMPOOL FUNCTIONALITY TESTS")
        print("=" * 50)
        
        run_test(test_coinbase_rejection, suite, test_delay=1.0)
        run_test(test_valid_transaction_addition, suite, test_delay=1.0)
        run_test(test_double_spend_rejection, suite, test_delay=1.0)
        run_test(test_mempool_reorg, suite, test_delay=1.0)
        
        print("\n" + "=" * 50)
        print("Adding additional tests...")
        print("=" * 50)
        # Add to the MEMPOOL FUNCTIONALITY TESTS section:
        run_test(test_transaction_removed_when_mined, suite, test_delay=1.0)
        run_test(test_transaction_invalidated_by_block, suite, test_delay=1.0)
        run_test(test_reorg_moves_transaction_to_mempool, suite, test_delay=1.0)       
        run_test(test_request_unknown_mempool_transactions, suite, test_delay=1.0)
        test_node_sends_getmempool_after_hello(suite)
        run_test(test_with_mempool_cleanup, suite, test_delay=1.0)

    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
    except Exception as e:
        print(f"\n\n⚠️  Unexpected error: {e}")
        import traceback
        traceback.print_exc()
    
    # Print summary
    success = suite.print_summary()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
