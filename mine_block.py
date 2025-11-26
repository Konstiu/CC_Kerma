#!/usr/bin/env python3
import sys
import json
import hashlib
from jcs import canonicalize

def mine_block(previd, txids, timestamp, target, miner="grader"):
    """
    Mine a block by finding a valid nonce.
    
    Args:
        previd: Previous block ID
        txids: List of transaction IDs
        timestamp: Block creation timestamp
        target: Target difficulty (64-char hex string)
        miner: Miner name (optional)
    
    Returns:
        JSON string of the mined block
    """
    block_template = {
        "type": "block",
        "txids": txids,
        "nonce": "",
        "previd": previd,
        "created": timestamp,
        "T": target,
        "miner": miner
    }
    
    # Convert target to comparable format
    target_int = int(target, 16)
    
    # Find valid nonce
    nonce = 0
    while True:
        # Format nonce as exactly 64 hex characters with leading zeros (lowercase)
        nonce_str = format(nonce, '064x')
        block_template["nonce"] = nonce_str
        
        # Calculate block hash
        block_hash = hashlib.blake2s(canonicalize(block_template)).hexdigest()
        block_hash_int = int(block_hash, 16)
        
        # Check if hash meets target
        if block_hash_int <= target_int:
            print(f"Found valid nonce after {nonce + 1} attempts!", file=sys.stderr)
            print(f"Block hash: {block_hash}", file=sys.stderr)
            return json.dumps(block_template)
        
        nonce += 1
        if nonce % 10000 == 0:
            print(f"Tried {nonce} nonces...", file=sys.stderr)

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: mine_block.py <previd> <txid1,txid2,...> <timestamp> <target> [miner]", file=sys.stderr)
        print("Example: mine_block.py 00000000...abc txid1,txid2 1234567890 0000abc0...000 grader", file=sys.stderr)
        sys.exit(1)
    
    previd = sys.argv[1]
    txids = sys.argv[2].split(',')
    timestamp = int(sys.argv[3])
    target = sys.argv[4]
    miner = sys.argv[5] if len(sys.argv) > 5 else "grader"
    
    result = mine_block(previd, txids, timestamp, target, miner)
    print(result)
