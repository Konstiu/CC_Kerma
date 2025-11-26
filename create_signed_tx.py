#!/usr/bin/env python3
import sys
import json
import hashlib
from jcs import canonicalize
from nacl.signing import SigningKey
from nacl.encoding import HexEncoder

def create_keypair():
    """Generate a new Ed25519 keypair."""
    signing_key = SigningKey.generate()
    verify_key = signing_key.verify_key
    
    private_key = signing_key.encode(encoder=HexEncoder).decode('utf-8')
    public_key = verify_key.encode(encoder=HexEncoder).decode('utf-8')
    
    return private_key, public_key

def sign_transaction(tx_dict, private_key_hex):
    """Sign a transaction with the given private key."""
    import copy
    signing_key = SigningKey(private_key_hex, encoder=HexEncoder)
    
    # Create a copy and set all signatures to None (matching verification)
    tx_local = copy.deepcopy(tx_dict)
    for i in tx_local['inputs']:
        i['sig'] = None
    
    # Canonicalize the transaction for signing
    tx_bytes = canonicalize(tx_local)
    
    # Sign the transaction
    signed = signing_key.sign(tx_bytes)
    signature = signed.signature.hex()
    
    return signature

def create_signed_transaction(prev_txid, prev_index, output_pubkey, output_value, signing_private_key):
    """Create and sign a transaction."""
    tx = {
        "type": "transaction",
        "inputs": [
            {
                "outpoint": {
                    "txid": prev_txid,
                    "index": prev_index
                },
                "sig": None  # Set to None before signing
            }
        ],
        "outputs": [
            {
                "pubkey": output_pubkey,
                "value": output_value
            }
        ]
    }
    
    # Sign the transaction
    signature = sign_transaction(tx, signing_private_key)
    tx["inputs"][0]["sig"] = signature
    
    return tx

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:", file=sys.stderr)
        print("  create_signed_tx.py keygen", file=sys.stderr)
        print("  create_signed_tx.py sign <prev_txid> <prev_index> <output_pubkey> <output_value> <private_key>", file=sys.stderr)
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "keygen":
        private_key, public_key = create_keypair()
        print(json.dumps({"private": private_key, "public": public_key}))
    
    elif command == "sign":
        if len(sys.argv) != 7:
            print("Error: sign requires 5 arguments", file=sys.stderr)
            sys.exit(1)
        
        prev_txid = sys.argv[2]
        prev_index = int(sys.argv[3])
        output_pubkey = sys.argv[4]
        output_value = int(sys.argv[5])
        private_key = sys.argv[6]
        
        tx = create_signed_transaction(prev_txid, prev_index, output_pubkey, output_value, private_key)
        print(json.dumps(tx))
    
    else:
        print(f"Unknown command: {command}", file=sys.stderr)
        sys.exit(1)
