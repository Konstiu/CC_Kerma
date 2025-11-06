from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

import copy
import hashlib
import json
import re

import constants as const
from message.msgexceptions import ErrorInvalidFormat



# perform syntactic checks. returns true iff check succeeded
OBJECTID_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_objectid(objid_str):
    if not isinstance(objid_str, str):
        raise ErrorInvalidFormat("Object ID must be a string")
    if not re.match(OBJECTID_REGEX, objid_str):
        raise ErrorInvalidFormat("Invalid object ID format: must be 64 hex characters")
    return True

PUBKEY_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_pubkey(pubkey_str):
    if not isinstance(pubkey_str, str):
        raise ErrorInvalidFormat("Public key must be a string")
    if not re.match(PUBKEY_REGEX, pubkey_str):
        raise ErrorInvalidFormat("Invalid public key format: must be 64 hex characters")
    return True

SIGNATURE_REGEX = re.compile("^[0-9a-f]{128}$")
def validate_signature(sig_str):
    if not isinstance(sig_str, str):
        raise ErrorInvalidFormat("Signature must be a string")
    if not re.match(SIGNATURE_REGEX, sig_str):
        raise ErrorInvalidFormat("Invalid signature format: must be 128 hex characters")
    return True

NONCE_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_nonce(nonce_str):
    if not isinstance(nonce_str, str):
        raise ErrorInvalidFormat("Nonce must be a string")
    if not re.match(NONCE_REGEX, nonce_str):
        raise ErrorInvalidFormat("Invalid nonce format: must be 64 hex characters")
    return True



TARGET_REGEX = re.compile("^[0-9a-f]{64}$")
def validate_target(target_str):
    if not isinstance(target_str, str):
        raise ErrorInvalidFormat("Nonce must be a string")
    if not re.match(TARGET_REGEX, target_str):
        raise ErrorInvalidFormat("Invalid nonce format: must be 64 hex characters")
    return True


def validate_transaction_input(in_dict):
    # todo
    return True

def validate_transaction_output(out_dict):
    # todo
    return True

def validate_transaction(trans_dict):
    # todo
    return True

def validate_block(block_dict):
    # todo
    return True

def validate_object(obj_dict):
    # todo
    return True

def get_objid(obj_dict):
    h = hashlib.blake2s()
    h.update(canonicalize(obj_dict))
    return h.hexdigest()

# perform semantic checks

# verify the signature sig in tx_dict using pubkey
def verify_tx_signature(tx_dict, sig, pubkey):
    # todo
    return True

class TXVerifyException(Exception):
    pass

def verify_transaction(tx_dict, input_txs):
    pass # todo 

class BlockVerifyException(Exception):
    pass

# apply tx to utxo
# returns mining fee
def update_utxo_and_calculate_fee(tx, utxo):
    # todo
    return 0

# verify that a block is valid in the current chain state, using known transactions txs
def verify_block(block, prev_block, prev_utxo, prev_height, txs):
    # todo
    return 0
