from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.exceptions import InvalidSignature
from datetime import datetime
from jcs import canonicalize

import copy
import hashlib
import json
import re
import binascii

import constants as const
from message.msgexceptions import ErrorInvalidFormat, ErrorInvalidAncestry, ErrorInvalidTxConservation, ErrorInvalidTxOutpoint, ErrorInvalidTxSignature, ErrorUnknownObject
import object_db

# perform syntactic checks. returns true iff check succeeded
OBJECTID_REGEX = re.compile(r"^[0-9a-f]{64}$")
def validate_objectid(objid_str):
    if not isinstance(objid_str, str):
        raise ErrorInvalidFormat("Object ID must be a string")
    if not re.match(OBJECTID_REGEX, objid_str):
        raise ErrorInvalidFormat("Invalid object ID format: must be 64 hex characters")
    return True

PUBKEY_REGEX = re.compile(r"^[0-9a-f]{64}$")
def validate_pubkey(pubkey_str):
    if not isinstance(pubkey_str, str):
        raise ErrorInvalidFormat("Public key must be a string")
    if not re.match(PUBKEY_REGEX, pubkey_str):
        raise ErrorInvalidFormat("Invalid public key format: must be 64 hex characters")
    return True

SIGNATURE_REGEX = re.compile(r"^[0-9a-f]{128}$")
def validate_signature(sig_str):
    if not isinstance(sig_str, str):
        raise ErrorInvalidFormat("Signature must be a string")
    if not re.match(SIGNATURE_REGEX, sig_str):
        raise ErrorInvalidFormat("Invalid signature format: must be 128 hex characters")
    return True

NONCE_REGEX = re.compile(r"^[0-9a-f]{64}$")
def validate_nonce(nonce_str):
    if not isinstance(nonce_str, str):
        raise ErrorInvalidFormat("Nonce must be a string")
    if not re.match(NONCE_REGEX, nonce_str):
        raise ErrorInvalidFormat("Invalid nonce format: must be 64 hex characters")
    return True



TARGET_REGEX = re.compile(r"^[0-9a-f]{64}$")
def validate_target(target_str):
    if not isinstance(target_str, str):
        raise ErrorInvalidFormat("Target must be a string")
    if not re.match(TARGET_REGEX, target_str):
        raise ErrorInvalidFormat("Invalid target format: must be 64 hex characters")
    return True


# Check if message contains no invalid keys,
# raises a MalformedMsgException
def validate_allowed_keys(msg_dict, allowed_keys, msg_type):
    if len(set(msg_dict.keys()) - set(allowed_keys)) != 0:
        raise ErrorInvalidFormat(
            "Message malformed: {} message contains invalid keys!".format(msg_type)
        )


def validate_transaction_input(in_dict, cleaned_tx_for_signature_verification):
    if not isinstance(in_dict, dict):
        raise ErrorInvalidFormat("Transaction input must be a dictionary")
    if 'outpoint' not in in_dict:
        raise ErrorInvalidFormat("Transaction input missing 'outpoint' field")
    if 'sig' not in in_dict:
        raise ErrorInvalidFormat("Transaction input missing 'sig' field")
    
    sig = in_dict['sig']
    validate_signature(sig)

    outpoint = in_dict['outpoint']
    if not isinstance(outpoint, dict):
        raise ErrorInvalidFormat("Transaction input outpoint must be a dictionary")
    if 'index' not in outpoint:
        raise ErrorInvalidFormat("Transaction input outpoint missing 'index' field")
    index = outpoint['index']
    if not isinstance(index, int) or index < 0:
        raise ErrorInvalidFormat("Invalid transaction input outpoint index")
    if 'txid' not in outpoint:
        raise ErrorInvalidFormat("Transaction input outpoint missing 'txid' field")
    txid = outpoint['txid']
    validate_objectid(txid)
    validate_allowed_keys(outpoint, ["txid", "index"], "transaction_input_outpoint")

    validate_allowed_keys(in_dict, ["outpoint", "sig"], "transaction_input")

    # syntax checks passed
    # now semantic checks are done
    # check if the input points on an existing transaction output
    existing_tx = object_db.get_object(txid)
    if existing_tx is None:
        raise ErrorUnknownObject(f"Referenced transaction {txid} does not exist")
    
    # check if the existing object is a transaction
    if existing_tx['type'] != "transaction":
        raise ErrorInvalidFormat(f"Referenced object {txid} is not a transaction")

    existing_tx_outputs = existing_tx['outputs']
    if index >= len(existing_tx_outputs):
        raise ErrorInvalidTxOutpoint(f"Referenced transaction has no output at index {index}")
    
    existing_tx_output = existing_tx_outputs[index]
    existing_tx_pubkey = existing_tx_output['pubkey']

    # verify the signature
    # for that we must copy the existing transaction and remove all signatures from its inputs
    verify_tx_signature(cleaned_tx_for_signature_verification, sig, existing_tx_pubkey)


def validate_transaction_output(out_dict):
    if not isinstance(out_dict, dict):
        raise ErrorInvalidFormat("Transaction output must be a dictionary")
    if 'pubkey' not in out_dict:
        raise ErrorInvalidFormat("Transaction output missing 'pubkey' field")
    if 'value' not in out_dict:
        raise ErrorInvalidFormat("Transaction output missing 'value' field")
    pub_key = out_dict['pubkey']
    value = out_dict['value']
    validate_pubkey(pub_key)
    if not isinstance(value, int) or value < 0:
        raise ErrorInvalidFormat("Invalid transaction output value")

    validate_allowed_keys(out_dict, ["pubkey", "value"], "transaction_output")

def validate_coinbase_transaction(trans_dict):
    if 'height' not in trans_dict:
        raise ErrorInvalidFormat("Coinbase transaction missing 'height' field")
    if 'outputs' not in trans_dict:
        raise ErrorInvalidFormat("Coinbase transaction missing 'outputs' field")
    height = trans_dict['height']
    if not isinstance(height, int) or height < 0:
        raise ErrorInvalidFormat("Invalid coinbase transaction height")
    outputs = trans_dict['outputs']
    if not isinstance(outputs, list):
        raise ErrorInvalidFormat("Invalid coinbase transaction outputs")

    validate_allowed_keys(trans_dict, ["type", "height", "outputs"], "transaction")

    for output in outputs:
        validate_transaction_output(output)
    
def validate_standard_transaction(trans_dict):
    if 'inputs' not in trans_dict:
        raise ErrorInvalidFormat("Standard transaction missing 'inputs' field")
    if 'outputs' not in trans_dict:
        raise ErrorInvalidFormat("Standard transaction missing 'outputs' field")
    inputs = trans_dict['inputs']
    outputs = trans_dict['outputs']
    if not isinstance(inputs, list) or len(inputs) == 0:
        raise ErrorInvalidFormat("Invalid standard transaction inputs")
    if not isinstance(outputs, list):
        raise ErrorInvalidFormat("Invalid standard transaction outputs")
    
    validate_allowed_keys(trans_dict, ["type", "inputs", "outputs"], "transaction")

    for output in outputs:
        validate_transaction_output(output)

    # prepare cleaned transaction for signature verification
    cleaned_tx_for_signature_verification = copy.deepcopy(trans_dict)
    for input in cleaned_tx_for_signature_verification['inputs']:
        if 'sig' in input:
            input['sig'] = None

    # validate inputs
    for input in inputs:
        validate_transaction_input(input, cleaned_tx_for_signature_verification)

    # at this point all syntax checks passed
    # and also all input signatures are valid
    # finally check if no input was used twice or even more times (double spending)
    # and check if the sum of the inputs is >= sum of the outputs
    sum_of_outputs = 0
    for output in outputs:
        sum_of_outputs += output['value']
    used_outpoints = set()
    sum_of_inputs = 0
    for input in inputs:
        outpoint = input['outpoint']
        outpoint_key = (outpoint['txid'], outpoint['index'])
        if outpoint_key in used_outpoints:
            raise ErrorInvalidFormat(f"Transaction double spends the outpoint {outpoint_key}")
        used_outpoints.add(outpoint_key)

        # get the value of the referenced output
        referenced_tx = object_db.get_object(outpoint['txid'])
        assert referenced_tx is not None  # already checked in validate_transaction_input
        referenced_output = referenced_tx['outputs'][outpoint['index']]
        sum_of_inputs += referenced_output['value']

    if sum_of_inputs < sum_of_outputs:
        raise ErrorInvalidTxConservation("Transaction inputs value is less than outputs value")

def validate_transaction(trans_dict):
    try:
        validate_coinbase_transaction(trans_dict)
        return
    except:
        pass
    
    # it is not a coinbase transaction, try if it is a standard transaction
    validate_standard_transaction(trans_dict)

def validate_block(block_dict):
    raise ErrorInvalidFormat("Block validation not yet implemented")

def validate_object(obj_dict):
    if not isinstance(obj_dict, dict):
        raise ErrorInvalidFormat("Object must be a dictionary")
    if 'type' not in obj_dict:
        raise ErrorInvalidFormat("Object missing 'type' field")
    obj_type = obj_dict['type']
    if obj_type == "transaction":
        validate_transaction(obj_dict)
    elif obj_type == "block":
        validate_block(obj_dict)
    else:
      raise ErrorInvalidFormat("Unknown object type")

def get_objid(obj_dict):
    msgbytes = canonicalize(obj_dict)
    if isinstance(msgbytes, str):
        msgbytes = msgbytes.encode("utf-8")
    h = hashlib.blake2s()
    h.update(msgbytes)
    return h.hexdigest()

# perform semantic checks

# verify the signature sig in tx_dict using pubkey
# the received tx_dict must have all signatures already removed from its inputs
def verify_tx_signature(tx_dict, sig, pubkey):
    plaintext = canonicalize(tx_dict)
    if isinstance(plaintext, str):
        plaintext = plaintext.encode("utf-8")
    pubkey = Ed25519PublicKey.from_public_bytes(binascii.unhexlify(pubkey))
    signature = binascii.unhexlify(sig)
    try:
        pubkey.verify(signature, plaintext)
    except InvalidSignature:
        raise ErrorInvalidTxSignature("Invalid transaction signature")

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