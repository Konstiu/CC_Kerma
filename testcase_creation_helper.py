import base64
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from jcs import canonicalize
import hashlib

def read_ed25519_public_key(pub_key_file):
    """
    Liest einen Ed25519 Public Key aus einer SSH .pub Datei
    und gibt ihn als 64-Zeichen Hex-String zurück (RFC 8032 Format)
    """
    with open(pub_key_file, 'r') as f:
        content = f.read().strip()
    
    # Format: "ssh-ed25519 AAAAC3Nza... kommentar"
    parts = content.split()
    
    if len(parts) < 2:
        raise ValueError("Ungültiges Public Key Format")
    
    key_type = parts[0]
    base64_key = parts[1]
    
    if key_type != 'ssh-ed25519':
        raise ValueError(f"Erwartete ssh-ed25519, aber gefunden: {key_type}")
    
    # Base64 dekodieren
    decoded = base64.b64decode(base64_key)
    
    # Die letzten 32 Bytes sind der eigentliche Ed25519 Public Key
    raw_public_key = decoded[-32:]
    
    # In Hex umwandeln
    hex_public_key = raw_public_key.hex()
    
    return hex_public_key


def sign_message(private_key_file, obj_dict):
    """
    Signiert eine Nachricht mit dem Ed25519 Private Key
    und gibt die Signatur als 128-Zeichen Hex-String zurück (RFC 8032 Format)
    """
    # Private Key einlesen
    with open(private_key_file, 'rb') as f:
        private_key = serialization.load_ssh_private_key(
            f.read(),
            password=None  # Falls dein Key eine Passphrase hat, hier angeben
        )
    
    # Nachricht in Bytes umwandeln
    message_bytes = canonicalize(obj_dict)
    
    # Signatur erstellen
    signature = private_key.sign(message_bytes)
    
    # In Hex umwandeln (64 Bytes = 128 Hex-Zeichen)
    hex_signature = signature.hex()
    
    return hex_signature


def get_objid(obj_dict):
    msgbytes = canonicalize(obj_dict)
    if isinstance(msgbytes, str):
        msgbytes = msgbytes.encode("utf-8")
    h = hashlib.blake2s()
    h.update(msgbytes)
    return h.hexdigest()

# Verwendung:
pub_key_hex = read_ed25519_public_key('id_test_ed25519.pub')
print(f"Public Key (hex): {pub_key_hex}")
print(f"Länge: {len(pub_key_hex)} Zeichen\n")

# Fixer String zum Signieren
message_to_sign = {
    #"object": {
        "inputs": [
            {
                "outpoint": {
                    "index": 0,
                    "txid": "e3e8ff71785e1bd9b2650acf48ed1a647b72d96862fd80c54fb912ce2d964963"
                },
                "sig": "375d15b69bab5d884444c79a383c42ba9819e69dd0009084e13b2b8381a3d0c02e4a8bde3f4d5ebba6e90092331ad44358b54e92c099b1c5fd9b752266ae730f"
            }
        ],
        "outputs": [
            {
                "pubkey": "b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985" ,
                "value": 50000000000001
            }
        ],
        "type": "transaction"
    #},
    #"type": "object"
}

signature_hex = sign_message('id_test_ed25519', message_to_sign)
print(f"Message: {message_to_sign}")
print(f"Signature (hex): {signature_hex}")
print(f"Länge: {len(signature_hex)} Zeichen")


# Object id bekommen
object_to_get_id_of = {"type":"object","object":{"T":"0000abc000000000000000000000000000000000000000000000000000000000","created":1671148800,"miner":"grader","nonce":"00000000000000000000000000000000000000000000000000000000000463cf","note":"This block has a coinbase transaction","previd":"00002fa163c7dab0991544424b9fd302bb1782b185e5a3bbdf12afb758e57dee","txids":["6ebfb4c8e8e9b19dcf54c6ce3e1e143da1f473ea986e70c5cb8899a4671c933a"],"type":"block"}}



objid = get_objid(object_to_get_id_of)
print(f"\nObject: {object_to_get_id_of}")
print(f"Object ID: {objid}")
print(f"Länge: {len(objid)} Zeichen")


object_to_canonicalize = {
    "object": {
        "inputs": [
            {
                "outpoint": {
                    "index": 0,
                    "txid": "e3e8ff71785e1bd9b2650acf48ed1a647b72d96862fd80c54fb912ce2d964963"
                },
                "sig": "375d15b69bab5d884444c79a383c42ba9819e69dd0009084e13b2b8381a3d0c02e4a8bde3f4d5ebba6e90092331ad44358b54e92c099b1c5fd9b752266ae730f"
            }
        ],
        "outputs": [
            {
                "pubkey": "b539258e808b3e3354b9776d1ff4146b52282e864f56224e7e33e7932ec72985" ,
                "value": 50000000000001
            }
        ],
        "type": "transaction"
    },
    "type": "object"
}

canonicalized = canonicalize(object_to_canonicalize)
print(f"\nObject to canonicalize: {object_to_canonicalize}")
print(f"Canonicalized: {canonicalized}")
print(f"Länge: {len(canonicalized)} Zeichen")