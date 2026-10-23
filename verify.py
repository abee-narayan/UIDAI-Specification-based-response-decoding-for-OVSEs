import json
import base64
import hashlib
import argparse
import sys

def b64url_to_bytes(b64url):
    b64url = b64url.replace('-', '+').replace('_', '/')
    pad = len(b64url) % 4
    if pad:
        b64url += '=' * (4 - pad)
    return base64.b64decode(b64url)

def verify_uidai_sdjwt(jwt_string, jwks_data):
    # Split SD-JWT into core JWT and disclosures
    parts = jwt_string.split('~')
    core_jwt = parts[0]
    disclosures = parts[1:] if len(parts) > 1 else []
    
    # Parse JWT Header & Payload
    jwt_parts = core_jwt.split('.')
    if len(jwt_parts) != 3:
        print("[-] Invalid JWT format")
        return

    header_b64, payload_b64, sig_b64 = jwt_parts
    header = json.loads(b64url_to_bytes(header_b64))
    signing_input = f"{header_b64}.{payload_b64}".encode('ascii')
    signature_bytes = b64url_to_bytes(sig_b64)
    payload = json.loads(b64url_to_bytes(payload_b64))
    
    kid = header.get('kid')
    if not kid:
        print("[-] No 'kid' (Key ID) found in JWT header.")
        return
        
    # Find matching key in JWKS
    key_data = next((k for k in jwks_data.get('keys', []) if k.get('kid') == kid), None)
    if not key_data:
        print(f"[-] Key with kid '{kid}' not found in provided JWKS.")
        return

    if key_data.get('kty') != 'RSA':
        print("[-] This script currently implements RSA verification only.")
        return

    # Extract RSA Parameters
    n = int.from_bytes(b64url_to_bytes(key_data['n']), 'big')
    e = int.from_bytes(b64url_to_bytes(key_data['e']), 'big')
    sig_int = int.from_bytes(signature_bytes, 'big')

    # RSA Decrypt: m = s^e mod n
    decrypted_int = pow(sig_int, e, n)
    decrypted_bytes = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, 'big')

    # Expected PKCS#1 v1.5 hash format for SHA-256
    sha256_oid = b'\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20'
    expected_hash = hashlib.sha256(signing_input).digest()
    expected_payload = sha256_oid + expected_hash

    # Validate Signature
    if decrypted_bytes.endswith(expected_payload):
        print("[+] Core JWT Signature: VALID")
    else:
        print("[-] Core JWT Signature: INVALID")
        return

    # Validate Selective Disclosures
    sd_array = payload.get('_sd', [])
    if not disclosures or not disclosures[0]:
        print("[!] No selective disclosures appended to this JWT.")
        return

    print("\n[+] Verified Disclosed Claims:")
    valid_count = 0
    for disclosure in disclosures:
        if not disclosure: 
            continue
            
        # Hash the raw disclosure string
        digest = hashlib.sha256(disclosure.encode('ascii')).digest()
        hash_b64url = base64.urlsafe_b64encode(digest).decode('ascii').rstrip('=')
        
        # Check if the hash is present in the payload's _sd array
        if hash_b64url in sd_array:
            decoded_disclosure = json.loads(b64url_to_bytes(disclosure).decode('utf-8'))
            # disclosure format is [salt, claim_name, claim_value]
            print(f"    - {decoded_disclosure[1]}: {decoded_disclosure[2]}")
            valid_count += 1
        else:
            print(f"    [-] Invalid disclosure (Hash not found in payload).")
            
    if valid_count == 0:
        print("    No valid disclosures found matching the payload hashes.")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Verify UIDAI Aadhaar SD-JWT")
    parser.add_argument("--jwt", required=True, help="Path to file containing the SD-JWT string")
    parser.add_argument("--jwks", required=True, help="Path to JWKS JSON file")
    args = parser.parse_args()

    try:
        with open(args.jwt, 'r') as f:
            jwt_string = f.read().strip()
    except Exception as e:
        print(f"Error reading JWT file: {e}")
        sys.exit(1)
        
    try:
        with open(args.jwks, 'r') as f:
            jwks_data = json.load(f)
    except Exception as e:
        print(f"Error reading JWKS file: {e}")
        sys.exit(1)
        
    verify_uidai_sdjwt(jwt_string, jwks_data)
