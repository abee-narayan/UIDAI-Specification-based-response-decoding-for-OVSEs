# UIDAI Aadhaar SD-JWT Verifier

A lightweight, standalone Python script to mathematically verify the Selective Disclosure JWT (SD-JWT) signatures provided by the UIDAI Aadhaar ecosystem. 

It checks the RS256 signature against UIDAI's JSON Web Key Set (JWKS) and validates the selectively disclosed claims via SHA-256 hashing.

## Features
- **Zero Dependencies:** Relies entirely on Python's standard library (`json`, `base64`, `hashlib`). No need to install `cryptography`, `pyjwt`, or any external packages.
- **Selective Disclosure Support:** Verifies the cryptographic hashes linking the core JWT to the individual disclosures.
- **Standalone:** Extremely portable, making it easy to integrate into larger backends or verify payloads locally on the fly.

## Prerequisites
- Python 3.6 or higher.

## Usage

1. Save the SD-JWT string you receive from the Aadhaar app into a text file (e.g., `jwt_data.txt`).
2. Save the UIDAI JWKS JSON into a file (e.g., `jwks.json`).
3. Run the verification script:

```bash
python verify.py --jwt jwt_data.txt --jwks jwks.json
```

## Example Output

```text
[+] Core JWT Signature: VALID

[+] Verified Disclosed Claims:
    - ResidentName: [Name of the Resident]
```

## How it works

1. **Splits the Payload:** Separates the base JWT from the appended `~` separated disclosures.
2. **Extracts Public Keys:** Looks up the `kid` (Key ID) from the JWT header in your provided `jwks.json`, and parses the RSA Modulus (`n`) and Exponent (`e`).
3. **Core Validation:** Computes the mathematical RSA decryption to verify the SHA-256 hash of the header and payload.
4. **Disclosure Validation:** Iterates over the disclosures, hashes them, checks them against the `_sd` array in the core payload, and reveals the authenticated claim data.

## License
MIT License
