import base64
import json
import hashlib
import sqlite3

# --------------------------
# Database Setup
# --------------------------
DB_FILE = "sdjwt_results.db"

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

# Create table if not exists
cursor.execute("""
CREATE TABLE IF NOT EXISTS sdjwt_verification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    attribute TEXT,
    value TEXT,
    digest TEXT,
    matched BOOLEAN,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)
""")
conn.commit()

# --------------------------
# Helpers
# --------------------------
def decode_base64url(data: str) -> str:
    padding = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding).decode('utf-8')

def compute_disclosure_digest(raw_disclosure: str) -> str:
    utf8_bytes = raw_disclosure.encode('utf-8')
    sha256_hash = hashlib.sha256(utf8_bytes).digest()
    return base64.urlsafe_b64encode(sha256_hash).decode('utf-8').rstrip('=')

# --------------------------
# Input SD-JWT
# --------------------------
sdjwt_input = input("Enter full SD-JWT string (header.payload.signature~disclosure1~...): ")

parts = sdjwt_input.split("~")
jwt_compact = parts[0]
    disclosures_raw = parts[1:]

try:
    header_b64, payload_b64, signature_b64 = jwt_compact.split('.')
except ValueError:
    raise ValueError("Invalid SD-JWT format. Must be header.payload.signature")

payload_json = json.loads(decode_base64url(payload_b64))
payload_digests = payload_json.get("_sd", [])

# --------------------------
# Process disclosures
# --------------------------
for raw_disclosure in disclosures_raw:
    try:
        disclosure_obj = json.loads(decode_base64url(raw_disclosure))
        if len(disclosure_obj) >= 3:
            attr_name = disclosure_obj[1]
            attr_value = disclosure_obj[2]

            digest = compute_disclosure_digest(raw_disclosure)
            matched = digest in payload_digests

            if matched:
                print(f"Matched: {attr_name} -> {attr_value}")
            else:
                print(f"Not matched: {attr_name} -> {attr_value}")

            # Insert into SQL database
            cursor.execute("""
                INSERT INTO sdjwt_verification (attribute, value, digest, matched)
                VALUES (?, ?, ?, ?)
            """, (attr_name, str(attr_value), digest, matched))

    except Exception as e:
        print(f"Error processing disclosure: {raw_disclosure} - {e}")

conn.commit()
conn.close()

print("Results inserted into database successfully.")
