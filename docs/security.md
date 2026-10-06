# Security Architecture — SAT-SA

## Encryption Design Decision

**Chosen approach: File-level AES-256-GCM encryption (NOT DuckDB native encryption)**

### Why not DuckDB native encryption?

DuckDB Community Edition (v1.1.3, pinned) does **not** include page-level encryption.
The Enterprise extension `duckdb_crypto` is:
1. Not available in offline/air-gapped builds.
2. Has an unstable API that has changed across minor versions.
3. Cannot be bundled into the PyInstaller single-binary without vendor support.

DuckDB's own documentation (v1.1.3) explicitly states the Community Edition
does not support encryption at rest.

---

## Encryption Implementation

| Property | Value |
|---|---|
| Algorithm | AES-256-GCM |
| Nonce size | 12 bytes (NIST SP 800-38D) |
| Tag size | 16 bytes (full GCM authentication) |
| Library | `cryptography` (Python, OpenSSL backend) |
| Standard | NIST SP 800-38D |

**File format (encrypted):**
```
[12-byte nonce] [ciphertext + 16-byte GCM authentication tag]
```

The GCM tag is automatically appended by `cryptography.hazmat.primitives.ciphers.aead.AESGCM`.
On decryption, the tag is verified **before** any plaintext is returned. Any byte
modification to the ciphertext raises `cryptography.exceptions.InvalidTag`.

---

## What IS encrypted

- **Input data files** (entities.csv, alerts.csv, cases.csv, etc.): AES-256-GCM at rest.
- Examiner generates the key once with `satsa ingest --generate-key`.
- The key is a 32-byte random value from `os.urandom(32)`.

## What is NOT encrypted (and mitigations)

| Component | Protection |
|---|---|
| DuckDB `.db` file | **OS-level disk encryption required** (BitLocker, FileVault, dm-crypt). Documented in deployment guide. |
| Temp decrypted file | Mode 0600, same directory as encrypted file, deleted on context exit |
| Audit log SQLite | OS-level disk encryption (same requirement) |
| Key file | Mode 0600, must be stored on separate encrypted media from data |

---

## Key Management

### Demo Mode: File-based key

```bash
satsa ingest --generate-key --key-file /media/secure-usb/satsa.key
```

- Key is 32 random bytes written to a file.
- **File mode: 0600** (owner read/write only).
- The key file MUST be stored on **separate media** from the encrypted data.
- Key loss = permanent data loss. No key recovery is possible.
- **Do NOT commit the key file to version control.**

### Production Stub: PKCS#11 (HSM / Smartcard)

The `PKCS11KeyProvider` class in `engine/ingestion/encryption.py` is a documented
interface stub. To implement:

1. Install `python-pkcs11`.
2. Configure your PKCS#11 middleware (e.g., OpenSC for smartcards, SoftHSM for testing).
3. Implement `get_key()` to retrieve the AES-256 key from the token.

```python
# Example (pseudocode)
import pkcs11
lib = pkcs11.lib("/usr/lib/opensc-pkcs11.so")
token = lib.get_token(token_label="SAT-SA-TOKEN")
with token.open(user_pin="123456") as session:
    key = session.get_key(pkcs11.KeyType.AES, label="SAT-SA-KEY")
    return key  # Returns key bytes
```

---

## Temp File Security

When the engine opens an encrypted data file:

1. Plaintext is decrypted into memory.
2. Written to a temporary file in the **same directory** as the encrypted file.
3. File mode is set to **0600** (restricted access).
4. DuckDB connects to the temp file.
5. **On context exit (even on exception), the temp file is deleted.**

**Limitation**: During the engine process lifetime, a plaintext temp file exists.
**Mitigation**: Process-level access controls (run as dedicated service account).

---

## Audit Log

- Stored in SQLite (separate from DuckDB).
- Append-only by convention.
- **Hash-chained** with SHA-256: each entry includes the previous entry's hash.
- Verification: `satsa verify-audit` recomputes the full chain.
- **Limitation**: The SQLite file can be deleted entirely. Consider append-only
  filesystem permissions or OS-level write-protect for production.

---

## Data Minimisation (DPDP Act 2023)

Processing of `analyst_id` (a personal data field under DPDP Act 2023) is
authorised under **Section 7 (State functions and legal obligations)**.

- Analyst IDs are used **only** for pattern detection, not individual performance scoring.
- Aggregate statistics are shown; individual analyst scores are not presented in the UI.
- Examiners must follow the NCIIPC Data Handling Policy before acting on
  analyst-linked findings.

---

## Network

SAT-SA is designed for **air-gapped deployment**. No network calls are made
during engine operation. The FastAPI server binds to `127.0.0.1` by default.

```bash
satsa serve --host 127.0.0.1 --port 8000  # Default: loopback only
```

Do NOT expose the port to the network without additional authentication middleware.
