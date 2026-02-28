# serdevault

Serialize any `Serialize + Deserialize` value to an encrypted file, and read it back.

**Encryption:** AES-256-GCM
**Key derivation:** Argon2id (64 MB RAM, 3 iterations — OWASP 2023)
**Format:** versioned binary with embedded Argon2 parameters

```rust
use serdevault::VaultFile;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct Secrets { api_key: String }

let vault = VaultFile::open("~/.secrets.vault", "master_password");
vault.save(&Secrets { api_key: "s3cr3t".into() })?;
let s: Secrets = vault.load()?;
```

A fresh random salt and nonce are generated on every `save`.
The master password and derived key are zeroized in memory after each operation.
Writes are atomic — the vault is never left in a partially-written state.

## Errors

| Error | Cause |
|---|---|
| `DecryptionFailed` | Wrong password or corrupted file |
| `InvalidFormat` | Not a serdevault file |
| `UnsupportedVersion(n)` | File written by a future version |
