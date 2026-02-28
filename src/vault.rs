use std::env;
use std::path::{Path, PathBuf};

use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::cipher::{decrypt, encrypt};
use crate::crypto::kdf::{derive_key, ARGON2_M_COST, ARGON2_P_COST, ARGON2_T_COST, SALT_SIZE};
use crate::error::SerdeVaultError;
use crate::format::{atomic_write, decode, encode, VaultHeader};

/// A handle to an encrypted vault file.
///
/// The vault stores any `Serialize + Deserialize` value as a single encrypted blob.
/// Encryption uses AES-256-GCM with a key derived from the master password via Argon2id.
///
/// # Example
///
/// ```no_run
/// use serdevault::VaultFile;
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct MyData { value: String }
///
/// let vault = VaultFile::open("~/.my.vault", "my_password");
/// vault.save(&MyData { value: "hello".into() }).unwrap();
/// let loaded: MyData = vault.load().unwrap();
/// ```
pub struct VaultFile {
    path: PathBuf,
    password: Zeroizing<String>,
    /// Argon2id memory cost (kibibytes). Stored here so callers can override for tests.
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
}

impl VaultFile {
    /// Open (or prepare to create) a vault at the given path.
    ///
    /// No I/O is performed — the file is only read on `load` and written on `save`.
    pub fn open(path: impl AsRef<Path>, password: &str) -> Self {
        Self {
            path: expand_tilde(path.as_ref()),
            password: Zeroizing::new(password.to_owned()),
            m_cost: ARGON2_M_COST,
            t_cost: ARGON2_T_COST,
            p_cost: ARGON2_P_COST,
        }
    }

    /// Override the Argon2id parameters used when saving.
    ///
    /// Useful for tests where full 64 MB RAM usage would be too slow.
    pub fn with_params(mut self, m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        self.m_cost = m_cost;
        self.t_cost = t_cost;
        self.p_cost = p_cost;
        self
    }

    /// Whether the vault file exists on disk.
    pub fn exists(&self) -> bool {
        self.path.exists()
    }

    /// Serialize `data` to JSON, encrypt it, and write it to the vault file atomically.
    pub fn save<T: Serialize>(&self, data: &T) -> Result<(), SerdeVaultError> {
        let plaintext = Zeroizing::new(
            serde_json::to_vec(data)
                .map_err(|e| SerdeVaultError::SerializationError(e.to_string()))?,
        );

        let mut salt = [0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let key = derive_key(&self.password, &salt, self.m_cost, self.t_cost, self.p_cost)?;

        let (ciphertext, nonce) = encrypt(&plaintext, &key)?;

        let header = VaultHeader {
            salt,
            m_cost: self.m_cost,
            t_cost: self.t_cost,
            p_cost: self.p_cost,
            nonce,
        };

        let encoded = encode(&header, &ciphertext);
        atomic_write(&self.path, &encoded)?;

        Ok(())
    }

    /// Read the vault file, decrypt it, and deserialize the data.
    pub fn load<T: for<'de> Deserialize<'de>>(&self) -> Result<T, SerdeVaultError> {
        let raw = std::fs::read(&self.path)?;

        let (header, ciphertext) = decode(&raw)?;

        let key = derive_key(
            &self.password,
            &header.salt,
            header.m_cost,
            header.t_cost,
            header.p_cost,
        )?;

        let plaintext = decrypt(ciphertext, &key, &header.nonce)?;

        let value = serde_json::from_slice(&plaintext)
            .map_err(|e| SerdeVaultError::DeserializationError(e.to_string()))?;

        Ok(value)
    }
}

/// Expand a leading `~/` to the user's home directory.
/// Falls back to the literal path if `HOME` is not set.
fn expand_tilde(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix("~/") {
        if let Ok(home) = env::var("HOME") {
            return PathBuf::from(home).join(rest);
        }
    }
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use tempfile::tempdir;

    // Low-cost Argon2 params so tests run in milliseconds instead of seconds.
    const M: u32 = 8;
    const T: u32 = 1;
    const P: u32 = 1;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestData {
        name: String,
        value: u64,
        tags: Vec<String>,
        optional: Option<String>,
    }

    fn sample() -> TestData {
        TestData {
            name: "GitHub perso".to_string(),
            value: 42,
            tags: vec!["work".to_string(), "git".to_string()],
            optional: Some("note".to_string()),
        }
    }

    fn vault_at(dir: &tempfile::TempDir, filename: &str, password: &str) -> VaultFile {
        VaultFile::open(dir.path().join(filename), password).with_params(M, T, P)
    }

    // 1. save → load → data is identical
    #[test]
    fn test_roundtrip() {
        let dir = tempdir().unwrap();
        let vault = vault_at(&dir, "vault.svlt", "correct-horse-battery");
        let data = sample();

        vault.save(&data).expect("save failed");
        let loaded: TestData = vault.load().expect("load failed");

        assert_eq!(data, loaded);
    }

    // 2. Nested structs, Vec, Option round-trip correctly
    #[test]
    fn test_roundtrip_option_none() {
        let dir = tempdir().unwrap();
        let vault = vault_at(&dir, "vault.svlt", "pwd");
        let mut data = sample();
        data.optional = None;

        vault.save(&data).unwrap();
        let loaded: TestData = vault.load().unwrap();

        assert_eq!(data, loaded);
    }

    // 3. Wrong password → DecryptionFailed, not a panic
    #[test]
    fn test_wrong_password() {
        let dir = tempdir().unwrap();
        let data = sample();

        vault_at(&dir, "vault.svlt", "correct").save(&data).unwrap();

        let err = VaultFile::open(dir.path().join("vault.svlt"), "wrong")
            .with_params(M, T, P)
            .load::<TestData>()
            .unwrap_err();

        assert!(
            matches!(err, SerdeVaultError::DecryptionFailed),
            "expected DecryptionFailed, got: {err}"
        );
    }

    // 4. Completely empty file → InvalidFormat
    #[test]
    fn test_empty_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.svlt");
        std::fs::write(&path, b"").unwrap();

        let err = VaultFile::open(&path, "pwd")
            .with_params(M, T, P)
            .load::<TestData>()
            .unwrap_err();

        assert!(matches!(err, SerdeVaultError::InvalidFormat(_)));
    }

    // 5. File with wrong magic number → InvalidFormat
    #[test]
    fn test_bad_magic() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("vault.svlt");
        // Write HEADER_SIZE bytes but with wrong magic
        let garbage = vec![0xFFu8; crate::format::HEADER_SIZE + 16];
        std::fs::write(&path, &garbage).unwrap();

        let err = VaultFile::open(&path, "pwd")
            .with_params(M, T, P)
            .load::<TestData>()
            .unwrap_err();

        assert!(matches!(err, SerdeVaultError::InvalidFormat(_)));
    }

    // 6. File with correct magic but truncated body → DecryptionFailed (GCM tag missing)
    #[test]
    fn test_truncated_ciphertext() {
        let dir = tempdir().unwrap();
        let vault = vault_at(&dir, "vault.svlt", "pwd");
        vault.save(&sample()).unwrap();

        // Truncate the file to just the header — no ciphertext
        let path = dir.path().join("vault.svlt");
        let header_only = std::fs::read(&path).unwrap()[..crate::format::HEADER_SIZE].to_vec();
        std::fs::write(&path, &header_only).unwrap();

        let err = vault.load::<TestData>().unwrap_err();
        // AES-GCM will fail to verify the (empty) tag
        assert!(matches!(err, SerdeVaultError::DecryptionFailed));
    }

    // 7. Unsupported version byte → UnsupportedVersion
    #[test]
    fn test_unsupported_version() {
        let dir = tempdir().unwrap();
        let vault = vault_at(&dir, "vault.svlt", "pwd");
        vault.save(&sample()).unwrap();

        let path = dir.path().join("vault.svlt");
        let mut raw = std::fs::read(&path).unwrap();
        raw[4] = 99; // overwrite version byte
        std::fs::write(&path, &raw).unwrap();

        let err = vault.load::<TestData>().unwrap_err();
        assert!(matches!(err, SerdeVaultError::UnsupportedVersion(99)));
    }

    // 8. Two saves produce different ciphertexts (fresh nonce + salt each time)
    #[test]
    fn test_fresh_nonce_on_every_save() {
        let dir = tempdir().unwrap();
        let vault = vault_at(&dir, "vault.svlt", "pwd");
        let data = sample();

        vault.save(&data).unwrap();
        let first = std::fs::read(dir.path().join("vault.svlt")).unwrap();

        vault.save(&data).unwrap();
        let second = std::fs::read(dir.path().join("vault.svlt")).unwrap();

        assert_ne!(first, second, "two saves of identical data must produce different ciphertexts");
    }

    // 9. VaultFile::exists() reflects disk state
    #[test]
    fn test_exists() {
        let dir = tempdir().unwrap();
        let vault = vault_at(&dir, "vault.svlt", "pwd");

        assert!(!vault.exists());
        vault.save(&sample()).unwrap();
        assert!(vault.exists());
    }
}
