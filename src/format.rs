use std::fs;
use std::io::Write;
use std::path::Path;

use tempfile::NamedTempFile;

use crate::crypto::cipher::NONCE_SIZE;
use crate::crypto::kdf::SALT_SIZE;
use crate::error::SerdeVaultError;

pub const MAGIC: &[u8; 4] = b"SVLT";
pub const FORMAT_VERSION: u8 = 1;

/// Layout:
///   [4]  magic
///   [1]  version
///   [32] salt
///   [4]  m_cost (u32 LE)
///   [4]  t_cost (u32 LE)
///   [4]  p_cost (u32 LE)
///   [12] nonce
///   ---- total: 61 bytes
///   [N]  ciphertext + 16-byte GCM tag
pub const HEADER_SIZE: usize = 4 + 1 + SALT_SIZE + 4 + 4 + 4 + NONCE_SIZE;

/// Parsed vault header.
pub struct VaultHeader {
    pub salt: [u8; SALT_SIZE],
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub nonce: [u8; NONCE_SIZE],
}

/// Serialize the header + ciphertext into bytes.
pub fn encode(header: &VaultHeader, ciphertext: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(HEADER_SIZE + ciphertext.len());
    buf.extend_from_slice(MAGIC);
    buf.push(FORMAT_VERSION);
    buf.extend_from_slice(&header.salt);
    buf.extend_from_slice(&header.m_cost.to_le_bytes());
    buf.extend_from_slice(&header.t_cost.to_le_bytes());
    buf.extend_from_slice(&header.p_cost.to_le_bytes());
    buf.extend_from_slice(&header.nonce);
    buf.extend_from_slice(ciphertext);
    buf
}

/// Parse the binary vault format. Returns `(header, ciphertext)`.
pub fn decode(data: &[u8]) -> Result<(VaultHeader, &[u8]), SerdeVaultError> {
    if data.len() < HEADER_SIZE {
        return Err(SerdeVaultError::InvalidFormat(format!(
            "file too small: {} bytes (minimum is {})",
            data.len(),
            HEADER_SIZE
        )));
    }

    if &data[0..4] != MAGIC {
        return Err(SerdeVaultError::InvalidFormat(
            "invalid magic number — not a serdevault file".to_string(),
        ));
    }

    let version = data[4];
    if version != FORMAT_VERSION {
        return Err(SerdeVaultError::UnsupportedVersion(version));
    }

    let mut salt = [0u8; SALT_SIZE];
    salt.copy_from_slice(&data[5..5 + SALT_SIZE]);

    let o = 5 + SALT_SIZE; // = 37
    let m_cost = u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
    let t_cost = u32::from_le_bytes([data[o + 4], data[o + 5], data[o + 6], data[o + 7]]);
    let p_cost = u32::from_le_bytes([data[o + 8], data[o + 9], data[o + 10], data[o + 11]]);

    let nonce_start = o + 12; // = 49
    let mut nonce = [0u8; NONCE_SIZE];
    nonce.copy_from_slice(&data[nonce_start..nonce_start + NONCE_SIZE]);

    let ciphertext = &data[HEADER_SIZE..];

    Ok((
        VaultHeader {
            salt,
            m_cost,
            t_cost,
            p_cost,
            nonce,
        },
        ciphertext,
    ))
}

/// Write vault bytes to disk atomically.
pub fn atomic_write(path: &Path, data: &[u8]) -> Result<(), SerdeVaultError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)?;

    let mut tmp = NamedTempFile::new_in(parent)?;
    tmp.write_all(data)?;
    tmp.flush()?;
    tmp.as_file().sync_all()?;

    tmp.persist(path)
        .map_err(|e| SerdeVaultError::IoError(e.error))?;

    Ok(())
}
