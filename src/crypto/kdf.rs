use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use crate::error::SerdeVaultError;

/// Salt size in bytes. 32 bytes = 256 bits (OWASP recommendation for Argon2id).
pub const SALT_SIZE: usize = 32;

/// Output key size in bytes. 32 bytes = 256-bit key for AES-256-GCM.
pub const KEY_SIZE: usize = 32;

/// Argon2id parameters — OWASP 2023 / RFC 9106 recommendation.
pub const ARGON2_M_COST: u32 = 65536; // 64 MB RAM
pub const ARGON2_T_COST: u32 = 3; // 3 iterations
pub const ARGON2_P_COST: u32 = 1; // 1 thread (portable)

/// Derive a 256-bit AES key from a password and a random salt using Argon2id.
pub fn derive_key(
    password: &str,
    salt: &[u8; SALT_SIZE],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Zeroizing<[u8; KEY_SIZE]>, SerdeVaultError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(KEY_SIZE))
        .map_err(|e| SerdeVaultError::KdfError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);

    argon2
        .hash_password_into(password.as_bytes(), salt, key.as_mut())
        .map_err(|e| SerdeVaultError::KdfError(e.to_string()))?;

    Ok(key)
}
