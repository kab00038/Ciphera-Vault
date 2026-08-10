use keyring::Entry;
use sha2::{Digest, Sha256};
use std::path::Path;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const SERVICE: &str = "com.ciphera.vault.quick-unlock";

#[derive(Debug, Error)]
pub enum SecureStorageError {
    #[error("OS secure storage is unavailable")]
    Unavailable,
    #[error("quick unlock is not configured for this vault")]
    NotConfigured,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct QuickUnlockSecret(String);

impl QuickUnlockSecret {
    pub fn expose(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct QuickUnlockStore;

impl QuickUnlockStore {
    pub fn save(&self, vault_path: &Path, master_password: &str) -> Result<(), SecureStorageError> {
        credential(vault_path)?
            .set_password(master_password)
            .map_err(|_| SecureStorageError::Unavailable)
    }

    pub fn load(&self, vault_path: &Path) -> Result<QuickUnlockSecret, SecureStorageError> {
        match credential(vault_path)?.get_password() {
            Ok(password) => Ok(QuickUnlockSecret(password)),
            Err(keyring::Error::NoEntry) => Err(SecureStorageError::NotConfigured),
            Err(_) => Err(SecureStorageError::Unavailable),
        }
    }

    pub fn remove(&self, vault_path: &Path) -> Result<(), SecureStorageError> {
        match credential(vault_path)?.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(_) => Err(SecureStorageError::Unavailable),
        }
    }
}

fn credential(vault_path: &Path) -> Result<Entry, SecureStorageError> {
    let absolute = if vault_path.is_absolute() {
        vault_path.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|directory| directory.join(vault_path))
            .unwrap_or_else(|_| vault_path.to_path_buf())
    };
    let stable_path = absolute.canonicalize().unwrap_or_else(|_| {
        let parent = absolute
            .parent()
            .and_then(|path| path.canonicalize().ok())
            .unwrap_or_else(|| absolute.parent().unwrap_or(Path::new("")).to_path_buf());
        absolute
            .file_name()
            .map(|name| parent.join(name))
            .unwrap_or(absolute)
    });
    let account = hex_digest(stable_path.as_os_str().as_encoded_bytes());
    Entry::new(SERVICE, &account).map_err(|_| SecureStorageError::Unavailable)
}

fn hex_digest(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write;
        let _ = write!(output, "{byte:02x}");
    }
    output
}
