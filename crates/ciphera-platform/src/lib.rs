use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use keyring::Entry;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

const QUICK_UNLOCK_SERVICE: &str = "com.ciphera.vault.quick-unlock";
const PIN_UNLOCK_SERVICE: &str = "com.ciphera.vault.pin-unlock";
const MAX_PIN_ATTEMPTS: u8 = 5;
const PIN_COOLDOWNS_SECONDS: [u64; 4] = [2, 5, 15, 60];

#[derive(Debug, Error)]
pub enum SecureStorageError {
    #[error("OS secure storage is unavailable")]
    Unavailable,
    #[error("PIN quick unlock is not configured for this vault")]
    NotConfigured,
    #[error("PIN must contain exactly 4 or 6 digits")]
    InvalidPinFormat,
    #[error("Incorrect PIN. {attempts_remaining} attempts remaining; retry in {retry_after_seconds} seconds")]
    InvalidPin {
        attempts_remaining: u8,
        retry_after_seconds: u64,
    },
    #[error("Too many PIN attempts. Unlock with the master password to re-enable PIN unlock")]
    MasterPasswordRequired,
    #[error("Wait {retry_after_seconds} seconds before trying the PIN again")]
    RateLimited { retry_after_seconds: u64 },
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
        credential(QUICK_UNLOCK_SERVICE, vault_path)?
            .set_password(master_password)
            .map_err(|_| SecureStorageError::Unavailable)
    }

    pub fn load(&self, vault_path: &Path) -> Result<QuickUnlockSecret, SecureStorageError> {
        match credential(QUICK_UNLOCK_SERVICE, vault_path)?.get_password() {
            Ok(password) => Ok(QuickUnlockSecret(password)),
            Err(keyring::Error::NoEntry) => Err(SecureStorageError::NotConfigured),
            Err(_) => Err(SecureStorageError::Unavailable),
        }
    }

    pub fn remove(&self, vault_path: &Path) -> Result<(), SecureStorageError> {
        remove_credential(QUICK_UNLOCK_SERVICE, vault_path)
    }
}

#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PinUnlockStatus {
    pub configured: bool,
    pub attempts_remaining: u8,
    pub retry_after_seconds: u64,
    pub master_password_required: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PinRecord {
    password_hash: String,
    failed_attempts: u8,
    retry_after_unix: u64,
    master_password_required: bool,
}

impl PinRecord {
    fn status(&self, now: u64) -> PinUnlockStatus {
        PinUnlockStatus {
            configured: true,
            attempts_remaining: MAX_PIN_ATTEMPTS.saturating_sub(self.failed_attempts),
            retry_after_seconds: self.retry_after_unix.saturating_sub(now),
            master_password_required: self.master_password_required,
        }
    }

    fn verify(&mut self, pin: &str, now: u64) -> Result<(), SecureStorageError> {
        validate_pin(pin)?;
        if self.master_password_required {
            return Err(SecureStorageError::MasterPasswordRequired);
        }
        if now < self.retry_after_unix {
            return Err(SecureStorageError::RateLimited {
                retry_after_seconds: self.retry_after_unix - now,
            });
        }
        let valid = PasswordHash::new(&self.password_hash)
            .ok()
            .and_then(|hash| {
                Argon2::default()
                    .verify_password(pin.as_bytes(), &hash)
                    .ok()
            })
            .is_some();
        if valid {
            self.failed_attempts = 0;
            self.retry_after_unix = 0;
            return Ok(());
        }

        self.failed_attempts = self.failed_attempts.saturating_add(1);
        if self.failed_attempts >= MAX_PIN_ATTEMPTS {
            self.master_password_required = true;
            self.retry_after_unix = 0;
            return Err(SecureStorageError::MasterPasswordRequired);
        }
        let retry_after_seconds =
            PIN_COOLDOWNS_SECONDS[usize::from(self.failed_attempts.saturating_sub(1))];
        self.retry_after_unix = now.saturating_add(retry_after_seconds);
        Err(SecureStorageError::InvalidPin {
            attempts_remaining: MAX_PIN_ATTEMPTS - self.failed_attempts,
            retry_after_seconds,
        })
    }

    fn reset_attempts(&mut self) {
        self.failed_attempts = 0;
        self.retry_after_unix = 0;
        self.master_password_required = false;
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct PinUnlockStore;

impl PinUnlockStore {
    pub fn configure(&self, vault_path: &Path, pin: &str) -> Result<(), SecureStorageError> {
        validate_pin(pin)?;
        let mut salt = [0_u8; 16];
        rand::rng().fill_bytes(&mut salt);
        let salt = SaltString::encode_b64(&salt).map_err(|_| SecureStorageError::Unavailable)?;
        let password_hash = Argon2::default()
            .hash_password(pin.as_bytes(), &salt)
            .map_err(|_| SecureStorageError::Unavailable)?
            .to_string();
        self.save(
            vault_path,
            &PinRecord {
                password_hash,
                failed_attempts: 0,
                retry_after_unix: 0,
                master_password_required: false,
            },
        )
    }

    pub fn verify(&self, vault_path: &Path, pin: &str) -> Result<(), SecureStorageError> {
        let mut record = self.load(vault_path)?;
        let result = record.verify(pin, unix_time());
        self.save(vault_path, &record)?;
        result
    }

    pub fn status(&self, vault_path: &Path) -> PinUnlockStatus {
        self.load(vault_path)
            .map(|record| record.status(unix_time()))
            .unwrap_or_default()
    }

    pub fn reset_after_master_password(&self, vault_path: &Path) -> Result<(), SecureStorageError> {
        let mut record = match self.load(vault_path) {
            Ok(record) => record,
            Err(SecureStorageError::NotConfigured) => return Ok(()),
            Err(error) => return Err(error),
        };
        record.reset_attempts();
        self.save(vault_path, &record)
    }

    pub fn remove(&self, vault_path: &Path) -> Result<(), SecureStorageError> {
        remove_credential(PIN_UNLOCK_SERVICE, vault_path)
    }

    fn load(&self, vault_path: &Path) -> Result<PinRecord, SecureStorageError> {
        match credential(PIN_UNLOCK_SERVICE, vault_path)?.get_password() {
            Ok(value) => serde_json::from_str(&value).map_err(|_| SecureStorageError::Unavailable),
            Err(keyring::Error::NoEntry) => Err(SecureStorageError::NotConfigured),
            Err(_) => Err(SecureStorageError::Unavailable),
        }
    }

    fn save(&self, vault_path: &Path, record: &PinRecord) -> Result<(), SecureStorageError> {
        let value = serde_json::to_string(record).map_err(|_| SecureStorageError::Unavailable)?;
        credential(PIN_UNLOCK_SERVICE, vault_path)?
            .set_password(&value)
            .map_err(|_| SecureStorageError::Unavailable)
    }
}

fn validate_pin(pin: &str) -> Result<(), SecureStorageError> {
    if matches!(pin.len(), 4 | 6) && pin.bytes().all(|byte| byte.is_ascii_digit()) {
        Ok(())
    } else {
        Err(SecureStorageError::InvalidPinFormat)
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn remove_credential(service: &str, vault_path: &Path) -> Result<(), SecureStorageError> {
    match credential(service, vault_path)?.delete_credential() {
        Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(_) => Err(SecureStorageError::Unavailable),
    }
}

fn credential(service: &str, vault_path: &Path) -> Result<Entry, SecureStorageError> {
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
    Entry::new(service, &account).map_err(|_| SecureStorageError::Unavailable)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn record_for(pin: &str) -> PinRecord {
        let salt = SaltString::encode_b64(b"fixed test salt").expect("salt");
        PinRecord {
            password_hash: Argon2::default()
                .hash_password(pin.as_bytes(), &salt)
                .expect("hash PIN")
                .to_string(),
            failed_attempts: 0,
            retry_after_unix: 0,
            master_password_required: false,
        }
    }

    #[test]
    fn accepts_only_four_or_six_ascii_digits() {
        for valid in ["1234", "123456"] {
            assert!(validate_pin(valid).is_ok());
        }
        for invalid in ["123", "12345", "1234567", "12a4", "１２３４"] {
            assert!(matches!(
                validate_pin(invalid),
                Err(SecureStorageError::InvalidPinFormat)
            ));
        }
    }

    #[test]
    fn failed_pin_attempts_are_delayed_and_require_master_password() {
        let mut record = record_for("123456");
        let mut now = 1_000;
        for expected_remaining in (1..MAX_PIN_ATTEMPTS).rev() {
            let error = record.verify("654321", now).expect_err("incorrect PIN");
            assert!(matches!(
                error,
                SecureStorageError::InvalidPin {
                    attempts_remaining,
                    ..
                } if attempts_remaining == expected_remaining
            ));
            now = record.retry_after_unix;
        }
        assert!(matches!(
            record.verify("654321", now),
            Err(SecureStorageError::MasterPasswordRequired)
        ));
        assert!(matches!(
            record.verify("123456", now),
            Err(SecureStorageError::MasterPasswordRequired)
        ));
        record.reset_attempts();
        assert!(record.verify("123456", now).is_ok());
    }

    #[test]
    fn pin_rate_limit_is_enforced_before_hash_verification() {
        let mut record = record_for("1234");
        let start = 2_000;
        let _ = record.verify("9999", start);
        assert!(matches!(
            record.verify("1234", start + 1),
            Err(SecureStorageError::RateLimited {
                retry_after_seconds: 1
            })
        ));
    }
}
