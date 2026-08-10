mod error;
mod model;

pub use error::VaultError;
pub use model::{
    AttachmentSummary, BackupInfo, EntryCategory, EntryDetail, EntryHistory, EntryInput,
    EntrySummary, Group, KdfParameters, PasswordHealth, TotpCode, VaultInfo,
};

use atomic_write_file::AtomicWriteFile;
use chrono::{DateTime, Utc};
use keepass::{
    config::{
        CompressionConfig, DatabaseConfig, DatabaseVersion, InnerCipherConfig, KdfConfig,
        OuterCipherConfig,
    },
    db::{fields, DatabaseOpenError, EntryId, Times, Value},
    Database, DatabaseKey,
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    hint::black_box,
    io::Write,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use url::Url;
use uuid::Uuid;

const FIELD_CATEGORY: &str = "Ciphera.Category";
const FIELD_FAVORITE: &str = "Ciphera.Favorite";
const DEFAULT_KDF_TARGET: Duration = Duration::from_millis(350);
const DESKTOP_KDF_MEMORY: u64 = 64 * 1024 * 1024;
const MOBILE_KDF_MEMORY: u64 = 32 * 1024 * 1024;
const MAX_KDF_ITERATIONS: u64 = 10;
const MAX_BACKUPS: usize = 5;
const MAX_ATTACHMENT_BYTES: usize = 20 * 1024 * 1024;

struct UnlockedVault {
    path: PathBuf,
    database: Database,
    key: DatabaseKey,
    disk_hash: Option<[u8; 32]>,
}

#[derive(Default)]
pub struct Vault {
    unlocked: Option<UnlockedVault>,
}

impl Vault {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_unlocked(&self) -> bool {
        self.unlocked.is_some()
    }

    pub fn create(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<VaultInfo, VaultError> {
        self.create_with_parameters(path, password, calibrate_argon2id())
    }

    pub fn create_with_parameters(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
        kdf: KdfParameters,
    ) -> Result<VaultInfo, VaultError> {
        validate_password(password)?;
        let path = normalize_new_path(path.as_ref())?;
        if path.exists() {
            return Err(VaultError::AlreadyExists(path));
        }
        ensure_private_parent(&path)?;

        let mut config = DatabaseConfig::default();
        config.version = keepass::config::DatabaseVersion::KDB4(1);
        config.outer_cipher_config = OuterCipherConfig::AES256;
        config.compression_config = CompressionConfig::GZip;
        config.inner_cipher_config = InnerCipherConfig::ChaCha20;
        config.kdf_config = KdfConfig::Argon2id {
            iterations: kdf.iterations,
            memory: kdf.memory_bytes,
            parallelism: kdf.parallelism,
            version: argon2::Version::Version13,
        };
        let mut database = Database::with_config(config);
        database.meta.database_name = Some("Ciphera Vault".to_owned());
        database.root_mut().name = "Ciphera Vault".to_owned();
        let key = DatabaseKey::new().with_password(password);
        let bytes = serialize_and_verify(&database, &key)?;
        atomic_write_private(&path, &bytes)?;
        let disk_hash = Some(hash_bytes(&bytes));
        self.unlocked = Some(UnlockedVault {
            path,
            database,
            key,
            disk_hash,
        });
        self.info()
    }

    pub fn open(
        &mut self,
        path: impl AsRef<Path>,
        password: &str,
    ) -> Result<VaultInfo, VaultError> {
        validate_password(password)?;
        let path = path.as_ref().to_path_buf();
        if !path.is_file() {
            return Err(VaultError::NotFound(path));
        }
        let bytes = fs::read(&path)?;
        let key = DatabaseKey::new().with_password(password);
        let mut database = Database::parse(&bytes, key.clone()).map_err(map_open_error)?;
        database.config.version = DatabaseVersion::KDB4(1);
        let disk_hash = Some(hash_bytes(&bytes));
        self.unlocked = Some(UnlockedVault {
            path,
            database,
            key,
            disk_hash,
        });
        self.info()
    }

    pub fn lock(&mut self) {
        self.unlocked = None;
    }

    pub fn close(&mut self) {
        self.lock();
    }

    pub fn info(&self) -> Result<VaultInfo, VaultError> {
        let state = self.state()?;
        Ok(VaultInfo {
            path: state.path.display().to_string(),
            name: state
                .database
                .meta
                .database_name
                .clone()
                .unwrap_or_else(|| "Vault".to_owned()),
            entry_count: state.database.num_entries(),
            kdf: kdf_parameters(&state.database.config.kdf_config),
        })
    }

    pub fn groups(&self) -> Result<Vec<Group>, VaultError> {
        let state = self.state()?;
        let mut groups: Vec<_> = state
            .database
            .iter_all_groups()
            .map(|group| Group {
                id: group.id().to_string(),
                parent_id: group.parent().map(|parent| parent.id().to_string()),
                name: group.name.clone(),
            })
            .collect();
        groups.sort_by_key(|group| group.name.to_lowercase());
        Ok(groups)
    }

    pub fn create_group(
        &mut self,
        parent_id: Option<&str>,
        name: &str,
    ) -> Result<Group, VaultError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(VaultError::EmptyGroupName);
        }
        let state = self.state_mut()?;
        let parent_id = match parent_id {
            Some(id) => parse_group_id(id)?,
            None => state.database.root().id(),
        };
        let previous = state.database.clone();
        let created = {
            let mut parent = state
                .database
                .group_mut(parent_id)
                .ok_or(VaultError::GroupNotFound)?;
            let mut group = parent.add_group();
            group.name = name.to_owned();
            Group {
                id: group.id().to_string(),
                parent_id: Some(parent_id.to_string()),
                name: group.name.clone(),
            }
        };
        if let Err(error) = save_state(state) {
            state.database = previous;
            return Err(error);
        }
        Ok(created)
    }

    pub fn rename_group(&mut self, id: &str, name: &str) -> Result<Group, VaultError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(VaultError::EmptyGroupName);
        }
        let group_id = parse_group_id(id)?;
        let state = self.state_mut()?;
        if group_id == state.database.root().id() {
            return Err(VaultError::RootGroupProtected);
        }
        let parent_id = state
            .database
            .group(group_id)
            .ok_or(VaultError::GroupNotFound)?
            .parent()
            .map(|parent| parent.id().to_string());
        let previous = state.database.clone();
        let renamed = {
            let mut group = state
                .database
                .group_mut(group_id)
                .ok_or(VaultError::GroupNotFound)?;
            group.name = name.to_owned();
            group.times.last_modification = Some(Times::now());
            Group {
                id: group.id().to_string(),
                parent_id,
                name: group.name.clone(),
            }
        };
        if let Err(error) = save_state(state) {
            state.database = previous;
            return Err(error);
        }
        Ok(renamed)
    }

    pub fn delete_group(&mut self, id: &str) -> Result<(), VaultError> {
        let group_id = parse_group_id(id)?;
        let state = self.state_mut()?;
        if group_id == state.database.root().id() {
            return Err(VaultError::RootGroupProtected);
        }
        let group = state
            .database
            .group(group_id)
            .ok_or(VaultError::GroupNotFound)?;
        if group.group_ids().next().is_some() || group.entry_ids().next().is_some() {
            return Err(VaultError::GroupNotEmpty);
        }
        let previous = state.database.clone();
        state
            .database
            .group_mut(group_id)
            .ok_or(VaultError::GroupNotFound)?
            .track_changes()
            .remove()
            .map_err(|_| VaultError::RootGroupProtected)?;
        if let Err(error) = save_state(state) {
            state.database = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn list_entries(&self, query: Option<&str>) -> Result<Vec<EntrySummary>, VaultError> {
        let state = self.state()?;
        let normalized_query = query.unwrap_or_default().trim().to_lowercase();
        let reuse_counts = password_reuse_counts(&state.database);
        let mut entries: Vec<_> = state
            .database
            .iter_all_entries()
            .filter_map(|entry| {
                let title = entry.get(fields::TITLE).unwrap_or_default();
                let username = entry.get(fields::USERNAME).unwrap_or_default();
                let url = entry.get(fields::URL).unwrap_or_default();
                if !normalized_query.is_empty()
                    && !format!("{title} {username} {url}")
                        .to_lowercase()
                        .contains(&normalized_query)
                {
                    return None;
                }
                Some(entry_summary(&entry, &reuse_counts))
            })
            .collect();
        entries.sort_by_key(|entry| entry.title.to_lowercase());
        Ok(entries)
    }

    pub fn get_entry(&self, id: &str) -> Result<EntryDetail, VaultError> {
        let state = self.state()?;
        let entry_id = parse_entry_id(id)?;
        let entry = state
            .database
            .entry(entry_id)
            .ok_or(VaultError::EntryNotFound)?;
        let reuse_counts = password_reuse_counts(&state.database);
        Ok(EntryDetail {
            summary: entry_summary(&entry, &reuse_counts),
            password: entry.get(fields::PASSWORD).unwrap_or_default().to_owned(),
            notes: entry.get(fields::NOTES).unwrap_or_default().to_owned(),
            totp: entry.get(fields::OTP).map(ToOwned::to_owned),
            attachments: attachment_summaries(&entry),
        })
    }

    pub fn totp_codes(&self) -> Result<Vec<TotpCode>, VaultError> {
        let state = self.state()?;
        let mut codes: Vec<_> = state
            .database
            .iter_all_entries()
            .filter_map(|entry| {
                let otp = entry.get_otp().ok()?;
                let current = otp.value_now().ok()?;
                Some(TotpCode {
                    id: entry.id().to_string(),
                    title: entry.get(fields::TITLE).unwrap_or_default().to_owned(),
                    username: entry.get(fields::USERNAME).unwrap_or_default().to_owned(),
                    code: current.code,
                    valid_for: current.valid_for.as_secs(),
                    period: current.period.as_secs(),
                })
            })
            .collect();
        codes.sort_by_key(|code| code.title.to_lowercase());
        Ok(codes)
    }

    pub fn add_entry(&mut self, input: EntryInput) -> Result<EntryDetail, VaultError> {
        validate_input(&input)?;
        let state = self.state_mut()?;
        let group_id = match input.group_id.as_deref() {
            Some(id) => parse_group_id(id)?,
            None => state.database.root().id(),
        };
        let previous = state.database.clone();
        let entry_id = {
            let mut group = state
                .database
                .group_mut(group_id)
                .ok_or(VaultError::GroupNotFound)?;
            let mut entry = group.add_entry();
            apply_input(&mut entry, &input);
            entry.id()
        };
        if let Err(error) = save_state(state) {
            state.database = previous;
            return Err(error);
        }
        self.get_entry(&entry_id.to_string())
    }

    pub fn update_entry(&mut self, id: &str, input: EntryInput) -> Result<EntryDetail, VaultError> {
        validate_input(&input)?;
        let entry_id = parse_entry_id(id)?;
        let state = self.state_mut()?;
        let previous = state.database.clone();
        {
            let mut entry = state
                .database
                .entry_mut(entry_id)
                .ok_or(VaultError::EntryNotFound)?;
            let mut tracked = entry.track_changes();
            apply_input(&mut tracked, &input);
            tracked.times.last_modification = Some(Times::now());
            if let Some(group_id) = input.group_id.as_deref() {
                tracked
                    .move_to(parse_group_id(group_id)?)
                    .map_err(|_| VaultError::GroupNotFound)?;
            }
        }
        if let Err(error) = save_state(state) {
            state.database = previous;
            return Err(error);
        }
        self.get_entry(id)
    }

    pub fn delete_entry(&mut self, id: &str) -> Result<(), VaultError> {
        let entry_id = parse_entry_id(id)?;
        let state = self.state_mut()?;
        let previous = state.database.clone();
        {
            let mut entry = state
                .database
                .entry_mut(entry_id)
                .ok_or(VaultError::EntryNotFound)?;
            entry.track_changes().remove();
        }
        if let Err(error) = save_state(state) {
            state.database = previous;
            return Err(error);
        }
        Ok(())
    }

    pub fn entry_history(&self, id: &str) -> Result<Vec<EntryHistory>, VaultError> {
        let state = self.state()?;
        let entry = state
            .database
            .entry(parse_entry_id(id)?)
            .ok_or(VaultError::EntryNotFound)?;
        let history_len = entry
            .history
            .as_ref()
            .map(|history| history.get_entries().len())
            .unwrap_or_default();
        Ok((0..history_len)
            .filter_map(|index| {
                let historical = entry.historical(index)?;
                Some(EntryHistory {
                    index,
                    title: historical.get(fields::TITLE).unwrap_or_default().to_owned(),
                    username: historical
                        .get(fields::USERNAME)
                        .unwrap_or_default()
                        .to_owned(),
                    url: historical.get(fields::URL).unwrap_or_default().to_owned(),
                    updated_at: historical
                        .times
                        .last_modification
                        .map(|time| format!("{}Z", time.format("%Y-%m-%dT%H:%M:%S"))),
                })
            })
            .collect())
    }

    pub fn restore_entry_history(
        &mut self,
        id: &str,
        index: usize,
    ) -> Result<EntryDetail, VaultError> {
        let entry_id = parse_entry_id(id)?;
        let input = {
            let state = self.state()?;
            let entry = state
                .database
                .entry(entry_id)
                .ok_or(VaultError::EntryNotFound)?;
            let historical = entry
                .historical(index)
                .ok_or(VaultError::HistoryNotFound)?;
            EntryInput {
                group_id: None,
                title: historical.get(fields::TITLE).unwrap_or_default().to_owned(),
                username: historical
                    .get(fields::USERNAME)
                    .unwrap_or_default()
                    .to_owned(),
                password: historical
                    .get(fields::PASSWORD)
                    .unwrap_or_default()
                    .to_owned(),
                url: historical.get(fields::URL).unwrap_or_default().to_owned(),
                notes: historical.get(fields::NOTES).unwrap_or_default().to_owned(),
                category: EntryCategory::from_field(historical.get(FIELD_CATEGORY)),
                favorite: historical.get(FIELD_FAVORITE) == Some("true"),
                totp: historical.get(fields::OTP).map(ToOwned::to_owned),
            }
        };
        self.update_entry(id, input)
    }

    pub fn add_attachment(
        &mut self,
        id: &str,
        name: &str,
        data: Vec<u8>,
    ) -> Result<EntryDetail, VaultError> {
        let name = name.trim();
        if name.is_empty() {
            return Err(VaultError::EmptyAttachmentName);
        }
        if data.len() > MAX_ATTACHMENT_BYTES {
            return Err(VaultError::AttachmentTooLarge);
        }
        let entry_id = parse_entry_id(id)?;
        let state = self.state_mut()?;
        let previous = state.database.clone();
        {
            let mut entry = state
                .database
                .entry_mut(entry_id)
                .ok_or(VaultError::EntryNotFound)?;
            entry
                .track_changes()
                .add_attachment(name, Value::unprotected(data));
        }
        if let Err(error) = save_state(state) {
            state.database = previous;
            return Err(error);
        }
        self.get_entry(id)
    }

    pub fn attachment(&self, id: &str, name: &str) -> Result<Vec<u8>, VaultError> {
        let state = self.state()?;
        let entry = state
            .database
            .entry(parse_entry_id(id)?)
            .ok_or(VaultError::EntryNotFound)?;
        entry
            .attachment_by_name(name)
            .map(|attachment| attachment.get().clone())
            .ok_or(VaultError::AttachmentNotFound)
    }

    pub fn remove_attachment(&mut self, id: &str, name: &str) -> Result<EntryDetail, VaultError> {
        let entry_id = parse_entry_id(id)?;
        let state = self.state_mut()?;
        let previous = state.database.clone();
        {
            let mut entry = state
                .database
                .entry_mut(entry_id)
                .ok_or(VaultError::EntryNotFound)?;
            if entry.as_ref().attachment_by_name(name).is_none() {
                return Err(VaultError::AttachmentNotFound);
            }
            let mut tracked = entry.track_changes();
            tracked.as_mut().remove_attachment_by_name(name);
            tracked.times.last_modification = Some(Times::now());
        }
        if let Err(error) = save_state(state) {
            state.database = previous;
            return Err(error);
        }
        self.get_entry(id)
    }

    pub fn backups(&self) -> Result<Vec<BackupInfo>, VaultError> {
        let state = self.state()?;
        Ok((0..MAX_BACKUPS)
            .filter_map(|index| {
                let path = backup_path_at(&state.path, index);
                let metadata = fs::metadata(&path).ok()?;
                let modified_at = metadata.modified().ok().map(|modified| {
                    DateTime::<Utc>::from(modified).to_rfc3339()
                });
                Some(BackupInfo {
                    index,
                    path: path.display().to_string(),
                    size: metadata.len(),
                    modified_at,
                })
            })
            .collect())
    }

    pub fn restore_backup(&mut self, index: usize) -> Result<VaultInfo, VaultError> {
        if index >= MAX_BACKUPS {
            return Err(VaultError::BackupNotFound);
        }
        let state = self.state_mut()?;
        let backup = backup_path_at(&state.path, index);
        if !backup.is_file() {
            return Err(VaultError::BackupNotFound);
        }
        let current = fs::read(&state.path)?;
        if state
            .disk_hash
            .is_some_and(|expected| hash_bytes(&current) != expected)
        {
            return Err(VaultError::ExternalModification);
        }
        let bytes = fs::read(backup)?;
        let mut database =
            Database::parse(&bytes, state.key.clone()).map_err(map_open_error)?;
        database.config.version = DatabaseVersion::KDB4(1);
        rotate_backups(&state.path, &current)?;
        atomic_write_private(&state.path, &bytes)?;
        state.database = database;
        state.disk_hash = Some(hash_bytes(&bytes));
        self.info()
    }

    pub fn save(&mut self) -> Result<(), VaultError> {
        save_state(self.state_mut()?)
    }

    pub fn change_password(
        &mut self,
        current_password: &str,
        new_password: &str,
    ) -> Result<(), VaultError> {
        validate_password(new_password)?;
        let state = self.state_mut()?;
        let current_bytes = fs::read(&state.path)?;
        Database::parse(
            &current_bytes,
            DatabaseKey::new().with_password(current_password),
        )
        .map_err(map_open_error)?;
        let previous_key = state.key.clone();
        state.key = DatabaseKey::new().with_password(new_password);
        if let Err(error) = save_state(state) {
            state.key = previous_key;
            return Err(error);
        }
        Ok(())
    }

    fn state(&self) -> Result<&UnlockedVault, VaultError> {
        self.unlocked.as_ref().ok_or(VaultError::Locked)
    }

    fn state_mut(&mut self) -> Result<&mut UnlockedVault, VaultError> {
        self.unlocked.as_mut().ok_or(VaultError::Locked)
    }
}

pub fn normalize_origin(value: &str) -> Option<String> {
    let candidate = if value.contains("://") {
        value.to_owned()
    } else {
        format!("https://{value}")
    };
    let url = Url::parse(&candidate).ok()?;
    let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
    let port = url.port();
    Some(match port {
        Some(port) => format!("{}://{host}:{port}", url.scheme().to_ascii_lowercase()),
        None => format!("{}://{host}", url.scheme().to_ascii_lowercase()),
    })
}

pub fn origin_matches(entry_url: &str, requested_url: &str) -> bool {
    let Some(entry) = normalize_origin(entry_url) else {
        return false;
    };
    let Some(requested) = normalize_origin(requested_url) else {
        return false;
    };
    entry == requested
}

pub fn calibrate_argon2id() -> KdfParameters {
    let memory_bytes = if cfg!(any(target_os = "android", target_os = "ios")) {
        MOBILE_KDF_MEMORY
    } else {
        DESKTOP_KDF_MEMORY
    };
    let memory_kib = (memory_bytes / 1024) as u32;
    let parallelism = std::thread::available_parallelism()
        .map(|value| value.get() as u32)
        .unwrap_or(1)
        .clamp(1, 4);
    let config = argon2::Config {
        variant: argon2::Variant::Argon2id,
        version: argon2::Version::Version13,
        mem_cost: memory_kib,
        time_cost: 1,
        lanes: parallelism,
        thread_mode: argon2::ThreadMode::Parallel,
        secret: &[],
        ad: &[],
        hash_length: 32,
    };
    let started = Instant::now();
    let sample = argon2::hash_raw(b"ciphera-calibration", b"ciphera-kdf-salt", &config)
        .unwrap_or_else(|_| vec![0; 32]);
    black_box(sample);
    let elapsed = started.elapsed().max(Duration::from_millis(1));
    let scaled = (DEFAULT_KDF_TARGET.as_millis() / elapsed.as_millis()).max(1) as u64;
    KdfParameters {
        memory_bytes,
        iterations: scaled.clamp(2, MAX_KDF_ITERATIONS),
        parallelism,
    }
}

fn validate_password(password: &str) -> Result<(), VaultError> {
    if password.is_empty() {
        Err(VaultError::EmptyPassword)
    } else {
        Ok(())
    }
}

fn validate_input(input: &EntryInput) -> Result<(), VaultError> {
    if input.title.trim().is_empty() {
        Err(VaultError::EmptyTitle)
    } else {
        Ok(())
    }
}

fn normalize_new_path(path: &Path) -> Result<PathBuf, VaultError> {
    if path.as_os_str().is_empty() || path.file_name().is_none() {
        return Err(VaultError::InvalidPath);
    }
    Ok(path.to_path_buf())
}

fn parse_entry_id(id: &str) -> Result<EntryId, VaultError> {
    Uuid::parse_str(id)
        .map(EntryId::from_uuid)
        .map_err(|_| VaultError::EntryNotFound)
}

fn parse_group_id(id: &str) -> Result<keepass::db::GroupId, VaultError> {
    Uuid::parse_str(id)
        .map(keepass::db::GroupId::from_uuid)
        .map_err(|_| VaultError::GroupNotFound)
}

fn apply_input(entry: &mut keepass::db::Entry, input: &EntryInput) {
    entry.set_unprotected(fields::TITLE, input.title.trim());
    entry.set_unprotected(fields::USERNAME, &input.username);
    entry.set_protected(fields::PASSWORD, &input.password);
    entry.set_unprotected(fields::URL, &input.url);
    entry.set_protected(fields::NOTES, &input.notes);
    entry.set_unprotected(FIELD_CATEGORY, input.category.as_field());
    entry.set_unprotected(
        FIELD_FAVORITE,
        if input.favorite { "true" } else { "false" },
    );
    match input.totp.as_deref().map(str::trim) {
        Some(totp) if !totp.is_empty() => {
            let value = if totp.starts_with("otpauth://") {
                totp.to_owned()
            } else {
                let secret: String = totp
                    .chars()
                    .filter(|character| !character.is_whitespace())
                    .collect();
                format!("otpauth://totp/Ciphera?secret={secret}&period=30&digits=6")
            };
            entry.set_protected(fields::OTP, value);
        }
        _ => {
            entry.fields.remove(fields::OTP);
        }
    }
}

fn entry_summary(
    entry: &keepass::db::EntryRef<'_>,
    reuse_counts: &HashMap<[u8; 32], usize>,
) -> EntrySummary {
    let password = entry.get(fields::PASSWORD).unwrap_or_default();
    let modified = entry.times.last_modification;
    EntrySummary {
        id: entry.id().to_string(),
        group_id: entry.parent().id().to_string(),
        title: entry.get(fields::TITLE).unwrap_or_default().to_owned(),
        username: entry.get(fields::USERNAME).unwrap_or_default().to_owned(),
        url: entry.get(fields::URL).unwrap_or_default().to_owned(),
        category: EntryCategory::from_field(entry.get(FIELD_CATEGORY)),
        favorite: entry.get(FIELD_FAVORITE) == Some("true"),
        health: password_health(password, modified, reuse_counts),
        updated_at: modified.map(|time| format!("{}Z", time.format("%Y-%m-%dT%H:%M:%S"))),
    }
}

fn attachment_summaries(entry: &keepass::db::EntryRef<'_>) -> Vec<AttachmentSummary> {
    let mut attachments: Vec<_> = entry
        .attachments_named()
        .map(|(name, attachment)| AttachmentSummary {
            name: name.to_owned(),
            size: attachment.get().len(),
        })
        .collect();
    attachments.sort_by_key(|attachment| attachment.name.to_lowercase());
    attachments
}

fn password_reuse_counts(database: &Database) -> HashMap<[u8; 32], usize> {
    let mut counts = HashMap::new();
    for entry in database.iter_all_entries() {
        let password = entry.get(fields::PASSWORD).unwrap_or_default();
        if !password.is_empty() {
            *counts.entry(hash_bytes(password.as_bytes())).or_insert(0) += 1;
        }
    }
    counts
}

fn password_health(
    password: &str,
    modified: Option<chrono::NaiveDateTime>,
    reuse_counts: &HashMap<[u8; 32], usize>,
) -> PasswordHealth {
    if !password.is_empty()
        && reuse_counts
            .get(&hash_bytes(password.as_bytes()))
            .copied()
            .unwrap_or_default()
            > 1
    {
        return PasswordHealth::Reused;
    }
    if password.len() < 12
        || !password.chars().any(char::is_uppercase)
        || !password.chars().any(char::is_lowercase)
        || !password.chars().any(|character| character.is_ascii_digit())
    {
        return PasswordHealth::Weak;
    }
    if modified.is_some_and(|time| Utc::now().naive_utc() - time > chrono::Duration::days(365)) {
        return PasswordHealth::Old;
    }
    PasswordHealth::Safe
}

fn kdf_parameters(config: &KdfConfig) -> KdfParameters {
    match config {
        KdfConfig::Argon2id {
            iterations,
            memory,
            parallelism,
            ..
        }
        | KdfConfig::Argon2 {
            iterations,
            memory,
            parallelism,
            ..
        } => KdfParameters {
            memory_bytes: *memory,
            iterations: *iterations,
            parallelism: *parallelism,
        },
        KdfConfig::Aes { rounds } => KdfParameters {
            memory_bytes: 0,
            iterations: *rounds,
            parallelism: 1,
        },
        _ => KdfParameters {
            memory_bytes: 0,
            iterations: 0,
            parallelism: 0,
        },
    }
}

fn save_state(state: &mut UnlockedVault) -> Result<(), VaultError> {
    let existing = state.path.exists().then(|| fs::read(&state.path)).transpose()?;
    if let (Some(expected), Some(current)) = (state.disk_hash, existing.as_ref()) {
        if hash_bytes(current) != expected {
            return Err(VaultError::ExternalModification);
        }
    }
    let bytes = serialize_and_verify(&state.database, &state.key)?;
    if let Some(existing) = existing {
        rotate_backups(&state.path, &existing)?;
    }
    atomic_write_private(&state.path, &bytes)?;
    state.disk_hash = Some(hash_bytes(&bytes));
    Ok(())
}

fn serialize_and_verify(database: &Database, key: &DatabaseKey) -> Result<Vec<u8>, VaultError> {
    let mut bytes = Vec::new();
    database
        .save(&mut bytes, key.clone())
        .map_err(|_| VaultError::Encryption)?;
    let verified = Database::parse(&bytes, key.clone()).map_err(|_| VaultError::Encryption)?;
    if !logical_database_matches(database, &verified) {
        return Err(VaultError::Encryption);
    }
    Ok(bytes)
}

fn logical_database_matches(expected: &Database, actual: &Database) -> bool {
    if expected.num_entries() != actual.num_entries()
        || expected.iter_all_groups().count() != actual.iter_all_groups().count()
    {
        return false;
    }
    for group in expected.iter_all_groups() {
        let Some(other) = actual.group(group.id()) else {
            return false;
        };
        if group.name != other.name
            || group.notes != other.notes
            || group.tags != other.tags
            || group.parent().map(|parent| parent.id())
                != other.parent().map(|parent| parent.id())
        {
            return false;
        }
    }
    for entry in expected.iter_all_entries() {
        let Some(other) = actual.entry(entry.id()) else {
            return false;
        };
        if entry.fields != other.fields
            || entry.tags != other.tags
            || entry.custom_data != other.custom_data
            || entry.override_url != other.override_url
            || entry.quality_check != other.quality_check
            || entry.parent().id() != other.parent().id()
            || entry.attachments().count() != other.attachments().count()
        {
            return false;
        }
        for (name, attachment) in entry.attachments_named() {
            let Some(other_attachment) = other.attachment_by_name(name) else {
                return false;
            };
            if attachment.is_protected() != other_attachment.is_protected()
                || attachment.get() != other_attachment.get()
            {
                return false;
            }
        }
        let expected_history = entry
            .history
            .as_ref()
            .map(|history| history.get_entries().len())
            .unwrap_or_default();
        let actual_history = other
            .history
            .as_ref()
            .map(|history| history.get_entries().len())
            .unwrap_or_default();
        if expected_history != actual_history {
            return false;
        }
        for index in 0..expected_history {
            let (Some(expected_version), Some(actual_version)) =
                (entry.historical(index), other.historical(index))
            else {
                return false;
            };
            if expected_version.fields != actual_version.fields
                || expected_version.tags != actual_version.tags
                || expected_version.custom_data != actual_version.custom_data
            {
                return false;
            }
        }
    }
    true
}

fn map_open_error(error: DatabaseOpenError) -> VaultError {
    match error {
        DatabaseOpenError::Key(_) => VaultError::WrongPassword,
        DatabaseOpenError::Io(error) => VaultError::Io(error),
        _ => VaultError::Corrupted,
    }
}

fn hash_bytes(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn backup_path(path: &Path) -> PathBuf {
    backup_path_at(path, 0)
}

fn backup_path_at(path: &Path, index: usize) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    if index == 0 {
        name.push(".bak");
    } else {
        name.push(format!(".bak.{index}"));
    }
    PathBuf::from(name)
}

fn rotate_backups(path: &Path, current: &[u8]) -> Result<(), VaultError> {
    for index in (1..MAX_BACKUPS).rev() {
        let previous = backup_path_at(path, index - 1);
        if previous.is_file() {
            let bytes = fs::read(previous)?;
            atomic_write_private(&backup_path_at(path, index), &bytes)?;
        }
    }
    atomic_write_private(&backup_path(path), current)
}

fn atomic_write_private(path: &Path, bytes: &[u8]) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = AtomicWriteFile::open(path)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.commit()?;
    set_private_permissions(path)?;
    Ok(())
}

fn ensure_private_parent(path: &Path) -> Result<(), VaultError> {
    if let Some(parent) = path.parent() {
        let existed = parent.exists();
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        if !existed {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
        }
    }
    Ok(())
}

fn set_private_permissions(path: &Path) -> Result<(), VaultError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tempfile::TempDir;

    fn test_kdf() -> KdfParameters {
        KdfParameters {
            memory_bytes: 1024 * 1024,
            iterations: 2,
            parallelism: 1,
        }
    }

    fn login(password: &str) -> EntryInput {
        EntryInput {
            group_id: None,
            title: "Example".to_owned(),
            username: "alex@example.com".to_owned(),
            password: password.to_owned(),
            url: "https://example.com".to_owned(),
            notes: "Private note".to_owned(),
            category: EntryCategory::Login,
            favorite: true,
            totp: Some("JBSWY3DPEHPK3PXP".to_owned()),
        }
    }

    #[test]
    fn create_restart_lock_and_error_boundaries() {
        let directory = TempDir::new().expect("temp directory");
        let path = directory.path().join("vault.kdbx");
        let mut vault = Vault::new();
        vault
            .create_with_parameters(&path, "master password", test_kdf())
            .expect("create vault");
        let created = vault
            .add_entry(login("UniquePassword42"))
            .expect("add entry");
        assert!(path.is_file());
        let encrypted = fs::read(&path).expect("read vault");
        assert!(!encrypted
            .windows(b"UniquePassword42".len())
            .any(|bytes| bytes == b"UniquePassword42"));
        vault.lock();
        assert!(matches!(vault.list_entries(None), Err(VaultError::Locked)));

        let mut reopened = Vault::new();
        assert!(matches!(
            reopened.open(&path, "wrong password"),
            Err(VaultError::WrongPassword)
        ));
        let info = reopened
            .open(&path, "master password")
            .expect("reopen vault");
        assert_eq!(info.entry_count, 1);
        assert_eq!(
            reopened
                .get_entry(&created.summary.id)
                .expect("entry")
                .password,
            "UniquePassword42"
        );
        reopened
            .change_password("master password", "new master password")
            .expect("change master password");
        reopened.lock();
        assert!(matches!(
            reopened.open(&path, "master password"),
            Err(VaultError::WrongPassword)
        ));
        reopened
            .open(&path, "new master password")
            .expect("open with changed password");

        let corrupted_path = directory.path().join("corrupted.kdbx");
        let mut corrupted = encrypted;
        corrupted[0] ^= 0xff;
        fs::write(&corrupted_path, corrupted).expect("write corrupted vault");
        let mut corrupted_vault = Vault::new();
        assert!(matches!(
            corrupted_vault.open(corrupted_path, "master password"),
            Err(VaultError::Corrupted)
        ));
    }

    #[test]
    fn saves_preserve_backup_history_and_deletion_tombstone() {
        let directory = TempDir::new().expect("temp directory");
        let path = directory.path().join("vault.kdbx");
        let mut vault = Vault::new();
        vault
            .create_with_parameters(&path, "master password", test_kdf())
            .expect("create vault");
        let created = vault
            .add_entry(login("FirstPassword42"))
            .expect("add entry");
        vault
            .update_entry(&created.summary.id, login("SecondPassword42"))
            .expect("update entry");

        let backup = backup_path(&path);
        let mut prior = Vault::new();
        prior.open(&backup, "master password").expect("open backup");
        assert_eq!(
            prior
                .get_entry(&created.summary.id)
                .expect("prior entry")
                .password,
            "FirstPassword42"
        );

        vault
            .delete_entry(&created.summary.id)
            .expect("delete entry");
        let bytes = fs::read(&path).expect("read current vault");
        let xml = Database::get_xml(
            &mut Cursor::new(bytes),
            DatabaseKey::new().with_password("master password"),
        )
        .expect("decrypt XML");
        let xml = String::from_utf8(xml).expect("UTF-8 XML");
        assert!(xml.contains("<DeletedObjects>"));
        assert!(xml.contains("<DeletedObject>"));
    }

    #[test]
    fn external_modification_is_never_overwritten() {
        let directory = TempDir::new().expect("temp directory");
        let path = directory.path().join("vault.kdbx");
        let mut vault = Vault::new();
        vault
            .create_with_parameters(&path, "master password", test_kdf())
            .expect("create vault");
        let mut external = fs::read(&path).expect("read vault");
        external.push(0);
        fs::write(&path, &external).expect("external write");
        assert!(matches!(
            vault.save(),
            Err(VaultError::ExternalModification)
        ));
        assert_eq!(fs::read(&path).expect("read unchanged file"), external);
    }

    #[test]
    fn origin_matching_rejects_lookalike_domains() {
        assert!(origin_matches("example.com", "https://example.com/login"));
        assert!(!origin_matches(
            "example.com",
            "https://example.com.attacker.test/login"
        ));
        assert!(!origin_matches("example.com", "http://example.com/login"));
    }

    #[test]
    fn totp_secrets_stay_in_core() {
        let directory = TempDir::new().expect("temp directory");
        let path = directory.path().join("vault.kdbx");
        let mut vault = Vault::new();
        vault
            .create_with_parameters(&path, "master password", test_kdf())
            .expect("create vault");
        vault
            .add_entry(login("UniquePassword42"))
            .expect("add entry");
        let codes = vault.totp_codes().expect("TOTP codes");
        assert_eq!(codes.len(), 1);
        assert_eq!(codes[0].code.len(), 6);
    }

    #[test]
    fn groups_and_attachments_survive_restart() {
        let directory = TempDir::new().expect("temp directory");
        let path = directory.path().join("vault.kdbx");
        let mut vault = Vault::new();
        vault
            .create_with_parameters(&path, "master password", test_kdf())
            .expect("create vault");
        let group = vault
            .create_group(None, "Work")
            .expect("create work group");
        let mut input = login("UniquePassword42");
        input.group_id = Some(group.id.clone());
        let created = vault.add_entry(input).expect("add grouped entry");
        let with_attachment = vault
            .add_attachment(
                &created.summary.id,
                "recovery-codes.txt",
                b"one-time recovery codes".to_vec(),
            )
            .expect("add encrypted attachment");
        assert_eq!(with_attachment.attachments[0].name, "recovery-codes.txt");
        assert!(matches!(
            vault.delete_group(&group.id),
            Err(VaultError::GroupNotEmpty)
        ));

        vault.lock();
        vault
            .open(&path, "master password")
            .expect("reopen vault");
        assert_eq!(
            vault
                .attachment(&created.summary.id, "recovery-codes.txt")
                .expect("read attachment"),
            b"one-time recovery codes"
        );
        let renamed = vault
            .rename_group(&group.id, "Client work")
            .expect("rename group");
        assert_eq!(renamed.name, "Client work");
        vault
            .remove_attachment(&created.summary.id, "recovery-codes.txt")
            .expect("remove attachment");
        let root_id = vault
            .groups()
            .expect("list groups")
            .into_iter()
            .find(|candidate| candidate.parent_id.is_none())
            .expect("root group")
            .id;
        let mut moved = login("UniquePassword42");
        moved.group_id = Some(root_id);
        vault
            .update_entry(&created.summary.id, moved)
            .expect("move entry to root");
        vault.delete_group(&group.id).expect("delete empty group");
    }

    #[test]
    fn history_and_rotating_backups_restore_prior_values() {
        let directory = TempDir::new().expect("temp directory");
        let path = directory.path().join("vault.kdbx");
        let mut vault = Vault::new();
        vault
            .create_with_parameters(&path, "master password", test_kdf())
            .expect("create vault");
        let created = vault
            .add_entry(login("FirstPassword42"))
            .expect("add entry");
        vault
            .update_entry(&created.summary.id, login("SecondPassword42"))
            .expect("first update");
        vault
            .update_entry(&created.summary.id, login("ThirdPassword42"))
            .expect("second update");
        assert_eq!(vault.entry_history(&created.summary.id).expect("history").len(), 2);
        assert!(vault.backups().expect("backups").len() >= 3);

        vault.restore_backup(0).expect("restore most recent backup");
        assert_eq!(
            vault
                .get_entry(&created.summary.id)
                .expect("restored entry")
                .password,
            "SecondPassword42"
        );
        vault
            .restore_entry_history(&created.summary.id, 0)
            .expect("restore first entry version");
        assert_eq!(
            vault
                .get_entry(&created.summary.id)
                .expect("history-restored entry")
                .password,
            "FirstPassword42"
        );
    }

    #[test]
    fn malformed_vault_inputs_fail_without_panicking() {
        let directory = TempDir::new().expect("temp directory");
        for (index, bytes) in [
            Vec::new(),
            vec![0_u8],
            vec![0xff_u8; 31],
            b"not a KDBX database".to_vec(),
        ]
        .into_iter()
        .enumerate()
        {
            let path = directory.path().join(format!("malformed-{index}.kdbx"));
            fs::write(&path, bytes).expect("write malformed input");
            assert!(Vault::new().open(path, "master password").is_err());
        }
    }
}
