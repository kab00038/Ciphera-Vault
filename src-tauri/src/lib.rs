use ciphera_core::{origin_matches, EntryCategory, EntryInput, Vault, VaultError, VaultInfo};
use ciphera_platform::{PinUnlockStatus, PinUnlockStore, QuickUnlockStore, SecureStorageError};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use tauri::{AppHandle, Manager, State};

const NATIVE_HOST_NAME: &str = "com.ciphera.browser";
const EXTENSION_ID: &str = "nbnpilplfaaigikkigfoeolljlpgknbg";
const MAX_NATIVE_MESSAGE_SIZE: usize = 1024 * 1024;

#[derive(Clone)]
struct AppState {
    descriptor: BridgeDescriptor,
    vault: Arc<Mutex<Vault>>,
    pin_state_lock: Arc<Mutex<()>>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct BridgeDescriptor {
    port: u16,
    token: String,
    pid: u32,
}

#[derive(Deserialize)]
struct BridgeEnvelope {
    token: String,
    request: BrowserRequest,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", tag = "action")]
enum BrowserRequest {
    Status,
    FindLogins { url: String },
    GetLogin { id: String },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct InstallResult {
    extension_id: &'static str,
    extension_directory: String,
    installed_manifests: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CommandError {
    code: &'static str,
    message: String,
}

impl From<VaultError> for CommandError {
    fn from(error: VaultError) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
        }
    }
}

impl From<SecureStorageError> for CommandError {
    fn from(error: SecureStorageError) -> Self {
        let code = match error {
            SecureStorageError::Unavailable => "secure_storage_unavailable",
            SecureStorageError::NotConfigured => "pin_unlock_not_configured",
            SecureStorageError::InvalidPinFormat => "invalid_pin_format",
            SecureStorageError::InvalidPin { .. } => "invalid_pin",
            SecureStorageError::MasterPasswordRequired => "pin_master_password_required",
            SecureStorageError::RateLimited { .. } => "pin_rate_limited",
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct VaultStatus {
    path: String,
    exists: bool,
    unlocked: bool,
    pin_unlock: PinUnlockStatus,
    info: Option<VaultInfo>,
}

fn bridge_data_directory() -> Result<PathBuf, String> {
    dirs::data_local_dir()
        .map(|path| path.join("Ciphera"))
        .ok_or_else(|| "Could not determine the local application data directory".to_string())
}

fn descriptor_path() -> Result<PathBuf, String> {
    Ok(bridge_data_directory()?.join("browser-bridge.json"))
}

fn default_vault_path() -> Result<PathBuf, CommandError> {
    bridge_data_directory()
        .map(|path| path.join("vault.kdbx"))
        .map_err(|message| CommandError {
            code: "invalid_path",
            message,
        })
}

fn requested_vault_path(path: Option<String>) -> Result<PathBuf, CommandError> {
    match path.map(|value| value.trim().to_owned()) {
        Some(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        _ => default_vault_path(),
    }
}

fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let existed = parent.exists();
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        if !existed {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| error.to_string())?;
    file.write_all(contents)
        .map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

fn browser_response(request: BrowserRequest, state: &AppState) -> Value {
    let Ok(vault) = state.vault.lock() else {
        return json!({ "ok": false, "error": "vault_state_unavailable" });
    };
    match request {
        BrowserRequest::Status => json!({
            "ok": true,
            "connected": true,
            "unlocked": vault.is_unlocked(),
            "app": "Ciphera"
        }),
        BrowserRequest::FindLogins { url } => match vault.list_entries(None) {
            Ok(entries) => {
                let matches: Vec<_> = entries
                    .into_iter()
                    .filter(|entry| {
                        entry.category == EntryCategory::Login && origin_matches(&entry.url, &url)
                    })
                    .map(|entry| {
                        json!({
                            "id": entry.id,
                            "title": entry.title,
                            "username": entry.username,
                            "url": entry.url
                        })
                    })
                    .collect();
                json!({ "ok": true, "logins": matches })
            }
            Err(VaultError::Locked) => json!({ "ok": false, "error": "vault_locked" }),
            Err(_) => json!({ "ok": false, "error": "vault_state_unavailable" }),
        },
        BrowserRequest::GetLogin { id } => match vault.get_entry(&id) {
            Ok(entry) if entry.summary.category == EntryCategory::Login => json!({
                "ok": true,
                "login": {
                    "username": entry.summary.username,
                    "password": entry.password
                }
            }),
            Ok(_) | Err(VaultError::EntryNotFound) => {
                json!({ "ok": false, "error": "login_not_found" })
            }
            Err(VaultError::Locked) => json!({ "ok": false, "error": "vault_locked" }),
            Err(_) => json!({ "ok": false, "error": "vault_state_unavailable" }),
        },
    }
}

fn handle_bridge_connection(stream: TcpStream, state: &AppState) -> Result<(), String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    let mut request_line = String::new();
    BufReader::new(stream.try_clone().map_err(|error| error.to_string())?)
        .take((MAX_NATIVE_MESSAGE_SIZE + 1) as u64)
        .read_line(&mut request_line)
        .map_err(|error| error.to_string())?;
    if request_line.len() > MAX_NATIVE_MESSAGE_SIZE {
        return Err("Browser bridge request is too large".to_owned());
    }
    let envelope: BridgeEnvelope = serde_json::from_str(&request_line)
        .map_err(|_| "Malformed browser bridge request".to_string())?;
    let response = if envelope.token == state.descriptor.token {
        browser_response(envelope.request, state)
    } else {
        json!({ "ok": false, "error": "unauthorized" })
    };
    let mut writer = stream;
    serde_json::to_writer(&mut writer, &response).map_err(|error| error.to_string())?;
    writer.write_all(b"\n").map_err(|error| error.to_string())?;
    writer.flush().map_err(|error| error.to_string())
}

fn start_bridge(vault: Arc<Mutex<Vault>>) -> Result<AppState, String> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|error| error.to_string())?;
    let descriptor = BridgeDescriptor {
        port: listener
            .local_addr()
            .map_err(|error| error.to_string())?
            .port(),
        token: random_token(),
        pid: std::process::id(),
    };
    write_private_file(
        &descriptor_path()?,
        &serde_json::to_vec(&descriptor).map_err(|error| error.to_string())?,
    )?;
    let state = AppState {
        descriptor,
        vault,
        pin_state_lock: Arc::new(Mutex::new(())),
    };
    let server_state = state.clone();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let _ = handle_bridge_connection(stream, &server_state);
        }
    });
    Ok(state)
}

#[tauri::command]
fn browser_integration_status(state: State<'_, AppState>) -> Value {
    let unlocked = state
        .vault
        .lock()
        .map(|vault| vault.is_unlocked())
        .unwrap_or(false);
    json!({
        "running": true,
        "hostName": NATIVE_HOST_NAME,
        "extensionId": EXTENSION_ID,
        "port": state.descriptor.port,
        "unlocked": unlocked,
        "descriptorPath": descriptor_path().ok().map(|path| path.display().to_string())
    })
}

#[tauri::command]
fn vault_status(
    path: Option<String>,
    state: State<'_, AppState>,
) -> Result<VaultStatus, CommandError> {
    let path = requested_vault_path(path)?;
    let vault = state.vault.lock().map_err(|_| CommandError {
        code: "vault_state_unavailable",
        message: "Vault state is unavailable".to_owned(),
    })?;
    let unlocked = vault.is_unlocked();
    let info = if unlocked { vault.info().ok() } else { None };
    let path = info
        .as_ref()
        .map(|info| PathBuf::from(&info.path))
        .unwrap_or(path);
    let pin_unlock = PinUnlockStore.status(&path);
    if !pin_unlock.configured {
        // Remove legacy zero-interaction quick-unlock secrets during the PIN-only cutover.
        let _ = QuickUnlockStore.remove(&path);
    }
    Ok(VaultStatus {
        path: path.display().to_string(),
        exists: path.is_file(),
        unlocked,
        pin_unlock,
        info,
    })
}

#[tauri::command]
fn create_vault(
    path: Option<String>,
    password: String,
    state: State<'_, AppState>,
) -> Result<VaultInfo, CommandError> {
    let path = requested_vault_path(path)?;
    if password.is_empty() {
        return Err(VaultError::EmptyPassword.into());
    }
    if path.exists() {
        return Err(VaultError::AlreadyExists(path).into());
    }
    let mut vault = state.vault.lock().map_err(|_| CommandError {
        code: "vault_state_unavailable",
        message: "Vault state is unavailable".to_owned(),
    })?;
    vault.create(&path, &password).map_err(Into::into)
}

#[tauri::command]
fn unlock_vault(
    path: Option<String>,
    password: String,
    state: State<'_, AppState>,
) -> Result<VaultInfo, CommandError> {
    let path = requested_vault_path(path)?;
    let _pin_guard = state.pin_state_lock.lock().map_err(|_| CommandError {
        code: "pin_state_unavailable",
        message: "PIN state is unavailable".to_owned(),
    })?;
    let info = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .open(&path, &password)?;
    let _ = PinUnlockStore.reset_after_master_password(&path);
    Ok(info)
}

#[tauri::command]
fn pin_unlock_vault(
    path: Option<String>,
    pin: String,
    state: State<'_, AppState>,
) -> Result<VaultInfo, CommandError> {
    let path = requested_vault_path(path)?;
    let _pin_guard = state.pin_state_lock.lock().map_err(|_| CommandError {
        code: "pin_state_unavailable",
        message: "PIN state is unavailable".to_owned(),
    })?;
    PinUnlockStore.verify(&path, &pin)?;
    let secret = QuickUnlockStore.load(&path)?;
    state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .open(path, secret.expose())
        .map_err(Into::into)
}

#[tauri::command]
fn enable_pin_unlock(
    path: Option<String>,
    password: String,
    pin: String,
    state: State<'_, AppState>,
) -> Result<(), CommandError> {
    let path = requested_vault_path(path)?;
    let _pin_guard = state.pin_state_lock.lock().map_err(|_| CommandError {
        code: "pin_state_unavailable",
        message: "PIN state is unavailable".to_owned(),
    })?;
    let mut verification = Vault::new();
    verification.open(&path, &password)?;
    verification.lock();
    QuickUnlockStore.save(&path, &password)?;
    if let Err(error) = PinUnlockStore.configure(&path, &pin) {
        let _ = QuickUnlockStore.remove(&path);
        return Err(error.into());
    }
    Ok(())
}

#[tauri::command]
fn disable_pin_unlock(
    path: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), CommandError> {
    let path = requested_vault_path(path)?;
    let _pin_guard = state.pin_state_lock.lock().map_err(|_| CommandError {
        code: "pin_state_unavailable",
        message: "PIN state is unavailable".to_owned(),
    })?;
    PinUnlockStore.remove(&path)?;
    QuickUnlockStore.remove(&path).map_err(Into::into)
}

#[tauri::command]
fn change_vault_password(
    current_password: String,
    new_password: String,
    state: State<'_, AppState>,
) -> Result<(), CommandError> {
    let _pin_guard = state.pin_state_lock.lock().map_err(|_| CommandError {
        code: "pin_state_unavailable",
        message: "PIN state is unavailable".to_owned(),
    })?;
    let mut vault = state.vault.lock().map_err(|_| CommandError {
        code: "vault_state_unavailable",
        message: "Vault state is unavailable".to_owned(),
    })?;
    let path = PathBuf::from(vault.info()?.path);
    let had_pin_unlock = PinUnlockStore.status(&path).configured;
    vault.change_password(&current_password, &new_password)?;
    if had_pin_unlock && QuickUnlockStore.save(&path, &new_password).is_err() {
        let _ = PinUnlockStore.remove(&path);
        let _ = QuickUnlockStore.remove(&path);
    }
    Ok(())
}

#[tauri::command]
fn lock_vault(state: State<'_, AppState>) -> Result<(), CommandError> {
    state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .lock();
    Ok(())
}

#[tauri::command]
fn list_vault_entries(
    query: Option<String>,
    state: State<'_, AppState>,
) -> Result<Value, CommandError> {
    let entries = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .list_entries(query.as_deref())?;
    serde_json::to_value(entries).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize vault entries".to_owned(),
    })
}

#[tauri::command]
fn get_vault_entry(id: String, state: State<'_, AppState>) -> Result<Value, CommandError> {
    let entry = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .get_entry(&id)?;
    serde_json::to_value(entry).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize vault entry".to_owned(),
    })
}

#[tauri::command]
fn add_vault_entry(input: EntryInput, state: State<'_, AppState>) -> Result<Value, CommandError> {
    let entry = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .add_entry(input)?;
    serde_json::to_value(entry).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize vault entry".to_owned(),
    })
}

#[tauri::command]
fn update_vault_entry(
    id: String,
    input: EntryInput,
    state: State<'_, AppState>,
) -> Result<Value, CommandError> {
    let entry = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .update_entry(&id, input)?;
    serde_json::to_value(entry).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize vault entry".to_owned(),
    })
}

#[tauri::command]
fn delete_vault_entry(id: String, state: State<'_, AppState>) -> Result<(), CommandError> {
    state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .delete_entry(&id)?;
    Ok(())
}

#[tauri::command]
fn list_vault_groups(state: State<'_, AppState>) -> Result<Value, CommandError> {
    let groups = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .groups()?;
    serde_json::to_value(groups).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize vault groups".to_owned(),
    })
}

#[tauri::command]
fn create_vault_group(
    parent_id: Option<String>,
    name: String,
    state: State<'_, AppState>,
) -> Result<Value, CommandError> {
    let group = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .create_group(parent_id.as_deref(), &name)?;
    serde_json::to_value(group).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize vault group".to_owned(),
    })
}

#[tauri::command]
fn rename_vault_group(
    id: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<Value, CommandError> {
    let group = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .rename_group(&id, &name)?;
    serde_json::to_value(group).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize vault group".to_owned(),
    })
}

#[tauri::command]
fn delete_vault_group(id: String, state: State<'_, AppState>) -> Result<(), CommandError> {
    state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .delete_group(&id)?;
    Ok(())
}

#[tauri::command]
fn vault_entry_history(id: String, state: State<'_, AppState>) -> Result<Value, CommandError> {
    let history = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .entry_history(&id)?;
    serde_json::to_value(history).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize entry history".to_owned(),
    })
}

#[tauri::command]
fn restore_vault_entry_history(
    id: String,
    index: usize,
    state: State<'_, AppState>,
) -> Result<Value, CommandError> {
    let entry = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .restore_entry_history(&id, index)?;
    serde_json::to_value(entry).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize restored entry".to_owned(),
    })
}

#[tauri::command]
fn vault_backups(state: State<'_, AppState>) -> Result<Value, CommandError> {
    let backups = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .backups()?;
    serde_json::to_value(backups).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize vault backups".to_owned(),
    })
}

#[tauri::command]
fn restore_vault_backup(
    index: usize,
    state: State<'_, AppState>,
) -> Result<VaultInfo, CommandError> {
    state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .restore_backup(index)
        .map_err(Into::into)
}

#[tauri::command]
fn add_vault_attachment(
    id: String,
    path: String,
    state: State<'_, AppState>,
) -> Result<Value, CommandError> {
    let path = PathBuf::from(path);
    let metadata = fs::metadata(&path).map_err(|error| CommandError {
        code: "io_error",
        message: format!("Could not read attachment: {error}"),
    })?;
    if metadata.len() > 20 * 1024 * 1024 {
        return Err(VaultError::AttachmentTooLarge.into());
    }
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(VaultError::EmptyAttachmentName)?;
    let data = fs::read(&path).map_err(|error| CommandError {
        code: "io_error",
        message: format!("Could not read attachment: {error}"),
    })?;
    let entry = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .add_attachment(&id, name, data)?;
    serde_json::to_value(entry).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize vault entry".to_owned(),
    })
}

#[tauri::command]
fn save_vault_attachment(
    id: String,
    name: String,
    path: String,
    state: State<'_, AppState>,
) -> Result<(), CommandError> {
    let bytes = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .attachment(&id, &name)?;
    write_private_file(Path::new(&path), &bytes).map_err(|message| CommandError {
        code: "io_error",
        message,
    })
}

#[tauri::command]
fn remove_vault_attachment(
    id: String,
    name: String,
    state: State<'_, AppState>,
) -> Result<Value, CommandError> {
    let entry = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .remove_attachment(&id, &name)?;
    serde_json::to_value(entry).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize vault entry".to_owned(),
    })
}

#[tauri::command]
fn vault_totp_codes(state: State<'_, AppState>) -> Result<Value, CommandError> {
    let codes = state
        .vault
        .lock()
        .map_err(|_| CommandError {
            code: "vault_state_unavailable",
            message: "Vault state is unavailable".to_owned(),
        })?
        .totp_codes()?;
    serde_json::to_value(codes).map_err(|_| CommandError {
        code: "serialization_error",
        message: "Could not serialize authenticator codes".to_owned(),
    })
}

fn copy_directory(source: &Path, destination: &Path) -> Result<(), String> {
    fs::create_dir_all(destination).map_err(|error| error.to_string())?;
    for entry in fs::read_dir(source).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_directory(&source_path, &destination_path)?;
        } else {
            fs::copy(source_path, destination_path).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

fn native_manifest_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();
    #[cfg(target_os = "linux")]
    if let Some(config) = dirs::config_dir() {
        paths.extend([
            config.join("chromium/NativeMessagingHosts"),
            config.join("google-chrome/NativeMessagingHosts"),
            config.join("BraveSoftware/Brave-Browser/NativeMessagingHosts"),
            config.join("microsoft-edge/NativeMessagingHosts"),
        ]);
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = dirs::home_dir() {
        let support = home.join("Library/Application Support");
        paths.extend([
            support.join("Google/Chrome/NativeMessagingHosts"),
            support.join("Chromium/NativeMessagingHosts"),
            support.join("BraveSoftware/Brave-Browser/NativeMessagingHosts"),
            support.join("Microsoft Edge/NativeMessagingHosts"),
        ]);
    }
    paths
}

fn install_browser_files(source: &Path, executable: &Path) -> Result<InstallResult, String> {
    let extension_directory = bridge_data_directory()?.join("browser-extension");
    copy_directory(source, &extension_directory)?;
    let manifest = json!({
        "name": NATIVE_HOST_NAME,
        "description": "Secure bridge between the Ciphera browser extension and desktop vault",
        "path": executable,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")]
    });
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(|error| error.to_string())?;
    let mut installed_manifests = Vec::new();
    for directory in native_manifest_paths() {
        let path = directory.join(format!("{NATIVE_HOST_NAME}.json"));
        write_private_file(&path, &manifest_bytes)?;
        installed_manifests.push(path.display().to_string());
    }

    #[cfg(target_os = "windows")]
    install_windows_native_host(&manifest_bytes, &mut installed_manifests)?;

    Ok(InstallResult {
        extension_id: EXTENSION_ID,
        extension_directory: extension_directory.display().to_string(),
        installed_manifests,
    })
}

#[tauri::command]
fn install_browser_integration(app: AppHandle) -> Result<InstallResult, String> {
    let bundled_extension = app
        .path()
        .resource_dir()
        .map_err(|error| error.to_string())?
        .join("extension");
    let development_extension = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../extension");
    let source = if bundled_extension.exists() {
        bundled_extension
    } else {
        development_extension
    };
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    install_browser_files(&source, &executable)
}

pub fn install_browser_host_from_cli() -> Result<(), String> {
    let source = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../extension");
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let result = install_browser_files(&source, &executable)?;
    println!(
        "{}",
        serde_json::to_string(&result).map_err(|error| error.to_string())?
    );
    Ok(())
}

#[cfg(target_os = "windows")]
fn install_windows_native_host(
    manifest_bytes: &[u8],
    installed_manifests: &mut Vec<String>,
) -> Result<(), String> {
    use winreg::{enums::HKEY_CURRENT_USER, RegKey};
    let manifest_path = bridge_data_directory()?.join(format!("{NATIVE_HOST_NAME}.json"));
    write_private_file(&manifest_path, manifest_bytes)?;
    let current_user = RegKey::predef(HKEY_CURRENT_USER);
    for browser in [
        "Google\\Chrome",
        "Chromium",
        "BraveSoftware\\Brave",
        "Microsoft\\Edge",
    ] {
        let key_path = format!("Software\\{browser}\\NativeMessagingHosts\\{NATIVE_HOST_NAME}");
        let (key, _) = current_user
            .create_subkey(key_path)
            .map_err(|error| error.to_string())?;
        key.set_value("", &manifest_path.display().to_string())
            .map_err(|error| error.to_string())?;
    }
    installed_manifests.push(manifest_path.display().to_string());
    Ok(())
}

fn forward_native_request(request: Value) -> Result<Value, String> {
    let descriptor: BridgeDescriptor = serde_json::from_slice(
        &fs::read(descriptor_path()?).map_err(|_| "Ciphera desktop is not running".to_string())?,
    )
    .map_err(|_| "Ciphera browser bridge descriptor is invalid".to_string())?;
    let mut stream = TcpStream::connect(("127.0.0.1", descriptor.port))
        .map_err(|_| "Ciphera desktop is not reachable".to_string())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| error.to_string())?;
    let envelope = json!({ "token": descriptor.token, "request": request });
    serde_json::to_writer(&mut stream, &envelope).map_err(|error| error.to_string())?;
    stream.write_all(b"\n").map_err(|error| error.to_string())?;
    stream.flush().map_err(|error| error.to_string())?;
    let mut response = String::new();
    BufReader::new(stream)
        .take((MAX_NATIVE_MESSAGE_SIZE + 1) as u64)
        .read_line(&mut response)
        .map_err(|error| error.to_string())?;
    if response.len() > MAX_NATIVE_MESSAGE_SIZE {
        return Err("Ciphera desktop response is too large".to_owned());
    }
    serde_json::from_str(&response).map_err(|error| error.to_string())
}

fn write_native_message(value: &Value) -> io::Result<()> {
    let payload = serde_json::to_vec(value)?;
    let length = u32::try_from(payload.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Native message is too large"))?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(&length.to_le_bytes())?;
    stdout.write_all(&payload)?;
    stdout.flush()
}

pub fn run_native_host() {
    let mut stdin = io::stdin().lock();
    loop {
        let mut length_bytes = [0_u8; 4];
        match stdin.read_exact(&mut length_bytes) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(_) => break,
        }
        let length = u32::from_le_bytes(length_bytes) as usize;
        if length > MAX_NATIVE_MESSAGE_SIZE {
            let _ = write_native_message(&json!({ "ok": false, "error": "message_too_large" }));
            break;
        }
        let mut payload = vec![0_u8; length];
        if stdin.read_exact(&mut payload).is_err() {
            break;
        }
        let response = match serde_json::from_slice::<Value>(&payload) {
            Ok(request) => forward_native_request(request)
                .unwrap_or_else(|error| json!({ "ok": false, "error": error })),
            Err(_) => json!({ "ok": false, "error": "invalid_json" }),
        };
        if write_native_message(&response).is_err() {
            break;
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod tests {
    use super::*;
    use ciphera_core::{EntryInput, KdfParameters};
    use tempfile::TempDir;

    fn unlocked_state() -> (TempDir, AppState, String) {
        let directory = TempDir::new().expect("temp directory");
        let path = directory.path().join("browser-test.kdbx");
        let mut vault = Vault::new();
        vault
            .create_with_parameters(
                &path,
                "test password",
                KdfParameters {
                    memory_bytes: 1024 * 1024,
                    iterations: 2,
                    parallelism: 1,
                },
            )
            .expect("create vault");
        let entry = vault
            .add_entry(EntryInput {
                group_id: None,
                title: "Example".to_owned(),
                username: "alex@example.com".to_owned(),
                password: "correct horse battery staple 42".to_owned(),
                url: "https://example.com".to_owned(),
                notes: String::new(),
                category: EntryCategory::Login,
                favorite: false,
                totp: None,
            })
            .expect("add login");
        let state = AppState {
            descriptor: BridgeDescriptor {
                port: 0,
                token: "test".to_owned(),
                pid: 0,
            },
            vault: Arc::new(Mutex::new(vault)),
            pin_state_lock: Arc::new(Mutex::new(())),
        };
        (directory, state, entry.summary.id)
    }

    #[test]
    fn browser_lookup_returns_metadata_without_password() {
        let (_directory, state, _id) = unlocked_state();
        let response = browser_response(
            BrowserRequest::FindLogins {
                url: "https://example.com/login".to_owned(),
            },
            &state,
        );
        assert_eq!(response["ok"], true);
        assert_eq!(response["logins"][0]["username"], "alex@example.com");
        assert!(response["logins"][0].get("password").is_none());
    }

    #[test]
    fn locked_vault_rejects_secret_requests() {
        let (_directory, state, id) = unlocked_state();
        state.vault.lock().expect("vault mutex").lock();
        let response = browser_response(BrowserRequest::GetLogin { id }, &state);
        assert_eq!(response, json!({ "ok": false, "error": "vault_locked" }));
    }

    #[test]
    fn similar_domains_do_not_match() {
        let (_directory, state, _id) = unlocked_state();
        let response = browser_response(
            BrowserRequest::FindLogins {
                url: "https://example.com.attacker.test/login".to_owned(),
            },
            &state,
        );
        assert_eq!(response["logins"].as_array().map(Vec::len), Some(0));
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let vault = Arc::new(Mutex::new(Vault::new()));
    tauri::Builder::default()
        .plugin(tauri_plugin_single_instance::init(
            |app, _arguments, _cwd| {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            },
        ))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .invoke_handler(tauri::generate_handler![
            browser_integration_status,
            install_browser_integration,
            vault_status,
            create_vault,
            unlock_vault,
            pin_unlock_vault,
            enable_pin_unlock,
            disable_pin_unlock,
            change_vault_password,
            lock_vault,
            list_vault_entries,
            get_vault_entry,
            add_vault_entry,
            update_vault_entry,
            delete_vault_entry,
            list_vault_groups,
            create_vault_group,
            rename_vault_group,
            delete_vault_group,
            vault_entry_history,
            restore_vault_entry_history,
            vault_backups,
            restore_vault_backup,
            add_vault_attachment,
            save_vault_attachment,
            remove_vault_attachment,
            vault_totp_codes
        ])
        .setup(move |app| {
            let state = start_bridge(vault).map_err(io::Error::other)?;
            app.manage(state);
            if cfg!(debug_assertions) {
                app.handle().plugin(
                    tauri_plugin_log::Builder::default()
                        .level(log::LevelFilter::Info)
                        .build(),
                )?;
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running Ciphera");
}
