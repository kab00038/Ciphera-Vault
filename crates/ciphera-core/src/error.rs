use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("vault is locked")]
    Locked,
    #[error("master password is incorrect")]
    WrongPassword,
    #[error("vault file is corrupted or unsupported")]
    Corrupted,
    #[error("vault was changed by another application; reopen it before saving")]
    ExternalModification,
    #[error("entry was not found")]
    EntryNotFound,
    #[error("group was not found")]
    GroupNotFound,
    #[error("the root vault group cannot be modified")]
    RootGroupProtected,
    #[error("group must be empty before it can be deleted")]
    GroupNotEmpty,
    #[error("group name is required")]
    EmptyGroupName,
    #[error("entry history version was not found")]
    HistoryNotFound,
    #[error("vault backup was not found")]
    BackupNotFound,
    #[error("attachment was not found")]
    AttachmentNotFound,
    #[error("attachment name is required")]
    EmptyAttachmentName,
    #[error("attachment exceeds the 20 MiB limit")]
    AttachmentTooLarge,
    #[error("CSV import exceeds the 10 MiB limit")]
    CsvTooLarge,
    #[error("CSV import exceeds the 100,000 row limit")]
    CsvTooManyRows,
    #[error("CSV import is malformed or not UTF-8")]
    InvalidCsv,
    #[error("CSV import requires a password column")]
    CsvMissingPasswordColumn,
    #[error("a master password is required")]
    EmptyPassword,
    #[error("entry title is required")]
    EmptyTitle,
    #[error("vault already exists at {0}")]
    AlreadyExists(PathBuf),
    #[error("vault does not exist at {0}")]
    NotFound(PathBuf),
    #[error("invalid vault path")]
    InvalidPath,
    #[error("vault I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("vault encryption failed")]
    Encryption,
}

impl VaultError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Locked => "vault_locked",
            Self::WrongPassword => "wrong_password",
            Self::Corrupted => "vault_corrupted",
            Self::ExternalModification => "external_modification",
            Self::EntryNotFound => "entry_not_found",
            Self::GroupNotFound => "group_not_found",
            Self::EmptyPassword => "empty_password",
            Self::RootGroupProtected => "root_group_protected",
            Self::GroupNotEmpty => "group_not_empty",
            Self::EmptyGroupName => "empty_group_name",
            Self::HistoryNotFound => "history_not_found",
            Self::BackupNotFound => "backup_not_found",
            Self::AttachmentNotFound => "attachment_not_found",
            Self::EmptyAttachmentName => "empty_attachment_name",
            Self::AttachmentTooLarge => "attachment_too_large",
            Self::CsvTooLarge => "csv_too_large",
            Self::CsvTooManyRows => "csv_too_many_rows",
            Self::InvalidCsv => "invalid_csv",
            Self::CsvMissingPasswordColumn => "csv_missing_password_column",
            Self::EmptyTitle => "empty_title",
            Self::AlreadyExists(_) => "vault_exists",
            Self::NotFound(_) => "vault_not_found",
            Self::InvalidPath => "invalid_path",
            Self::Io(_) => "io_error",
            Self::Encryption => "encryption_error",
        }
    }
}
