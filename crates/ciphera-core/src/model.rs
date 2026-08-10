use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Group {
    pub id: String,
    pub parent_id: Option<String>,
    pub name: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryHistory {
    pub index: usize,
    pub title: String,
    pub username: String,
    pub url: String,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AttachmentSummary {
    pub name: String,
    pub size: usize,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackupInfo {
    pub index: usize,
    pub path: String,
    pub size: u64,
    pub modified_at: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub enum EntryCategory {
    #[default]
    Login,
    Card,
    Identity,
    #[serde(rename = "Secure note")]
    SecureNote,
}

impl EntryCategory {
    pub(crate) fn as_field(self) -> &'static str {
        match self {
            Self::Login => "Login",
            Self::Card => "Card",
            Self::Identity => "Identity",
            Self::SecureNote => "Secure note",
        }
    }

    pub(crate) fn from_field(value: Option<&str>) -> Self {
        match value {
            Some("Card") => Self::Card,
            Some("Identity") => Self::Identity,
            Some("Secure note") => Self::SecureNote,
            _ => Self::Login,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum PasswordHealth {
    Safe,
    Weak,
    Reused,
    Old,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntrySummary {
    pub id: String,
    pub group_id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub category: EntryCategory,
    pub favorite: bool,
    pub health: PasswordHealth,
    pub updated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryDetail {
    #[serde(flatten)]
    pub summary: EntrySummary,
    pub password: String,
    pub notes: String,
    pub totp: Option<String>,
    #[serde(default)]
    pub attachments: Vec<AttachmentSummary>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TotpCode {
    pub id: String,
    pub title: String,
    pub username: String,
    pub code: String,
    pub valid_for: u64,
    pub period: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryInput {
    pub group_id: Option<String>,
    pub title: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub category: EntryCategory,
    #[serde(default)]
    pub favorite: bool,
    pub totp: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KdfParameters {
    pub memory_bytes: u64,
    pub iterations: u64,
    pub parallelism: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultInfo {
    pub path: String,
    pub name: String,
    pub entry_count: usize,
    pub kdf: KdfParameters,
}
