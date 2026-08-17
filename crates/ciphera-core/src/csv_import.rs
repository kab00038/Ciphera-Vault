use crate::{CsvImportIssue, EntryCategory, EntryInput, VaultError};
use csv::{ReaderBuilder, StringRecord, Trim};
use sha2::{Digest, Sha256};

pub const MAX_CSV_IMPORT_BYTES: usize = 10 * 1024 * 1024;
const MAX_CSV_IMPORT_ROWS: usize = 100_000;
const MAX_CSV_FIELD_BYTES: usize = 64 * 1024;
const MAX_REPORTED_ISSUES: usize = 20;

pub(crate) struct ParsedCsvImport {
    pub source_format: String,
    pub rows: Vec<EntryInput>,
    pub total_rows: usize,
    pub skipped_rows: usize,
    pub issues: Vec<CsvImportIssue>,
}

struct CsvColumns {
    title: Option<usize>,
    username: Option<usize>,
    password: usize,
    url: Option<usize>,
    notes: Option<usize>,
    totp: Option<usize>,
    favorite: Option<usize>,
}

impl CsvColumns {
    fn from_headers(headers: &StringRecord) -> Result<(Self, String), VaultError> {
        let normalized: Vec<String> = headers.iter().map(normalize_header).collect();
        let find = |aliases: &[&str]| {
            normalized
                .iter()
                .position(|header| aliases.contains(&header.as_str()))
        };
        let password = find(&["password", "loginpassword", "pass"])
            .ok_or(VaultError::CsvMissingPasswordColumn)?;
        let source_format = if normalized.iter().any(|header| header == "loginpassword") {
            "Bitwarden CSV"
        } else if normalized
            .iter()
            .any(|header| header == "formactionorigin" || header == "httprealm")
        {
            "Firefox CSV"
        } else if normalized.iter().any(|header| header == "group")
            && normalized.iter().any(|header| header == "totp")
        {
            "KeePassXC CSV"
        } else if normalized.iter().any(|header| header == "otpauth") {
            "1Password CSV"
        } else if ["name", "url", "username", "password"]
            .iter()
            .all(|required| normalized.iter().any(|header| header == required))
        {
            "Chromium CSV"
        } else {
            "Generic CSV"
        };
        Ok((
            Self {
                title: find(&["title", "name", "account", "service"]),
                username: find(&["username", "loginusername", "user", "email", "login"]),
                password,
                url: find(&["url", "loginuri", "website", "uri", "origin"]),
                notes: find(&["notes", "note", "extra", "comments", "comment"]),
                totp: find(&["totp", "logintotp", "otp", "otpauth", "otpauthurl"]),
                favorite: find(&["favorite", "favourite"]),
            },
            source_format.to_owned(),
        ))
    }
}

pub(crate) fn parse_csv_import(bytes: &[u8]) -> Result<ParsedCsvImport, VaultError> {
    if bytes.len() > MAX_CSV_IMPORT_BYTES {
        return Err(VaultError::CsvTooLarge);
    }
    let mut reader = ReaderBuilder::new()
        .flexible(true)
        .trim(Trim::All)
        .from_reader(bytes);
    let headers = reader
        .headers()
        .map_err(|_| VaultError::InvalidCsv)?
        .clone();
    let (columns, source_format) = CsvColumns::from_headers(&headers)?;
    let mut rows = Vec::new();
    let mut total_rows = 0;
    let mut skipped_rows = 0;
    let mut issues = Vec::new();

    for record in reader.records() {
        total_rows += 1;
        if total_rows > MAX_CSV_IMPORT_ROWS {
            return Err(VaultError::CsvTooManyRows);
        }
        let source_row = total_rows + 1;
        let record = match record {
            Ok(record) => record,
            Err(_) => {
                skipped_rows += 1;
                report_issue(&mut issues, source_row, "Malformed CSV row");
                continue;
            }
        };
        let value = |index: Option<usize>| index.and_then(|index| record.get(index)).unwrap_or("");
        let password = record.get(columns.password).unwrap_or("").to_owned();
        let username = value(columns.username).to_owned();
        let url = value(columns.url).to_owned();
        let mut title = value(columns.title).to_owned();
        if title.is_empty() {
            title = if !url.is_empty() {
                url.clone()
            } else {
                username.clone()
            };
        }
        let notes = value(columns.notes).to_owned();
        let totp = value(columns.totp).trim();
        let favorite = matches!(
            value(columns.favorite).to_ascii_lowercase().as_str(),
            "1" | "true" | "yes"
        );

        if password.is_empty() {
            skipped_rows += 1;
            report_issue(&mut issues, source_row, "Password is empty");
            continue;
        }
        if title.trim().is_empty() {
            skipped_rows += 1;
            report_issue(&mut issues, source_row, "No title, username, or URL");
            continue;
        }
        if [&title, &username, &password, &url, &notes]
            .iter()
            .any(|field| field.len() > MAX_CSV_FIELD_BYTES)
            || totp.len() > MAX_CSV_FIELD_BYTES
        {
            skipped_rows += 1;
            report_issue(&mut issues, source_row, "Field exceeds the 64 KiB limit");
            continue;
        }

        rows.push(EntryInput {
            group_id: None,
            title,
            username,
            password,
            url,
            notes,
            category: EntryCategory::Login,
            favorite,
            totp: (!totp.is_empty()).then(|| totp.to_owned()),
        });
    }

    Ok(ParsedCsvImport {
        source_format,
        rows,
        total_rows,
        skipped_rows,
        issues,
    })
}

pub(crate) fn input_fingerprint(input: &EntryInput) -> [u8; 32] {
    let totp = crate::canonical_totp(input.totp.as_deref());
    content_fingerprint([
        input.title.trim().as_bytes(),
        input.username.as_bytes(),
        input.password.as_bytes(),
        input.url.as_bytes(),
        input.notes.as_bytes(),
        input.category.as_field().as_bytes(),
        if input.favorite { b"true" } else { b"false" },
        totp.as_deref().unwrap_or_default().as_bytes(),
    ])
}

pub(crate) fn stored_entry_fingerprint(entry: &keepass::db::EntryRef<'_>) -> [u8; 32] {
    content_fingerprint([
        entry
            .get(keepass::db::fields::TITLE)
            .unwrap_or_default()
            .as_bytes(),
        entry
            .get(keepass::db::fields::USERNAME)
            .unwrap_or_default()
            .as_bytes(),
        entry
            .get(keepass::db::fields::PASSWORD)
            .unwrap_or_default()
            .as_bytes(),
        entry
            .get(keepass::db::fields::URL)
            .unwrap_or_default()
            .as_bytes(),
        entry
            .get(keepass::db::fields::NOTES)
            .unwrap_or_default()
            .as_bytes(),
        EntryCategory::from_field(entry.get("Ciphera.Category"))
            .as_field()
            .as_bytes(),
        if entry.get("Ciphera.Favorite") == Some("true") {
            b"true"
        } else {
            b"false"
        },
        entry
            .get(keepass::db::fields::OTP)
            .unwrap_or_default()
            .as_bytes(),
    ])
}

fn normalize_header(header: &str) -> String {
    header
        .trim_start_matches('\u{feff}')
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn report_issue(issues: &mut Vec<CsvImportIssue>, row: usize, message: &str) {
    if issues.len() < MAX_REPORTED_ISSUES {
        issues.push(CsvImportIssue {
            row,
            message: message.to_owned(),
        });
    }
}

fn content_fingerprint<'a>(fields: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.finalize().into()
}
