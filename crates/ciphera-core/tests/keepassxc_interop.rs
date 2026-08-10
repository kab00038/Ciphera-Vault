use ciphera_core::{EntryCategory, EntryInput, KdfParameters, Vault};
use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};
use tempfile::TempDir;

fn run_cli(cli: &str, args: &[&str], stdin: &str) -> Output {
    let mut child = Command::new(cli)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start keepassxc-cli");
    child
        .stdin
        .take()
        .expect("KeePassXC stdin")
        .write_all(stdin.as_bytes())
        .expect("write KeePassXC input");
    child.wait_with_output().expect("wait for keepassxc-cli")
}

fn add_ciphera_entry(vault: &mut Vault) {
    vault
        .add_entry(EntryInput {
            group_id: None,
            title: "Ciphera Entry".to_owned(),
            username: "ciphera-user".to_owned(),
            password: "CipheraPassword42".to_owned(),
            url: "https://ciphera.example".to_owned(),
            notes: "Created by Ciphera".to_owned(),
            category: EntryCategory::Login,
            favorite: false,
            totp: None,
        })
        .expect("add Ciphera entry");
}

#[test]
#[ignore = "requires KEEPASSXC_CLI pointing to KeePassXC 2.7+"]
fn bidirectional_keepassxc_compatibility() {
    let cli = std::env::var("KEEPASSXC_CLI").expect("KEEPASSXC_CLI");
    let directory = TempDir::new().expect("temp directory");
    let path = directory.path().join("interop.kdbx");
    let path_text = path.to_string_lossy();
    let mut vault = Vault::new();
    vault
        .create_with_parameters(
            &path,
            "interop-master",
            KdfParameters {
                memory_bytes: 8 * 1024 * 1024,
                iterations: 2,
                parallelism: 1,
            },
        )
        .expect("create Ciphera database");
    add_ciphera_entry(&mut vault);
    vault.lock();

    let shown = run_cli(
        &cli,
        &[
            "show",
            "-q",
            "-s",
            "-a",
            "Password",
            &path_text,
            "Ciphera Entry",
        ],
        "interop-master\n",
    );
    assert!(
        shown.status.success(),
        "KeePassXC could not read Ciphera output: {}",
        String::from_utf8_lossy(&shown.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&shown.stdout).trim(),
        "CipheraPassword42"
    );

    let added = run_cli(
        &cli,
        &[
            "add",
            "-q",
            "-u",
            "keepassxc-user",
            "--url",
            "https://keepassxc.example",
            "-p",
            &path_text,
            "KeePassXC Entry",
        ],
        "interop-master\nKeePassXCPassword42\n",
    );
    assert!(
        added.status.success(),
        "KeePassXC could not modify Ciphera output: {}",
        String::from_utf8_lossy(&added.stderr)
    );

    let mut reopened = Vault::new();
    reopened
        .open(Path::new(&*path_text), "interop-master")
        .expect("reopen KeePassXC-modified file");
    let entry = reopened
        .list_entries(Some("KeePassXC Entry"))
        .expect("list KeePassXC entry")
        .into_iter()
        .next()
        .expect("KeePassXC entry exists");
    let detail = reopened.get_entry(&entry.id).expect("read KeePassXC entry");
    assert_eq!(detail.summary.username, "keepassxc-user");
    assert_eq!(detail.password, "KeePassXCPassword42");
    assert_eq!(detail.summary.url, "https://keepassxc.example");

    reopened
        .update_entry(
            &entry.id,
            EntryInput {
                group_id: Some(detail.summary.group_id),
                title: detail.summary.title,
                username: detail.summary.username,
                password: detail.password,
                url: detail.summary.url,
                notes: "Touched by Ciphera after KeePassXC".to_owned(),
                category: detail.summary.category,
                favorite: detail.summary.favorite,
                totp: detail.totp,
            },
        )
        .expect("save KeePassXC entry through Ciphera");
    reopened.lock();

    let shown_again = run_cli(
        &cli,
        &[
            "show",
            "-q",
            "-s",
            "-a",
            "Password",
            &path_text,
            "KeePassXC Entry",
        ],
        "interop-master\n",
    );
    assert!(
        shown_again.status.success(),
        "KeePassXC could not reopen Ciphera re-save: {}",
        String::from_utf8_lossy(&shown_again.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&shown_again.stdout).trim(),
        "KeePassXCPassword42"
    );
}
