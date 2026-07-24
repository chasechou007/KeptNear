use std::env;
use std::fs;
use std::path::PathBuf;

use psw_core::{
    CreateVaultRequest, LoginItem, SecretBytes, UnlockRequest, VaultCore, VaultItemContent,
    VaultItemDraft,
};

fn main() {
    let vault_path = PathBuf::from(env::args().nth(1).expect("vault path argument"));
    let password = SecretBytes::new(b"correct horse battery staple".to_vec());
    let core = VaultCore::new();
    let mut unlocked = core
        .create_vault(CreateVaultRequest {
            path: vault_path.clone(),
            display_name: Some("Doctor Readiness".to_owned()),
            master_password: password.clone(),
        })
        .expect("create vault")
        .unlock(UnlockRequest {
            master_password: password,
        })
        .expect("unlock vault");

    unlocked
        .create_item(VaultItemDraft {
            title: "Doctor Login".to_owned(),
            content: VaultItemContent::Login(LoginItem {
                username: Some("doctor-user@example.com".to_owned()),
                password: Some(SecretBytes::new(b"doctor-secret-never-print".to_vec())),
                urls: vec!["https://doctor.example".to_owned()],
                notes: Some("doctor private note".to_owned()),
                totp_secret: None,
            }),
            tags: vec!["doctor".to_owned()],
            favorite: false,
        })
        .expect("create login item");

    fs::write(
        vault_path.join("attachments").join("doctor-attachment.bin"),
        b"attachment",
    )
    .expect("write attachment");
    fs::write(
        vault_path.join("local_unlock.enc"),
        b"local unlock envelope",
    )
    .expect("write local unlock marker");
}
