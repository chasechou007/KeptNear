use std::path::PathBuf;

use psw_core::{
    CreateVaultRequest, LoginItem, SecretBytes, UnlockRequest, VaultCore, VaultItemContent,
    VaultItemDraft,
};

fn main() {
    let output_path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: generate_golden_vault_fixture <output.pswvault>");
    if output_path.exists() {
        panic!("output path already exists: {}", output_path.display());
    }
    if let Some(parent) = output_path.parent() {
        std::fs::create_dir_all(parent).expect("create fixture parent");
    }

    let password = SecretBytes::new(b"correct horse battery staple".to_vec());
    let core = VaultCore::new();
    let mut unlocked = core
        .create_vault(CreateVaultRequest {
            path: output_path.clone(),
            display_name: Some("Golden Fixture V1".to_owned()),
            master_password: password.clone(),
        })
        .expect("create golden fixture vault")
        .unlock(UnlockRequest {
            master_password: password,
        })
        .expect("unlock golden fixture vault");

    unlocked
        .create_item(VaultItemDraft {
            title: "Golden Login".to_owned(),
            content: VaultItemContent::Login(LoginItem {
                username: Some("golden-user".to_owned()),
                password: Some(SecretBytes::new(b"golden-password".to_vec())),
                urls: vec!["https://golden.example".to_owned()],
                notes: Some("golden-note".to_owned()),
                totp_secret: Some(SecretBytes::new(
                    b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_vec(),
                )),
            }),
            tags: vec!["golden".to_owned()],
            favorite: true,
        })
        .expect("create golden fixture item");

    println!("Generated golden vault fixture: {}", output_path.display());
}
