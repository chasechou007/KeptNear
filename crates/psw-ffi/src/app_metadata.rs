#![forbid(unsafe_code)]

fn main() {
    let metadata = psw_broker::ComponentMetadata::current(
        psw_broker::PackagedComponent::MacOsApp,
        env!("CARGO_PKG_VERSION"),
    )
    .expect("Cargo package version is valid component metadata");
    println!(
        "{}",
        serde_json::to_string(&metadata).expect("serialize component metadata")
    );
}
