#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
fn main() {
    let mut arguments = std::env::args_os().skip(1);
    match arguments.next() {
        Some(argument) if argument == "--component-metadata" && arguments.next().is_none() => {
            print_component_metadata();
        }
        None => run_broker(),
        _ => {
            eprintln!("KeptNear Broker accepts no arguments or --component-metadata.");
            std::process::exit(2);
        }
    }
}

#[cfg(target_os = "macos")]
fn print_component_metadata() {
    let metadata = psw_broker::ComponentMetadata::current(
        psw_broker::PackagedComponent::Broker,
        env!("CARGO_PKG_VERSION"),
    )
    .expect("Cargo package version is valid component metadata");
    println!(
        "{}",
        serde_json::to_string(&metadata).expect("serialize component metadata")
    );
}

#[cfg(target_os = "macos")]
fn run_broker() {
    let mut runtime = match psw_broker::BrokerRuntime::open_or_initialize_for_current_user(
        psw_broker::MacOsDeviceKeyStore::new(),
    ) {
        Ok(runtime) => runtime,
        Err(_) => {
            eprintln!("KeptNear Broker could not open its protected local state.");
            std::process::exit(1);
        }
    };
    let listener = match psw_broker::UnixBrokerListener::bind(runtime.paths()) {
        Ok(listener) => listener,
        Err(_) => {
            let _ = runtime.shutdown();
            eprintln!("KeptNear Broker could not bind its owner-only local transport.");
            std::process::exit(1);
        }
    };

    loop {
        if listener.serve_one_runtime(&runtime).is_err() {
            let _ = runtime.shutdown();
            eprintln!("KeptNear Broker stopped after a local transport failure.");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    if matches!(
        std::env::args_os().skip(1).collect::<Vec<_>>().as_slice(),
        [argument] if argument == "--component-metadata"
    ) {
        let metadata = psw_broker::ComponentMetadata::current(
            psw_broker::PackagedComponent::Broker,
            env!("CARGO_PKG_VERSION"),
        )
        .expect("Cargo package version is valid component metadata");
        println!(
            "{}",
            serde_json::to_string(&metadata).expect("serialize component metadata")
        );
        return;
    }
    eprintln!("KeptNear Broker currently supports macOS only.");
    std::process::exit(1);
}
