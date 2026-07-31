#![forbid(unsafe_code)]

use std::env;
use std::io;
use std::process;

use psw_broker::{ComponentMetadata, PackagedComponent};
use psw_cli::{
    doctor_vault, execute_keptnear_invocation, parse_keptnear_arguments,
    render_keptnear_text_report, CliVaultDoctorOutput, KeptNearCliAction, KEPTNEAR_HELP,
};

fn main() {
    match parse_keptnear_arguments(env::args_os().skip(1)) {
        Ok(KeptNearCliAction::Help) => print!("{KEPTNEAR_HELP}"),
        Ok(KeptNearCliAction::Version) => {
            println!("keptnear {}", env!("CARGO_PKG_VERSION"));
        }
        Ok(KeptNearCliAction::ComponentMetadata) => {
            let metadata =
                ComponentMetadata::current(PackagedComponent::Cli, env!("CARGO_PKG_VERSION"))
                    .expect("Cargo package version is valid component metadata");
            println!(
                "{}",
                serde_json::to_string(&metadata).expect("serialize component metadata")
            );
        }
        Ok(KeptNearCliAction::VaultDoctor(invocation)) => {
            let report = doctor_vault(invocation.path());
            match invocation.output() {
                CliVaultDoctorOutput::Text => print!("{}", render_keptnear_text_report(&report)),
                CliVaultDoctorOutput::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&report).expect("serialize doctor report")
                ),
            }
            if !report.is_usable() {
                process::exit(1);
            }
        }
        Ok(KeptNearCliAction::Invoke(invocation)) => {
            let stdout = io::stdout();
            let result = execute_keptnear_invocation(*invocation, &mut stdout.lock());
            match result {
                Ok(outcome) => {
                    let exit_status = outcome.exit_status();
                    if exit_status != 0 {
                        process::exit(exit_status);
                    }
                }
                Err(error) => {
                    let stderr = io::stderr();
                    let mut stderr = stderr.lock();
                    if error.write_json(&mut stderr).is_err() {
                        drop(stderr);
                        eprintln!("KeptNear could not write a command result.");
                    }
                    process::exit(1);
                }
            }
        }
        Err(error) => {
            eprintln!("{error}");
            eprintln!();
            eprint!("{KEPTNEAR_HELP}");
            process::exit(2);
        }
    }
}
