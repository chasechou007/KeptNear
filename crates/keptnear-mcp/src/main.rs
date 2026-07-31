#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct StartupArgumentError;

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq)]
enum StartupAction {
    Serve(keptnear_mcp::PairingProfileId),
    ComponentMetadata,
}

#[cfg(target_os = "macos")]
fn parse_startup_arguments(
    arguments: impl IntoIterator<Item = std::ffi::OsString>,
) -> Result<StartupAction, StartupArgumentError> {
    let mut arguments = arguments.into_iter();
    let Some(option) = arguments.next() else {
        return Ok(StartupAction::Serve(
            keptnear_mcp::PairingProfileId::default(),
        ));
    };
    let option = option.to_str().ok_or(StartupArgumentError)?;
    if option == "--component-metadata" {
        return if arguments.next().is_none() {
            Ok(StartupAction::ComponentMetadata)
        } else {
            Err(StartupArgumentError)
        };
    }
    let profile = if option == "--profile" {
        arguments
            .next()
            .and_then(|value| value.into_string().ok())
            .ok_or(StartupArgumentError)?
    } else if let Some(profile) = option.strip_prefix("--profile=") {
        profile.to_owned()
    } else {
        return Err(StartupArgumentError);
    };
    if arguments.next().is_some() {
        return Err(StartupArgumentError);
    }
    profile
        .parse()
        .map(StartupAction::Serve)
        .map_err(|_| StartupArgumentError)
}

#[cfg(target_os = "macos")]
fn main() {
    let action = match parse_startup_arguments(std::env::args_os().skip(1)) {
        Ok(action) => action,
        Err(_) => {
            eprintln!(
                "KeptNear MCP accepts no arguments, one valid --profile <id> option, or --component-metadata."
            );
            std::process::exit(2);
        }
    };
    match action {
        StartupAction::Serve(profile) => {
            if keptnear_mcp::run_stdio_for_profile(profile).is_err() {
                eprintln!("KeptNear MCP stopped because its local stdio transport failed.");
                std::process::exit(1);
            }
        }
        StartupAction::ComponentMetadata => {
            let metadata = psw_broker::ComponentMetadata::current(
                psw_broker::PackagedComponent::McpAdapter,
                env!("CARGO_PKG_VERSION"),
            )
            .expect("Cargo package version is valid component metadata");
            println!(
                "{}",
                serde_json::to_string(&metadata).expect("serialize component metadata")
            );
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("KeptNear MCP currently supports macOS only.");
    std::process::exit(1);
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::ffi::OsString;

    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn profile_arguments_preserve_default_and_canonicalize_named_profiles() {
        assert_eq!(
            parse_startup_arguments(Vec::<OsString>::new()).expect("default"),
            StartupAction::Serve(keptnear_mcp::PairingProfileId::default())
        );
        for (values, expected) in [
            (&["--profile", "Codex.Release"][..], "codex.release"),
            (&["--profile=Claude-Code"][..], "claude-code"),
        ] {
            let StartupAction::Serve(profile) =
                parse_startup_arguments(arguments(values)).expect("profile")
            else {
                panic!("expected serve action");
            };
            assert_eq!(profile.as_str(), expected);
        }
        assert_eq!(
            parse_startup_arguments(arguments(&["--component-metadata"])).expect("metadata"),
            StartupAction::ComponentMetadata
        );
    }

    #[test]
    fn profile_arguments_reject_unknown_missing_extra_and_unsafe_values() {
        for values in [
            vec!["--unknown"],
            vec!["--profile"],
            vec!["--profile", "codex", "extra"],
            vec!["--profile", "../codex"],
            vec!["--profile="],
            vec!["--component-metadata", "extra"],
        ] {
            assert_eq!(
                parse_startup_arguments(arguments(&values)),
                Err(StartupArgumentError)
            );
        }
    }
}
