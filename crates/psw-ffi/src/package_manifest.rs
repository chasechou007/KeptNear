#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use psw_broker::{
    ComponentMetadata, PackagedComponent, BROKER_PROTOCOL_MAJOR, BROKER_PROTOCOL_MINOR,
    BROKER_PROTOCOL_NAME, COMPONENT_METADATA_SCHEMA,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const PROTOCOL_MANIFEST_SCHEMA: &str = "keptnear.protocol-manifest.v1";
const MAX_COMPONENT_METADATA_BYTES: usize = 16 * 1024;
const MAX_PROTOCOL_MANIFEST_BYTES: usize = 64 * 1024;

const APP_MANIFEST_PATH: &str = "KeptNear.app/Contents/MacOS/KeptNear";
const BROKER_MANIFEST_PATH: &str = "KeptNear.app/Contents/Helpers/keptnear-broker";
const MCP_MANIFEST_PATH: &str = "KeptNear.app/Contents/Helpers/keptnear-mcp";
const CLI_MANIFEST_PATH: &str = "KeptNear.app/Contents/Helpers/keptnear";
const FFI_MANIFEST_PATH: &str = "KeptNear.app/Contents/Frameworks/libpsw_ffi.dylib";
const APP_METADATA_MANIFEST_PATH: &str =
    "KeptNear.app/Contents/Resources/KeptNear-App-Component.json";

const APP_INSTALL_PATH: &str = "/Applications/KeptNear.app";
const BROKER_INSTALL_PATH: &str = "/Applications/KeptNear.app/Contents/Helpers/keptnear-broker";
const MCP_INSTALL_PATH: &str = "/Applications/KeptNear.app/Contents/Helpers/keptnear-mcp";
const CLI_INSTALL_PATH: &str = "/Applications/KeptNear.app/Contents/Helpers/keptnear";

fn main() {
    let mut arguments = env::args_os().skip(1);
    let result = match arguments.next().and_then(|value| value.into_string().ok()) {
        Some(command) if command == "generate" => generate(arguments),
        Some(command) if command == "verify" => verify(arguments),
        _ => Err(PackageManifestError::InvalidArgument),
    };
    match result {
        Ok(protocol) => println!("{protocol}"),
        Err(error) => {
            eprintln!("KeptNear protocol manifest operation failed: {error}");
            process::exit(1);
        }
    }
}

fn generate(arguments: impl IntoIterator<Item = OsString>) -> Result<String, PackageManifestError> {
    let arguments = GenerateArguments::parse(arguments)?;
    validate_atom(&arguments.product_version)?;
    validate_atom(&arguments.architecture)?;
    validate_atom(&arguments.git_revision)?;
    if !valid_source_worktree(&arguments.source_worktree)
        || !valid_utc_timestamp(&arguments.generated_at_utc)
    {
        return Err(PackageManifestError::InvalidArgument);
    }

    let app = load_component_metadata(&arguments.app_metadata, PackagedComponent::MacOsApp)?;
    let embedded_app =
        load_component_metadata_file(&arguments.app_metadata_file, PackagedComponent::MacOsApp)?;
    if app != embedded_app {
        return Err(PackageManifestError::InvalidComponentMetadata);
    }
    let broker = load_component_metadata(&arguments.broker, PackagedComponent::Broker)?;
    let mcp = load_component_metadata(&arguments.mcp, PackagedComponent::McpAdapter)?;
    let cli = load_component_metadata(&arguments.cli, PackagedComponent::Cli)?;
    require_shared_protocol([&app, &broker, &mcp, &cli])?;

    let manifest = ProtocolManifest {
        schema: PROTOCOL_MANIFEST_SCHEMA.to_owned(),
        component_metadata_schema: COMPONENT_METADATA_SCHEMA.to_owned(),
        product: ProductManifest {
            name: "KeptNear".to_owned(),
            version: arguments.product_version,
            architecture: arguments.architecture,
            git_revision: arguments.git_revision,
            source_worktree: arguments.source_worktree,
            generated_at_utc: arguments.generated_at_utc,
        },
        shared_protocol: SharedProtocolManifest {
            name: BROKER_PROTOCOL_NAME.to_owned(),
            major: BROKER_PROTOCOL_MAJOR,
            minor: BROKER_PROTOCOL_MINOR,
        },
        installation: InstallationManifest::current(),
        components: vec![
            component_entry(
                "macos-app",
                app.component_version(),
                APP_MANIFEST_PATH,
                &arguments.app_executable,
            )?,
            component_entry(
                "broker",
                broker.component_version(),
                BROKER_MANIFEST_PATH,
                &arguments.broker,
            )?,
            component_entry(
                "mcp-adapter",
                mcp.component_version(),
                MCP_MANIFEST_PATH,
                &arguments.mcp,
            )?,
            component_entry(
                "cli",
                cli.component_version(),
                CLI_MANIFEST_PATH,
                &arguments.cli,
            )?,
        ],
        supporting_files: vec![
            supporting_file_entry("rust-ffi", FFI_MANIFEST_PATH, &arguments.ffi)?,
            supporting_file_entry(
                "app-component-metadata",
                APP_METADATA_MANIFEST_PATH,
                &arguments.app_metadata_file,
            )?,
        ],
    };
    write_manifest(&arguments.output, &manifest)?;
    Ok(protocol_declaration())
}

fn verify(arguments: impl IntoIterator<Item = OsString>) -> Result<String, PackageManifestError> {
    let arguments = VerifyArguments::parse(arguments)?;
    validate_atom(&arguments.product_version)?;
    validate_atom(&arguments.architecture)?;
    let manifest = read_protocol_manifest(&arguments.manifest)?;
    validate_manifest_contract(
        &manifest,
        &arguments.product_version,
        &arguments.architecture,
    )?;

    let app_metadata_path = resolve_manifest_path(&arguments.root, APP_METADATA_MANIFEST_PATH);
    let app = load_component_metadata_file(&app_metadata_path, PackagedComponent::MacOsApp)?;
    let broker_path = resolve_manifest_path(&arguments.root, BROKER_MANIFEST_PATH);
    let broker = load_component_metadata(&broker_path, PackagedComponent::Broker)?;
    let mcp_path = resolve_manifest_path(&arguments.root, MCP_MANIFEST_PATH);
    let mcp = load_component_metadata(&mcp_path, PackagedComponent::McpAdapter)?;
    let cli_path = resolve_manifest_path(&arguments.root, CLI_MANIFEST_PATH);
    let cli = load_component_metadata(&cli_path, PackagedComponent::Cli)?;
    require_shared_protocol([&app, &broker, &mcp, &cli])?;

    let expected_components = [
        (
            "macos-app",
            APP_MANIFEST_PATH,
            app.component_version(),
            true,
        ),
        (
            "broker",
            BROKER_MANIFEST_PATH,
            broker.component_version(),
            true,
        ),
        (
            "mcp-adapter",
            MCP_MANIFEST_PATH,
            mcp.component_version(),
            true,
        ),
        ("cli", CLI_MANIFEST_PATH, cli.component_version(), true),
    ];
    for (entry, (id, path, version, require_executable)) in
        manifest.components.iter().zip(expected_components)
    {
        if entry.id != id || entry.path != path || entry.version != version {
            return Err(PackageManifestError::InvalidProtocolManifest);
        }
        verify_manifest_hash(
            &arguments.root,
            &entry.path,
            &entry.sha256,
            require_executable,
        )?;
    }

    let expected_supporting_files = [
        ("rust-ffi", FFI_MANIFEST_PATH, false),
        ("app-component-metadata", APP_METADATA_MANIFEST_PATH, false),
    ];
    for (entry, (id, path, require_executable)) in manifest
        .supporting_files
        .iter()
        .zip(expected_supporting_files)
    {
        if entry.id != id || entry.path != path {
            return Err(PackageManifestError::InvalidProtocolManifest);
        }
        verify_manifest_hash(
            &arguments.root,
            &entry.path,
            &entry.sha256,
            require_executable,
        )?;
    }
    Ok(protocol_declaration())
}

fn component_entry(
    id: &str,
    version: &str,
    manifest_path: &str,
    local_path: &Path,
) -> Result<ComponentManifest, PackageManifestError> {
    Ok(ComponentManifest {
        id: id.to_owned(),
        version: version.to_owned(),
        path: manifest_path.to_owned(),
        sha256: sha256_regular_file(local_path, true)?,
    })
}

fn supporting_file_entry(
    id: &str,
    manifest_path: &str,
    local_path: &Path,
) -> Result<SupportingFileManifest, PackageManifestError> {
    Ok(SupportingFileManifest {
        id: id.to_owned(),
        path: manifest_path.to_owned(),
        sha256: sha256_regular_file(local_path, false)?,
    })
}

fn load_component_metadata(
    executable: &Path,
    expected_component: PackagedComponent,
) -> Result<ComponentMetadata, PackageManifestError> {
    sha256_regular_file(executable, true)?;
    let output = Command::new(executable)
        .arg("--component-metadata")
        .output()
        .map_err(|_| PackageManifestError::ComponentMetadataUnavailable)?;
    if !output.status.success()
        || !output.stderr.is_empty()
        || output.stdout.is_empty()
        || output.stdout.len() > MAX_COMPONENT_METADATA_BYTES
    {
        return Err(PackageManifestError::ComponentMetadataUnavailable);
    }
    decode_component_metadata(&output.stdout, expected_component)
}

fn load_component_metadata_file(
    path: &Path,
    expected_component: PackagedComponent,
) -> Result<ComponentMetadata, PackageManifestError> {
    let bytes = read_bounded_regular_file(path, MAX_COMPONENT_METADATA_BYTES)?;
    decode_component_metadata(&bytes, expected_component)
}

fn decode_component_metadata(
    bytes: &[u8],
    expected_component: PackagedComponent,
) -> Result<ComponentMetadata, PackageManifestError> {
    let metadata: ComponentMetadata = serde_json::from_slice(bytes)
        .map_err(|_| PackageManifestError::InvalidComponentMetadata)?;
    let expected = ComponentMetadata::current(expected_component, metadata.component_version())
        .map_err(|_| PackageManifestError::InvalidComponentMetadata)?;
    if metadata != expected {
        return Err(if metadata.component() == expected_component {
            PackageManifestError::IncompatibleProtocol
        } else {
            PackageManifestError::UnexpectedComponent
        });
    }
    Ok(metadata)
}

fn require_shared_protocol<const N: usize>(
    components: [&ComponentMetadata; N],
) -> Result<(), PackageManifestError> {
    if components.iter().any(|metadata| {
        metadata.broker_protocol().name() != BROKER_PROTOCOL_NAME
            || metadata.broker_protocol().major() != BROKER_PROTOCOL_MAJOR
            || metadata.broker_protocol().minor() != BROKER_PROTOCOL_MINOR
    }) {
        return Err(PackageManifestError::IncompatibleProtocol);
    }
    Ok(())
}

fn read_protocol_manifest(path: &Path) -> Result<ProtocolManifest, PackageManifestError> {
    let bytes = read_bounded_regular_file(path, MAX_PROTOCOL_MANIFEST_BYTES)?;
    serde_json::from_slice(&bytes).map_err(|_| PackageManifestError::InvalidProtocolManifest)
}

fn validate_manifest_contract(
    manifest: &ProtocolManifest,
    product_version: &str,
    architecture: &str,
) -> Result<(), PackageManifestError> {
    let expected_components = [
        ("macos-app", APP_MANIFEST_PATH),
        ("broker", BROKER_MANIFEST_PATH),
        ("mcp-adapter", MCP_MANIFEST_PATH),
        ("cli", CLI_MANIFEST_PATH),
    ];
    let expected_supporting_files = [
        ("rust-ffi", FFI_MANIFEST_PATH),
        ("app-component-metadata", APP_METADATA_MANIFEST_PATH),
    ];
    if manifest.schema != PROTOCOL_MANIFEST_SCHEMA
        || manifest.component_metadata_schema != COMPONENT_METADATA_SCHEMA
        || manifest.product.name != "KeptNear"
        || manifest.product.version != product_version
        || manifest.product.architecture != architecture
        || validate_atom(&manifest.product.git_revision).is_err()
        || !valid_source_worktree(&manifest.product.source_worktree)
        || !valid_utc_timestamp(&manifest.product.generated_at_utc)
        || manifest.shared_protocol.name != BROKER_PROTOCOL_NAME
        || manifest.shared_protocol.major != BROKER_PROTOCOL_MAJOR
        || manifest.shared_protocol.minor != BROKER_PROTOCOL_MINOR
        || manifest.installation != InstallationManifest::current()
        || manifest.components.len() != 4
        || manifest.supporting_files.len() != 2
        || manifest
            .components
            .iter()
            .zip(expected_components)
            .any(|(entry, (id, path))| {
                entry.id != id
                    || entry.path != path
                    || validate_atom(&entry.version).is_err()
                    || !valid_sha256(&entry.sha256)
            })
        || manifest
            .supporting_files
            .iter()
            .zip(expected_supporting_files)
            .any(|(entry, (id, path))| {
                entry.id != id || entry.path != path || !valid_sha256(&entry.sha256)
            })
    {
        return Err(PackageManifestError::InvalidProtocolManifest);
    }
    Ok(())
}

fn verify_manifest_hash(
    root: &Path,
    manifest_path: &str,
    expected_sha256: &str,
    require_executable: bool,
) -> Result<(), PackageManifestError> {
    if !valid_sha256(expected_sha256) {
        return Err(PackageManifestError::InvalidProtocolManifest);
    }
    let actual = sha256_regular_file(
        &resolve_manifest_path(root, manifest_path),
        require_executable,
    )?;
    if actual != expected_sha256 {
        return Err(PackageManifestError::HashMismatch);
    }
    Ok(())
}

fn resolve_manifest_path(root: &Path, manifest_path: &str) -> PathBuf {
    root.join(manifest_path)
}

fn sha256_regular_file(
    path: &Path,
    require_executable: bool,
) -> Result<String, PackageManifestError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PackageManifestError::ComponentFileUnavailable)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(PackageManifestError::ComponentFileUnavailable);
    }
    #[cfg(unix)]
    if require_executable {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(PackageManifestError::ComponentFileUnavailable);
        }
    }
    #[cfg(not(unix))]
    let _ = require_executable;

    let mut reader = BufReader::new(
        File::open(path).map_err(|_| PackageManifestError::ComponentFileUnavailable)?,
    );
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|_| PackageManifestError::ComponentFileUnavailable)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn read_bounded_regular_file(
    path: &Path,
    maximum_bytes: usize,
) -> Result<Vec<u8>, PackageManifestError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| PackageManifestError::ComponentFileUnavailable)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > maximum_bytes as u64
    {
        return Err(PackageManifestError::ComponentFileUnavailable);
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|mut file| file.read_to_end(&mut bytes))
        .map_err(|_| PackageManifestError::ComponentFileUnavailable)?;
    if bytes.is_empty() || bytes.len() > maximum_bytes {
        return Err(PackageManifestError::ComponentFileUnavailable);
    }
    Ok(bytes)
}

fn write_manifest(output: &Path, manifest: &ProtocolManifest) -> Result<(), PackageManifestError> {
    if output.exists() {
        return Err(PackageManifestError::OutputAlreadyExists);
    }
    let parent = output
        .parent()
        .filter(|path| path.is_dir())
        .ok_or(PackageManifestError::OutputUnavailable)?;
    let file_name = output
        .file_name()
        .ok_or(PackageManifestError::OutputUnavailable)?;
    let temporary = parent.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        process::id()
    ));
    let file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)
        .map_err(|_| PackageManifestError::OutputUnavailable)?;
    let mut writer = BufWriter::new(file);
    let result = (|| {
        serde_json::to_writer_pretty(&mut writer, manifest)
            .map_err(|_| PackageManifestError::OutputUnavailable)?;
        writer
            .write_all(b"\n")
            .map_err(|_| PackageManifestError::OutputUnavailable)?;
        writer
            .flush()
            .map_err(|_| PackageManifestError::OutputUnavailable)?;
        writer
            .get_ref()
            .sync_all()
            .map_err(|_| PackageManifestError::OutputUnavailable)?;
        fs::rename(&temporary, output).map_err(|_| PackageManifestError::OutputUnavailable)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_atom(value: &str) -> Result<(), PackageManifestError> {
    if value.is_empty()
        || value.len() > 128
        || !value.is_ascii()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'_'))
    {
        return Err(PackageManifestError::InvalidArgument);
    }
    Ok(())
}

fn valid_source_worktree(value: &str) -> bool {
    matches!(value, "clean" | "dirty" | "unavailable")
}

fn valid_utc_timestamp(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn protocol_declaration() -> String {
    format!("{BROKER_PROTOCOL_NAME}/{BROKER_PROTOCOL_MAJOR}.{BROKER_PROTOCOL_MINOR}")
}

struct GenerateArguments {
    product_version: String,
    architecture: String,
    git_revision: String,
    source_worktree: String,
    generated_at_utc: String,
    output: PathBuf,
    app_executable: PathBuf,
    app_metadata: PathBuf,
    app_metadata_file: PathBuf,
    broker: PathBuf,
    mcp: PathBuf,
    cli: PathBuf,
    ffi: PathBuf,
}

impl GenerateArguments {
    fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, PackageManifestError> {
        let mut values = parse_options(
            arguments,
            &[
                "--product-version",
                "--architecture",
                "--git-revision",
                "--source-worktree",
                "--generated-at-utc",
                "--output",
                "--app-executable",
                "--app-metadata",
                "--app-metadata-file",
                "--broker",
                "--mcp",
                "--cli",
                "--ffi",
            ],
        )?;
        Ok(Self {
            product_version: required_string(&mut values, "--product-version")?,
            architecture: required_string(&mut values, "--architecture")?,
            git_revision: required_string(&mut values, "--git-revision")?,
            source_worktree: required_string(&mut values, "--source-worktree")?,
            generated_at_utc: required_string(&mut values, "--generated-at-utc")?,
            output: required_path(&mut values, "--output")?,
            app_executable: required_path(&mut values, "--app-executable")?,
            app_metadata: required_path(&mut values, "--app-metadata")?,
            app_metadata_file: required_path(&mut values, "--app-metadata-file")?,
            broker: required_path(&mut values, "--broker")?,
            mcp: required_path(&mut values, "--mcp")?,
            cli: required_path(&mut values, "--cli")?,
            ffi: required_path(&mut values, "--ffi")?,
        })
    }
}

struct VerifyArguments {
    manifest: PathBuf,
    root: PathBuf,
    product_version: String,
    architecture: String,
}

impl VerifyArguments {
    fn parse(arguments: impl IntoIterator<Item = OsString>) -> Result<Self, PackageManifestError> {
        let mut values = parse_options(
            arguments,
            &[
                "--manifest",
                "--root",
                "--product-version",
                "--architecture",
            ],
        )?;
        Ok(Self {
            manifest: required_path(&mut values, "--manifest")?,
            root: required_path(&mut values, "--root")?,
            product_version: required_string(&mut values, "--product-version")?,
            architecture: required_string(&mut values, "--architecture")?,
        })
    }
}

fn parse_options(
    arguments: impl IntoIterator<Item = OsString>,
    allowed: &[&str],
) -> Result<BTreeMap<String, OsString>, PackageManifestError> {
    let arguments = arguments.into_iter().collect::<Vec<_>>();
    if arguments.len() != allowed.len() * 2 {
        return Err(PackageManifestError::InvalidArgument);
    }
    let mut values = BTreeMap::new();
    for pair in arguments.chunks_exact(2) {
        let option = pair[0]
            .to_str()
            .ok_or(PackageManifestError::InvalidArgument)?;
        if !allowed.contains(&option) || values.insert(option.to_owned(), pair[1].clone()).is_some()
        {
            return Err(PackageManifestError::InvalidArgument);
        }
    }
    Ok(values)
}

fn required_string(
    values: &mut BTreeMap<String, OsString>,
    key: &str,
) -> Result<String, PackageManifestError> {
    values
        .remove(key)
        .and_then(|value| value.into_string().ok())
        .ok_or(PackageManifestError::InvalidArgument)
}

fn required_path(
    values: &mut BTreeMap<String, OsString>,
    key: &str,
) -> Result<PathBuf, PackageManifestError> {
    values
        .remove(key)
        .map(PathBuf::from)
        .ok_or(PackageManifestError::InvalidArgument)
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProtocolManifest {
    schema: String,
    component_metadata_schema: String,
    product: ProductManifest,
    shared_protocol: SharedProtocolManifest,
    installation: InstallationManifest,
    components: Vec<ComponentManifest>,
    supporting_files: Vec<SupportingFileManifest>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ProductManifest {
    name: String,
    version: String,
    architecture: String,
    git_revision: String,
    source_worktree: String,
    generated_at_utc: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SharedProtocolManifest {
    name: String,
    major: u16,
    minor: u16,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct InstallationManifest {
    app: String,
    broker: String,
    mcp_adapter: String,
    cli: String,
}

impl InstallationManifest {
    fn current() -> Self {
        Self {
            app: APP_INSTALL_PATH.to_owned(),
            broker: BROKER_INSTALL_PATH.to_owned(),
            mcp_adapter: MCP_INSTALL_PATH.to_owned(),
            cli: CLI_INSTALL_PATH.to_owned(),
        }
    }
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct ComponentManifest {
    id: String,
    version: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SupportingFileManifest {
    id: String,
    path: String,
    sha256: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PackageManifestError {
    InvalidArgument,
    ComponentMetadataUnavailable,
    InvalidComponentMetadata,
    UnexpectedComponent,
    IncompatibleProtocol,
    ComponentFileUnavailable,
    InvalidProtocolManifest,
    HashMismatch,
    OutputAlreadyExists,
    OutputUnavailable,
}

impl std::fmt::Display for PackageManifestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidArgument => "arguments are invalid",
            Self::ComponentMetadataUnavailable => "component metadata is unavailable",
            Self::InvalidComponentMetadata => "component metadata is invalid",
            Self::UnexpectedComponent => "component identity is unexpected",
            Self::IncompatibleProtocol => "component Broker protocols are incompatible",
            Self::ComponentFileUnavailable => "a component file is unavailable",
            Self::InvalidProtocolManifest => "the protocol manifest is invalid",
            Self::HashMismatch => "a component hash does not match the protocol manifest",
            Self::OutputAlreadyExists => "the output manifest already exists",
            Self::OutputUnavailable => "the output manifest is unavailable",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for PackageManifestError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_arguments() -> Vec<OsString> {
        [
            "--product-version",
            "0.1.0-alpha",
            "--architecture",
            "arm64",
            "--git-revision",
            "abc123",
            "--source-worktree",
            "dirty",
            "--generated-at-utc",
            "2026-07-30T12:34:56Z",
            "--output",
            "/tmp/manifest.json",
            "--app-executable",
            "/tmp/app",
            "--app-metadata",
            "/tmp/app-metadata",
            "--app-metadata-file",
            "/tmp/app-metadata.json",
            "--broker",
            "/tmp/broker",
            "--mcp",
            "/tmp/mcp",
            "--cli",
            "/tmp/cli",
            "--ffi",
            "/tmp/ffi",
        ]
        .map(OsString::from)
        .to_vec()
    }

    fn valid_protocol_manifest() -> ProtocolManifest {
        ProtocolManifest {
            schema: PROTOCOL_MANIFEST_SCHEMA.to_owned(),
            component_metadata_schema: COMPONENT_METADATA_SCHEMA.to_owned(),
            product: ProductManifest {
                name: "KeptNear".to_owned(),
                version: "0.1.0-alpha".to_owned(),
                architecture: "arm64".to_owned(),
                git_revision: "abc123".to_owned(),
                source_worktree: "clean".to_owned(),
                generated_at_utc: "2026-07-30T12:34:56Z".to_owned(),
            },
            shared_protocol: SharedProtocolManifest {
                name: BROKER_PROTOCOL_NAME.to_owned(),
                major: BROKER_PROTOCOL_MAJOR,
                minor: BROKER_PROTOCOL_MINOR,
            },
            installation: InstallationManifest::current(),
            components: [
                ("macos-app", APP_MANIFEST_PATH),
                ("broker", BROKER_MANIFEST_PATH),
                ("mcp-adapter", MCP_MANIFEST_PATH),
                ("cli", CLI_MANIFEST_PATH),
            ]
            .into_iter()
            .map(|(id, path)| ComponentManifest {
                id: id.to_owned(),
                version: "0.1.0".to_owned(),
                path: path.to_owned(),
                sha256: "a".repeat(64),
            })
            .collect(),
            supporting_files: [
                ("rust-ffi", FFI_MANIFEST_PATH),
                ("app-component-metadata", APP_METADATA_MANIFEST_PATH),
            ]
            .into_iter()
            .map(|(id, path)| SupportingFileManifest {
                id: id.to_owned(),
                path: path.to_owned(),
                sha256: "b".repeat(64),
            })
            .collect(),
        }
    }

    #[test]
    fn argument_parsers_require_every_unique_closed_option() {
        let valid = generate_arguments();
        assert!(GenerateArguments::parse(valid.clone()).is_ok());
        assert_eq!(
            GenerateArguments::parse(
                valid
                    .iter()
                    .cloned()
                    .chain([OsString::from("--output"), OsString::from("/tmp/other")])
            )
            .err(),
            Some(PackageManifestError::InvalidArgument)
        );
        assert_eq!(
            GenerateArguments::parse(valid.into_iter().take(24)).err(),
            Some(PackageManifestError::InvalidArgument)
        );
        assert!(VerifyArguments::parse(
            [
                "--manifest",
                "/tmp/manifest",
                "--root",
                "/tmp/root",
                "--product-version",
                "0.1.0-alpha",
                "--architecture",
                "arm64",
            ]
            .map(OsString::from)
        )
        .is_ok());
    }

    #[test]
    fn manifest_values_are_closed_and_install_paths_are_fixed() {
        assert!(validate_atom("0.1.0-alpha+local").is_ok());
        assert!(validate_atom("0.1.0 alpha").is_err());
        assert!(validate_atom("0.1.0\"").is_err());
        assert!(valid_utc_timestamp("2026-07-30T12:34:56Z"));
        assert!(!valid_utc_timestamp("2026-7-30T12:34:56Z"));
        assert!(!valid_utc_timestamp("2026-07-30T12:34:56+00:00"));
        assert!(valid_sha256(&"a".repeat(64)));
        assert!(!valid_sha256(&"A".repeat(64)));
        assert_eq!(
            InstallationManifest::current(),
            InstallationManifest {
                app: "/Applications/KeptNear.app".to_owned(),
                broker: "/Applications/KeptNear.app/Contents/Helpers/keptnear-broker".to_owned(),
                mcp_adapter: "/Applications/KeptNear.app/Contents/Helpers/keptnear-mcp".to_owned(),
                cli: "/Applications/KeptNear.app/Contents/Helpers/keptnear".to_owned(),
            }
        );
    }

    #[test]
    fn protocol_manifest_rejects_unknown_fields() {
        let value = serde_json::json!({
            "schema": PROTOCOL_MANIFEST_SCHEMA,
            "component_metadata_schema": COMPONENT_METADATA_SCHEMA,
            "product": {
                "name": "KeptNear",
                "version": "0.1.0",
                "architecture": "arm64",
                "git_revision": "abc123",
                "source_worktree": "clean",
                "generated_at_utc": "2026-07-30T12:34:56Z"
            },
            "shared_protocol": {
                "name": BROKER_PROTOCOL_NAME,
                "major": BROKER_PROTOCOL_MAJOR,
                "minor": BROKER_PROTOCOL_MINOR
            },
            "installation": InstallationManifest::current(),
            "components": [],
            "supporting_files": [],
            "unexpected": true
        });
        assert!(serde_json::from_value::<ProtocolManifest>(value).is_err());
    }

    #[test]
    fn protocol_manifest_requires_complete_catalog_hashes_and_install_paths() {
        let mut manifest = valid_protocol_manifest();
        assert!(validate_manifest_contract(&manifest, "0.1.0-alpha", "arm64").is_ok());

        let missing_mcp = manifest.components.remove(2);
        assert_eq!(missing_mcp.id, "mcp-adapter");
        assert_eq!(
            validate_manifest_contract(&manifest, "0.1.0-alpha", "arm64"),
            Err(PackageManifestError::InvalidProtocolManifest)
        );

        let mut manifest = valid_protocol_manifest();
        manifest.components[1].sha256 = "A".repeat(64);
        assert_eq!(
            validate_manifest_contract(&manifest, "0.1.0-alpha", "arm64"),
            Err(PackageManifestError::InvalidProtocolManifest)
        );

        let mut manifest = valid_protocol_manifest();
        manifest.installation.cli = "/usr/local/bin/keptnear".to_owned();
        assert_eq!(
            validate_manifest_contract(&manifest, "0.1.0-alpha", "arm64"),
            Err(PackageManifestError::InvalidProtocolManifest)
        );
    }
}
