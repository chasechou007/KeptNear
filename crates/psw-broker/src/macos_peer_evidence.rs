use std::mem::{size_of, MaybeUninit};
use std::os::fd::RawFd;
use std::ptr;
use std::slice;

use core_foundation::base::{CFType, CFTypeRef, OSStatus, TCFType};
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFDictionaryRef};
use core_foundation::string::{CFString, CFStringRef};
use nix::libc;
use security_framework_sys::base::errSecSuccess;
use security_framework_sys::code_signing::{
    kSecCSNoNetworkAccess, kSecCSStrictValidate, kSecGuestAttributeAudit, SecCodeCheckValidity,
    SecCodeCopyGuestWithAttributes, SecCodeRef, SecStaticCodeRef,
};
use sha2::{Digest, Sha256};

use crate::state_model::ObservedConsumerIdentity;

const AUDIT_TOKEN_VALUE_COUNT: usize = 8;
const AUDIT_TOKEN_EFFECTIVE_USER_INDEX: usize = 1;
const AUDIT_TOKEN_PROCESS_ID_INDEX: usize = 5;
const PROCESS_NAME_BUFFER_LENGTH: usize = 1024;
const EXECUTABLE_NAME_MAX_BYTES: usize = 128;
const BUNDLE_IDENTIFIER_MAX_BYTES: usize = 255;
const TEAM_IDENTIFIER_MAX_BYTES: usize = 64;
const K_SEC_CS_SIGNING_INFORMATION: u32 = 1 << 1;

extern "C" {
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecCodeInfoUnique: CFStringRef;

    fn SecCodeCopySigningInformation(
        code: SecStaticCodeRef,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> OSStatus;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AuditToken {
    values: [u32; AUDIT_TOKEN_VALUE_COUNT],
}

impl AuditToken {
    fn effective_user_id(self) -> u32 {
        self.values[AUDIT_TOKEN_EFFECTIVE_USER_INDEX]
    }

    fn process_id(self) -> Option<u32> {
        let process_id = self.values[AUDIT_TOKEN_PROCESS_ID_INDEX];
        (process_id != 0 && i32::try_from(process_id).is_ok()).then_some(process_id)
    }

    fn as_bytes(&self) -> &[u8] {
        // SAFETY: AuditToken is repr(C), contains only eight u32 values, and
        // the resulting slice cannot outlive this borrowed value.
        unsafe {
            slice::from_raw_parts(
                (self as *const AuditToken).cast::<u8>(),
                size_of::<AuditToken>(),
            )
        }
    }
}

pub(crate) struct MacOsPeerObservation {
    pub(crate) process_id: Option<u32>,
    pub(crate) identity: ObservedConsumerIdentity,
}

pub(crate) fn observe_peer(socket: RawFd, expected_effective_user_id: u32) -> MacOsPeerObservation {
    let Some(audit_token) = read_peer_audit_token(socket)
        .filter(|token| token.effective_user_id() == expected_effective_user_id)
    else {
        return MacOsPeerObservation {
            process_id: None,
            identity: ObservedConsumerIdentity::default(),
        };
    };
    let process_id = audit_token.process_id();
    let executable_name = process_id.and_then(read_process_name);
    let signing = read_verified_signing_evidence(&audit_token);
    let identity = ObservedConsumerIdentity::new(
        executable_name,
        signing
            .as_ref()
            .and_then(|evidence| evidence.bundle_identifier.clone()),
        signing
            .as_ref()
            .and_then(|evidence| evidence.team_identifier.clone()),
        signing.map(|evidence| evidence.digest),
    )
    .unwrap_or_default();
    MacOsPeerObservation {
        process_id,
        identity,
    }
}

fn read_peer_audit_token(socket: RawFd) -> Option<AuditToken> {
    let mut token = MaybeUninit::<AuditToken>::uninit();
    let mut length = libc::socklen_t::try_from(size_of::<AuditToken>()).ok()?;
    // SAFETY: token points to writable storage of exactly `length` bytes and
    // getsockopt receives a valid connected Unix socket descriptor.
    let status = unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if status != 0 || usize::try_from(length).ok()? != size_of::<AuditToken>() {
        return None;
    }
    // SAFETY: a successful exact-length getsockopt initialized every byte.
    Some(unsafe { token.assume_init() })
}

fn read_process_name(process_id: u32) -> Option<String> {
    let process_id = i32::try_from(process_id).ok()?;
    let mut buffer = [0_u8; PROCESS_NAME_BUFFER_LENGTH];
    // SAFETY: proc_name receives a valid writable buffer and its exact size.
    let length = unsafe {
        libc::proc_name(
            process_id,
            buffer.as_mut_ptr().cast(),
            u32::try_from(buffer.len()).ok()?,
        )
    };
    let length = usize::try_from(length).ok()?;
    if length == 0 || length > buffer.len() {
        return None;
    }
    let name = std::str::from_utf8(&buffer[..length]).ok()?;
    sanitize_executable_name(name)
}

struct VerifiedSigningEvidence {
    bundle_identifier: Option<String>,
    team_identifier: Option<String>,
    digest: [u8; 32],
}

fn read_verified_signing_evidence(audit_token: &AuditToken) -> Option<VerifiedSigningEvidence> {
    let code = copy_guest_code(audit_token)?;
    // SAFETY: code is a retained valid SecCodeRef. The null requirement means
    // validate the code's own designated requirement. Network access is
    // explicitly disabled.
    let validation = unsafe {
        SecCodeCheckValidity(
            code.reference,
            kSecCSStrictValidate | kSecCSNoNetworkAccess,
            ptr::null_mut(),
        )
    };
    if validation != errSecSuccess {
        return None;
    }
    let information = copy_signing_information(code.reference)?;
    let unique = dictionary_data(&information, unsafe { kSecCodeInfoUnique })?;
    if unique.is_empty() {
        return None;
    }
    let digest = Sha256::digest(unique);
    let bundle_identifier = dictionary_string(&information, unsafe { kSecCodeInfoIdentifier })
        .and_then(sanitize_bundle_identifier);
    let team_identifier = dictionary_string(&information, unsafe { kSecCodeInfoTeamIdentifier })
        .and_then(sanitize_team_identifier);
    Some(VerifiedSigningEvidence {
        bundle_identifier,
        team_identifier,
        digest: digest.into(),
    })
}

struct OwnedSecCode {
    reference: SecCodeRef,
    _owner: CFType,
}

fn copy_guest_code(audit_token: &AuditToken) -> Option<OwnedSecCode> {
    // SAFETY: kSecGuestAttributeAudit is a process-lifetime CFString exported
    // by Security.framework.
    let key = unsafe { CFString::wrap_under_get_rule(kSecGuestAttributeAudit) };
    let attributes = CFDictionary::from_CFType_pairs(&[(
        key,
        CFData::from_buffer(audit_token.as_bytes()).into_CFType(),
    )]);
    let mut reference: SecCodeRef = ptr::null_mut();
    // SAFETY: attributes owns a valid audit-token CFData for the call and the
    // output pointer is writable. A null host selects the system root host.
    let status = unsafe {
        SecCodeCopyGuestWithAttributes(
            ptr::null_mut(),
            attributes.as_concrete_TypeRef(),
            0,
            &mut reference,
        )
    };
    if status != errSecSuccess || reference.is_null() {
        return None;
    }
    // SAFETY: the successful copy call returns one create-rule CF object.
    let owner = unsafe {
        CFType::wrap_under_create_rule(reference.cast::<std::ffi::c_void>() as CFTypeRef)
    };
    Some(OwnedSecCode {
        reference,
        _owner: owner,
    })
}

fn copy_signing_information(code: SecCodeRef) -> Option<CFDictionary<CFString, CFType>> {
    let mut information: CFDictionaryRef = ptr::null();
    // SAFETY: code is a live retained SecCodeRef and the output pointer is
    // writable. Security.framework accepts dynamic code here and returns its
    // corresponding static signing information.
    let status = unsafe {
        SecCodeCopySigningInformation(code.cast(), K_SEC_CS_SIGNING_INFORMATION, &mut information)
    };
    if status != errSecSuccess || information.is_null() {
        return None;
    }
    // SAFETY: the successful copy call returns one create-rule dictionary.
    Some(unsafe { CFDictionary::wrap_under_create_rule(information) })
}

fn dictionary_string(
    dictionary: &CFDictionary<CFString, CFType>,
    key: CFStringRef,
) -> Option<String> {
    // SAFETY: callers pass process-lifetime Security.framework CFString keys.
    let key = unsafe { CFString::wrap_under_get_rule(key) };
    dictionary
        .find(&key)?
        .downcast::<CFString>()
        .map(|value| value.to_string())
}

fn dictionary_data(
    dictionary: &CFDictionary<CFString, CFType>,
    key: CFStringRef,
) -> Option<Vec<u8>> {
    // SAFETY: callers pass process-lifetime Security.framework CFString keys.
    let key = unsafe { CFString::wrap_under_get_rule(key) };
    dictionary
        .find(&key)?
        .downcast::<CFData>()
        .map(|value| value.bytes().to_vec())
}

fn sanitize_executable_name(value: &str) -> Option<String> {
    (value.len() <= EXECUTABLE_NAME_MAX_BYTES
        && !value.trim().is_empty()
        && !value.contains('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control))
    .then(|| value.to_owned())
}

fn sanitize_bundle_identifier(value: String) -> Option<String> {
    (value.contains('.') && is_bounded_identifier(&value, BUNDLE_IDENTIFIER_MAX_BYTES))
        .then_some(value)
}

fn sanitize_team_identifier(value: String) -> Option<String> {
    is_bounded_identifier(&value, TEAM_IDENTIFIER_MAX_BYTES).then_some(value)
}

fn is_bounded_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;

    use nix::unistd::geteuid;

    use super::*;

    #[test]
    fn live_socket_observation_returns_path_free_process_evidence() {
        let (left, _right) = UnixStream::pair().expect("socket pair");
        let observation = observe_peer(left.as_raw_fd(), geteuid().as_raw());

        assert_eq!(observation.process_id, Some(std::process::id()));
        let executable_name = observation
            .identity
            .executable_name()
            .expect("executable basename");
        assert!(!executable_name.contains('/'));
        assert!(!executable_name.contains('\\'));
        assert!(executable_name.len() <= EXECUTABLE_NAME_MAX_BYTES);
        assert_eq!(
            observation.identity.code_signing_evidence(),
            crate::ConsumerCodeSigningEvidence::VerifiedWithoutTeamIdentifier
        );
        assert_eq!(observation.identity.team_identifier(), None);
        assert!(observation.identity.code_signature_fingerprint().is_some());
    }

    #[test]
    fn wrong_user_discards_process_and_signing_evidence_without_failing() {
        let (left, _right) = UnixStream::pair().expect("socket pair");
        let observation = observe_peer(left.as_raw_fd(), geteuid().as_raw().wrapping_add(1));

        assert_eq!(observation.process_id, None);
        assert_eq!(observation.identity, ObservedConsumerIdentity::default());
    }

    #[test]
    fn sanitizers_reject_paths_controls_and_unbounded_identifiers() {
        assert_eq!(
            sanitize_executable_name("adapter"),
            Some("adapter".to_owned())
        );
        assert_eq!(sanitize_executable_name("/usr/bin/adapter"), None);
        assert_eq!(sanitize_executable_name("bad\nname"), None);
        assert_eq!(sanitize_bundle_identifier("adapter".to_owned()), None);
        assert_eq!(
            sanitize_bundle_identifier("com.example.adapter".to_owned()),
            Some("com.example.adapter".to_owned())
        );
        assert_eq!(
            sanitize_team_identifier("TEAM_123".to_owned()),
            Some("TEAM_123".to_owned())
        );
        assert_eq!(sanitize_team_identifier("bad/team".to_owned()), None);
    }
}
