use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::CFDictionary;
use core_foundation::string::CFString;
use security_framework_sys::access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
use security_framework_sys::base::{
    errSecDuplicateItem, errSecItemNotFound, errSecParam, errSecSuccess,
};
use security_framework_sys::item::{
    kSecAttrAccount, kSecAttrLabel, kSecAttrService, kSecClass, kSecClassGenericPassword,
    kSecReturnData, kSecUseDataProtectionKeychain, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching};

use crate::identity::{
    ClientIdentityKind, ConsumerIdentity, ConsumerIdentityStore, IdentityStoreError,
    PairingProfileId,
};

const MCP_IDENTITY_SERVICE: &str = "app.keptnear.mcp.consumer-key.v1";
const CLI_IDENTITY_SERVICE: &str = "app.keptnear.cli.consumer-key.v1";
const MCP_DEFAULT_IDENTITY_ACCOUNT: &str = "default-v1";
const MCP_PROFILE_IDENTITY_ACCOUNT_PREFIX: &str = "profile-v1:";
const MCP_IDENTITY_LABEL: &str = "KeptNear MCP Consumer key";
const CLI_IDENTITY_LABEL: &str = "KeptNear CLI Consumer key";

extern "C" {
    static kSecAttrAccessible: core_foundation::string::CFStringRef;
    static kSecAttrSynchronizable: core_foundation::string::CFStringRef;
}

#[derive(Clone, Debug)]
pub(crate) struct MacOsConsumerIdentityStore {
    client_kind: ClientIdentityKind,
    profile: PairingProfileId,
}

impl MacOsConsumerIdentityStore {
    pub(crate) const fn new(client_kind: ClientIdentityKind, profile: PairingProfileId) -> Self {
        Self {
            client_kind,
            profile,
        }
    }

    const fn service(&self) -> &'static str {
        match self.client_kind {
            ClientIdentityKind::Cli => CLI_IDENTITY_SERVICE,
            ClientIdentityKind::Mcp => MCP_IDENTITY_SERVICE,
        }
    }

    const fn label(&self) -> &'static str {
        match self.client_kind {
            ClientIdentityKind::Cli => CLI_IDENTITY_LABEL,
            ClientIdentityKind::Mcp => MCP_IDENTITY_LABEL,
        }
    }

    fn account(&self) -> String {
        if self.profile.is_default() {
            MCP_DEFAULT_IDENTITY_ACCOUNT.to_owned()
        } else {
            format!(
                "{MCP_PROFILE_IDENTITY_ACCOUNT_PREFIX}{}",
                self.profile.as_str()
            )
        }
    }

    fn base_query(&self) -> Vec<(CFString, CFType)> {
        let account = self.account();
        // SAFETY: each symbol is a process-lifetime CFString exported by
        // Security.framework.
        unsafe {
            vec![
                (
                    CFString::wrap_under_get_rule(kSecClass),
                    CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrService),
                    CFString::new(self.service()).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrAccount),
                    CFString::new(&account).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecUseDataProtectionKeychain),
                    CFBoolean::true_value().into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrSynchronizable),
                    CFBoolean::false_value().into_CFType(),
                ),
            ]
        }
    }
}

impl ConsumerIdentityStore for MacOsConsumerIdentityStore {
    fn load(&self) -> Result<Option<ConsumerIdentity>, IdentityStoreError> {
        match copy_generic_password(self.base_query()) {
            Ok(bytes) => ConsumerIdentity::from_stored_bytes(bytes).map(Some),
            Err(status) if status == errSecItemNotFound => Ok(None),
            Err(_) => Err(IdentityStoreError::Unavailable),
        }
    }

    fn create(&self, identity: &ConsumerIdentity) -> Result<(), IdentityStoreError> {
        add_generic_password(self.base_query(), self.label(), identity.expose_seed()).map_err(
            |status| {
                if status == errSecDuplicateItem {
                    IdentityStoreError::AlreadyExists
                } else {
                    IdentityStoreError::Unavailable
                }
            },
        )
    }
}

fn add_generic_password(
    query: Vec<(CFString, CFType)>,
    label: &str,
    seed: &[u8],
) -> Result<(), i32> {
    let query = add_query(query, label, seed);
    let dictionary = CFDictionary::from_CFType_pairs(&query);

    // SAFETY: the dictionary owns valid Core Foundation keys and values for
    // the duration of the call; no result pointer is requested.
    let status = unsafe { SecItemAdd(dictionary.as_concrete_TypeRef(), std::ptr::null_mut()) };
    if status == errSecSuccess {
        Ok(())
    } else {
        Err(status)
    }
}

fn add_query(
    mut query: Vec<(CFString, CFType)>,
    label: &str,
    seed: &[u8],
) -> Vec<(CFString, CFType)> {
    // SAFETY: each symbol is a process-lifetime CFString exported by
    // Security.framework.
    unsafe {
        query.extend([
            (
                CFString::wrap_under_get_rule(kSecAttrAccessible),
                CFString::wrap_under_get_rule(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
                    .into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecAttrLabel),
                CFString::new(label).into_CFType(),
            ),
            (
                CFString::wrap_under_get_rule(kSecValueData),
                CFData::from_buffer(seed).into_CFType(),
            ),
        ]);
    }
    query
}

fn copy_generic_password(query: Vec<(CFString, CFType)>) -> Result<Vec<u8>, i32> {
    let query = load_query(query);
    let dictionary = CFDictionary::from_CFType_pairs(&query);
    let mut result = std::ptr::null();

    // SAFETY: result is null or a create-rule Core Foundation object, which
    // is transferred into CFType immediately after a successful call.
    let status = unsafe { SecItemCopyMatching(dictionary.as_concrete_TypeRef(), &mut result) };
    if status != errSecSuccess {
        return Err(status);
    }
    if result.is_null() {
        return Err(errSecParam);
    }

    // SAFETY: successful kSecReturnData lookup owns one valid CF object.
    let value = unsafe { CFType::wrap_under_create_rule(result) };
    let data = value.downcast_into::<CFData>().ok_or(errSecParam)?;
    Ok(data.bytes().to_vec())
}

fn load_query(mut query: Vec<(CFString, CFType)>) -> Vec<(CFString, CFType)> {
    // SAFETY: kSecReturnData is a process-lifetime Security.framework key.
    query.push(unsafe {
        (
            CFString::wrap_under_get_rule(kSecReturnData),
            CFBoolean::true_value().into_CFType(),
        )
    });
    query
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query_value(
        query: &[(CFString, CFType)],
        key: core_foundation::string::CFStringRef,
    ) -> &CFType {
        // SAFETY: callers pass process-lifetime Security.framework constants.
        let key = unsafe { CFString::wrap_under_get_rule(key) };
        query
            .iter()
            .find_map(|(candidate, value)| (candidate == &key).then_some(value))
            .expect("query attribute")
    }

    #[test]
    fn identity_item_is_stable_device_only_and_non_synchronizing() {
        let store =
            MacOsConsumerIdentityStore::new(ClientIdentityKind::Mcp, PairingProfileId::default());
        let base = store.base_query();
        let create = add_query(base.clone(), store.label(), &[0x73; 32]);

        assert_eq!(MCP_IDENTITY_SERVICE, "app.keptnear.mcp.consumer-key.v1");
        assert_eq!(store.service(), MCP_IDENTITY_SERVICE);
        assert_eq!(store.account(), "default-v1");
        assert!(!MCP_IDENTITY_SERVICE.contains('/'));
        assert!(!store.account().contains('/'));
        assert!(bool::from(
            query_value(&base, unsafe { kSecUseDataProtectionKeychain })
                .downcast::<CFBoolean>()
                .expect("data protection")
        ));
        assert!(!bool::from(
            query_value(&base, unsafe { kSecAttrSynchronizable })
                .downcast::<CFBoolean>()
                .expect("synchronizable")
        ));
        let accessibility = query_value(&create, unsafe { kSecAttrAccessible })
            .downcast::<CFString>()
            .expect("accessibility");
        let expected = unsafe {
            CFString::wrap_under_get_rule(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        };
        assert_eq!(accessibility, expected);
    }

    #[test]
    fn pairing_profiles_use_distinct_accounts_and_preserve_the_legacy_default() {
        let default =
            MacOsConsumerIdentityStore::new(ClientIdentityKind::Mcp, PairingProfileId::default());
        let codex = MacOsConsumerIdentityStore::new(
            ClientIdentityKind::Mcp,
            PairingProfileId::new("Codex").expect("Codex profile"),
        );
        let claude = MacOsConsumerIdentityStore::new(
            ClientIdentityKind::Mcp,
            PairingProfileId::new("claude-code").expect("Claude profile"),
        );

        assert_eq!(default.account(), MCP_DEFAULT_IDENTITY_ACCOUNT);
        assert_eq!(codex.account(), "profile-v1:codex");
        assert_eq!(claude.account(), "profile-v1:claude-code");
        assert_ne!(codex.account(), claude.account());
        for store in [default, codex, claude] {
            let query = store.base_query();
            let account = query_value(&query, unsafe { kSecAttrAccount })
                .downcast::<CFString>()
                .expect("account");
            assert_eq!(account.to_string(), store.account());
        }
    }

    #[test]
    fn cli_and_mcp_identities_use_distinct_stable_services() {
        let cli =
            MacOsConsumerIdentityStore::new(ClientIdentityKind::Cli, PairingProfileId::default());
        let mcp =
            MacOsConsumerIdentityStore::new(ClientIdentityKind::Mcp, PairingProfileId::default());

        assert_eq!(cli.service(), "app.keptnear.cli.consumer-key.v1");
        assert_eq!(cli.label(), "KeptNear CLI Consumer key");
        assert_eq!(mcp.service(), "app.keptnear.mcp.consumer-key.v1");
        assert_eq!(mcp.label(), "KeptNear MCP Consumer key");
        assert_ne!(cli.service(), mcp.service());
        assert_eq!(cli.account(), "default-v1");
        assert_eq!(mcp.account(), "default-v1");
    }
}
