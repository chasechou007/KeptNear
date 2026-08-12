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
    kSecAttrAccessGroup, kSecAttrAccount, kSecAttrLabel, kSecAttrService, kSecClass,
    kSecClassGenericPassword, kSecReturnData, kSecUseDataProtectionKeychain, kSecValueData,
};
use security_framework_sys::keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemDelete};

use crate::device_key::{DeviceKeyStore, DeviceKeyStoreError, DeviceRootKey};
use crate::{
    is_controller_removal_marker, ControllerKeyStore, ControllerKeyStoreError,
    ControllerKeychainAccessGroup, ControllerSigningKey, CONTROLLER_KEYCHAIN_ACCOUNT,
    CONTROLLER_KEYCHAIN_LABEL, CONTROLLER_KEYCHAIN_REMOVAL_MARKER_ACCOUNT,
    CONTROLLER_KEYCHAIN_REMOVAL_MARKER_VALUE, CONTROLLER_KEYCHAIN_SERVICE,
};

const DEVICE_KEY_SERVICE: &str = "app.psw.local.device-root-key.v1";
const DEVICE_KEY_ACCOUNT: &str = "device-v1";
const DEVICE_KEY_LABEL: &str = "KeptNear device root key";
const CONTROLLER_REMOVAL_MARKER_LABEL: &str = "KeptNear controller removal marker";

extern "C" {
    static kSecAttrAccessible: core_foundation::string::CFStringRef;
    static kSecAttrSynchronizable: core_foundation::string::CFStringRef;
}

/// macOS Data Protection Keychain store for the Broker device root key.
#[derive(Clone, Copy, Debug, Default)]
pub struct MacOsDeviceKeyStore;

impl MacOsDeviceKeyStore {
    /// Creates a store bound to KeptNear's stable device-key item identity.
    pub fn new() -> Self {
        Self
    }

    fn base_query() -> Vec<(CFString, CFType)> {
        // SAFETY: every referenced symbol is a process-lifetime CFString
        // exported by Security.framework.
        unsafe {
            vec![
                (
                    CFString::wrap_under_get_rule(kSecClass),
                    CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrService),
                    CFString::new(DEVICE_KEY_SERVICE).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrAccount),
                    CFString::new(DEVICE_KEY_ACCOUNT).into_CFType(),
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

impl DeviceKeyStore for MacOsDeviceKeyStore {
    fn load(&self) -> Result<Option<DeviceRootKey>, DeviceKeyStoreError> {
        match copy_generic_password(Self::base_query()) {
            Ok(bytes) => DeviceRootKey::from_stored_bytes(bytes).map(Some),
            Err(status) if status == errSecItemNotFound => Ok(None),
            Err(status) => Err(platform_error(status)),
        }
    }

    fn create_new(&self, key: &DeviceRootKey) -> Result<(), DeviceKeyStoreError> {
        add_generic_password(Self::base_query(), key.expose(), DEVICE_KEY_LABEL).map_err(|status| {
            if status == errSecDuplicateItem {
                DeviceKeyStoreError::AlreadyExists
            } else {
                platform_error(status)
            }
        })
    }

    fn delete(&self) -> Result<bool, DeviceKeyStoreError> {
        delete_generic_password(Self::base_query()).map_err(platform_error)
    }
}

/// Data Protection Keychain store for the shared human-controller authority.
#[derive(Clone, Debug)]
pub struct MacOsControllerKeyStore {
    access_group: ControllerKeychainAccessGroup,
}

impl MacOsControllerKeyStore {
    /// Creates a store whose every query names the verified signing access group.
    #[must_use]
    pub const fn new(access_group: ControllerKeychainAccessGroup) -> Self {
        Self { access_group }
    }

    fn base_query(&self, account: &str) -> Vec<(CFString, CFType)> {
        // SAFETY: every referenced symbol is a process-lifetime CFString
        // exported by Security.framework.
        unsafe {
            vec![
                (
                    CFString::wrap_under_get_rule(kSecClass),
                    CFString::wrap_under_get_rule(kSecClassGenericPassword).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrService),
                    CFString::new(CONTROLLER_KEYCHAIN_SERVICE).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrAccount),
                    CFString::new(account).into_CFType(),
                ),
                (
                    CFString::wrap_under_get_rule(kSecAttrAccessGroup),
                    CFString::new(self.access_group.as_str()).into_CFType(),
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

impl ControllerKeyStore for MacOsControllerKeyStore {
    fn load_seed(&self) -> Result<Option<ControllerSigningKey>, ControllerKeyStoreError> {
        match copy_generic_password(self.base_query(CONTROLLER_KEYCHAIN_ACCOUNT)) {
            Ok(bytes) => ControllerSigningKey::from_stored_bytes(bytes).map(Some),
            Err(status) if status == errSecItemNotFound => Ok(None),
            Err(status) => Err(controller_platform_error(status)),
        }
    }

    fn create_seed(&self, key: &ControllerSigningKey) -> Result<(), ControllerKeyStoreError> {
        add_generic_password(
            self.base_query(CONTROLLER_KEYCHAIN_ACCOUNT),
            key.expose_seed(),
            CONTROLLER_KEYCHAIN_LABEL,
        )
        .map_err(map_controller_add_error)
    }

    fn delete_seed(&self) -> Result<bool, ControllerKeyStoreError> {
        delete_generic_password(self.base_query(CONTROLLER_KEYCHAIN_ACCOUNT))
            .map_err(controller_platform_error)
    }

    fn removal_pending(&self) -> Result<bool, ControllerKeyStoreError> {
        match copy_generic_password(self.base_query(CONTROLLER_KEYCHAIN_REMOVAL_MARKER_ACCOUNT)) {
            Ok(bytes) if is_controller_removal_marker(&bytes) => Ok(true),
            Ok(_) => Err(ControllerKeyStoreError::InvalidRemovalMarker),
            Err(status) if status == errSecItemNotFound => Ok(false),
            Err(status) => Err(controller_platform_error(status)),
        }
    }

    fn create_removal_marker(&self) -> Result<(), ControllerKeyStoreError> {
        add_generic_password(
            self.base_query(CONTROLLER_KEYCHAIN_REMOVAL_MARKER_ACCOUNT),
            CONTROLLER_KEYCHAIN_REMOVAL_MARKER_VALUE,
            CONTROLLER_REMOVAL_MARKER_LABEL,
        )
        .map_err(map_controller_add_error)
    }

    fn delete_removal_marker(&self) -> Result<bool, ControllerKeyStoreError> {
        delete_generic_password(self.base_query(CONTROLLER_KEYCHAIN_REMOVAL_MARKER_ACCOUNT))
            .map_err(controller_platform_error)
    }
}

fn platform_error(status: i32) -> DeviceKeyStoreError {
    DeviceKeyStoreError::Platform { status }
}

fn add_generic_password(
    query: Vec<(CFString, CFType)>,
    key: &[u8],
    label: &str,
) -> Result<(), i32> {
    let query = add_query(query, key, label);
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

fn delete_generic_password(query: Vec<(CFString, CFType)>) -> Result<bool, i32> {
    let dictionary = CFDictionary::from_CFType_pairs(&query);

    // SAFETY: the dictionary owns valid Core Foundation keys and values for
    // the duration of the call. The query names one non-synchronizing item.
    let status = unsafe { SecItemDelete(dictionary.as_concrete_TypeRef()) };
    if status == errSecSuccess {
        Ok(true)
    } else if status == errSecItemNotFound {
        Ok(false)
    } else {
        Err(status)
    }
}

fn add_query(
    mut query: Vec<(CFString, CFType)>,
    key: &[u8],
    label: &str,
) -> Vec<(CFString, CFType)> {
    // SAFETY: every referenced symbol is a process-lifetime CFString exported
    // by Security.framework.
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
                CFData::from_buffer(key).into_CFType(),
            ),
        ]);
    }
    query
}

fn controller_platform_error(status: i32) -> ControllerKeyStoreError {
    ControllerKeyStoreError::Platform { status }
}

fn map_controller_add_error(status: i32) -> ControllerKeyStoreError {
    if status == errSecDuplicateItem {
        ControllerKeyStoreError::AlreadyExists
    } else {
        controller_platform_error(status)
    }
}

fn copy_generic_password(query: Vec<(CFString, CFType)>) -> Result<Vec<u8>, i32> {
    let query = load_query(query);
    let dictionary = CFDictionary::from_CFType_pairs(&query);
    let mut result = std::ptr::null();

    // SAFETY: result is either null or a create-rule Core Foundation object;
    // the latter is transferred into CFType immediately below.
    let status = unsafe { SecItemCopyMatching(dictionary.as_concrete_TypeRef(), &mut result) };
    if status != errSecSuccess {
        return Err(status);
    }
    if result.is_null() {
        return Err(errSecParam);
    }

    // SAFETY: a successful SecItemCopyMatching with kSecReturnData owns one
    // valid Core Foundation result reference.
    let value = unsafe { CFType::wrap_under_create_rule(result) };
    let data = value.downcast_into::<CFData>().ok_or(errSecParam)?;
    Ok(data.bytes().to_vec())
}

fn load_query(mut query: Vec<(CFString, CFType)>) -> Vec<(CFString, CFType)> {
    // SAFETY: kSecReturnData is a process-lifetime CFString exported by
    // Security.framework.
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
        // SAFETY: test callers pass process-lifetime Security.framework
        // CFString constants.
        let key = unsafe { CFString::wrap_under_get_rule(key) };
        query
            .iter()
            .find_map(|(candidate, value)| (candidate == &key).then_some(value))
            .expect("query attribute")
    }

    #[test]
    fn item_identity_is_stable_and_not_path_derived() {
        assert_eq!(DEVICE_KEY_SERVICE, "app.psw.local.device-root-key.v1");
        assert_eq!(DEVICE_KEY_ACCOUNT, "device-v1");
        assert!(!DEVICE_KEY_SERVICE.contains('/'));
        assert!(!DEVICE_KEY_ACCOUNT.contains('/'));
    }

    #[test]
    fn query_can_be_built_without_reading_or_writing_keychain() {
        let query = MacOsDeviceKeyStore::base_query();
        assert_eq!(query.len(), 5);
        assert_eq!(std::mem::size_of::<MacOsDeviceKeyStore>(), 0);

        let data_protection = query_value(&query, unsafe { kSecUseDataProtectionKeychain })
            .downcast::<CFBoolean>()
            .expect("data protection boolean");
        let synchronizable = query_value(&query, unsafe { kSecAttrSynchronizable })
            .downcast::<CFBoolean>()
            .expect("synchronizable boolean");

        assert!(bool::from(data_protection));
        assert!(!bool::from(synchronizable));
    }

    #[test]
    fn delete_query_uses_only_the_stable_device_local_identity() {
        let query = MacOsDeviceKeyStore::base_query();

        assert_eq!(query.len(), 5);
        assert_eq!(
            query_value(&query, unsafe { kSecAttrService })
                .downcast::<CFString>()
                .expect("service")
                .to_string(),
            DEVICE_KEY_SERVICE
        );
        assert_eq!(
            query_value(&query, unsafe { kSecAttrAccount })
                .downcast::<CFString>()
                .expect("account")
                .to_string(),
            DEVICE_KEY_ACCOUNT
        );
        let synchronizable = query_value(&query, unsafe { kSecAttrSynchronizable })
            .downcast::<CFBoolean>()
            .expect("synchronizable boolean");
        assert!(!bool::from(synchronizable));
    }

    #[test]
    fn create_query_is_device_only_and_load_query_requests_only_data() {
        let test_key = [0x5a; crate::DEVICE_ROOT_KEY_LENGTH];
        let create = add_query(
            MacOsDeviceKeyStore::base_query(),
            &test_key,
            DEVICE_KEY_LABEL,
        );
        let load = load_query(MacOsDeviceKeyStore::base_query());

        let accessibility = query_value(&create, unsafe { kSecAttrAccessible })
            .downcast::<CFString>()
            .expect("accessibility string");
        let expected = unsafe {
            CFString::wrap_under_get_rule(kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        };
        let stored = query_value(&create, unsafe { kSecValueData })
            .downcast::<CFData>()
            .expect("stored key data");
        let return_data = query_value(&load, unsafe { kSecReturnData })
            .downcast::<CFBoolean>()
            .expect("return-data boolean");

        assert_eq!(accessibility, expected);
        assert_eq!(stored.bytes(), test_key);
        assert!(bool::from(return_data));
        assert_eq!(create.len(), 8);
        assert_eq!(load.len(), 6);
    }

    #[test]
    fn controller_queries_always_name_the_verified_access_group_and_exact_account() {
        let access_group =
            ControllerKeychainAccessGroup::from_signing_prefix("ABCDEF1234").expect("access group");
        let store = MacOsControllerKeyStore::new(access_group);
        let seed = store.base_query(CONTROLLER_KEYCHAIN_ACCOUNT);
        let marker = store.base_query(CONTROLLER_KEYCHAIN_REMOVAL_MARKER_ACCOUNT);

        for query in [&seed, &marker] {
            assert_eq!(query.len(), 6);
            assert_eq!(
                query_value(query, unsafe { kSecAttrAccessGroup })
                    .downcast::<CFString>()
                    .expect("access group")
                    .to_string(),
                "ABCDEF1234.app.keptnear.human-controller"
            );
        }
        assert_eq!(
            query_value(&seed, unsafe { kSecAttrAccount })
                .downcast::<CFString>()
                .expect("seed account")
                .to_string(),
            CONTROLLER_KEYCHAIN_ACCOUNT
        );
        assert_eq!(
            query_value(&marker, unsafe { kSecAttrAccount })
                .downcast::<CFString>()
                .expect("marker account")
                .to_string(),
            CONTROLLER_KEYCHAIN_REMOVAL_MARKER_ACCOUNT
        );
    }
}
