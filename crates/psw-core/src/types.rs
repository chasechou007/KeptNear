use std::fmt::{Display, Formatter};

use serde::{Deserialize, Serialize};

/// Current public vault format version supported by this crate.
pub const CURRENT_VAULT_FORMAT_VERSION: u32 = 1;

/// Current encrypted item record format version supported by this crate.
pub const CURRENT_RECORD_FORMAT_VERSION: u32 = 1;

/// Public vault metadata that can be read before unlock.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultMetadata {
    /// Human-readable format name.
    pub format_name: String,
    /// Public vault format version.
    pub vault_format_version: u32,
    /// Encrypted item record format version.
    pub record_format_version: u32,
    /// Optional user-visible vault display name.
    pub display_name: Option<String>,
}

impl VaultMetadata {
    /// Creates metadata for a new experimental vault.
    pub fn experimental(display_name: Option<String>) -> Self {
        Self {
            format_name: "psw-local-vault".to_owned(),
            vault_format_version: CURRENT_VAULT_FORMAT_VERSION,
            record_format_version: CURRENT_RECORD_FORMAT_VERSION,
            display_name,
        }
    }
}

/// Opaque item identifier.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ItemId(pub String);

impl Display for ItemId {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Opaque item revision identifier.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ItemRevision(pub String);

/// Opaque tombstone identifier.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct TombstoneId(pub String);

/// Opaque conflict identifier.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub struct ConflictId(pub String);

/// Supported high-level item types for the MVP.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ItemType {
    /// Login credential with username, password, URL, and optional TOTP.
    Login,
    /// Free-form encrypted note.
    SecureNote,
    /// Software license or entitlement record.
    SoftwareLicense,
    /// Payment card record.
    CreditCard,
}

/// User-visible item status.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ItemStatus {
    /// Visible in default active views.
    Active,
    /// Hidden from default active views but preserved.
    Archived,
    /// Deleted locally and represented by a tombstone for sync.
    Deleted,
    /// Multiple versions require user resolution.
    Conflicted(ConflictId),
}

/// Secret byte container that clears its allocation on drop.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Creates a secret from raw bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the secret bytes.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Login item content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct LoginItem {
    /// Login username.
    pub username: Option<String>,
    /// Login password.
    pub password: Option<SecretBytes>,
    /// Associated URLs.
    pub urls: Vec<String>,
    /// Optional notes.
    pub notes: Option<String>,
    /// Optional TOTP seed.
    pub totp_secret: Option<SecretBytes>,
}

/// Secure note item content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SecureNoteItem {
    /// Encrypted note body.
    pub body: String,
}

/// Software license item content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SoftwareLicenseItem {
    /// Licensed product name.
    pub product: Option<String>,
    /// License key.
    pub license_key: Option<SecretBytes>,
    /// Licensed-to name or email.
    pub licensed_to: Option<String>,
    /// Optional notes.
    pub notes: Option<String>,
}

/// Credit card item content.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CreditCardItem {
    /// Cardholder name.
    pub cardholder_name: Option<String>,
    /// Primary account number.
    pub number: Option<SecretBytes>,
    /// Expiration month.
    pub expiry_month: Option<u8>,
    /// Expiration year.
    pub expiry_year: Option<u16>,
    /// Verification code.
    pub verification_code: Option<SecretBytes>,
    /// Optional notes.
    pub notes: Option<String>,
}

/// Item content variants supported by the MVP.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum VaultItemContent {
    /// Login credential.
    Login(LoginItem),
    /// Secure note.
    SecureNote(SecureNoteItem),
    /// Software license.
    SoftwareLicense(SoftwareLicenseItem),
    /// Credit card.
    CreditCard(CreditCardItem),
}

impl VaultItemContent {
    /// Returns the high-level item type.
    #[must_use]
    pub fn item_type(&self) -> ItemType {
        match self {
            Self::Login(_) => ItemType::Login,
            Self::SecureNote(_) => ItemType::SecureNote,
            Self::SoftwareLicense(_) => ItemType::SoftwareLicense,
            Self::CreditCard(_) => ItemType::CreditCard,
        }
    }
}

impl ItemType {
    /// Returns a stable lowercase type label for search.
    #[must_use]
    pub fn as_search_label(&self) -> &'static str {
        match self {
            Self::Login => "login",
            Self::SecureNote => "secure note",
            Self::SoftwareLicense => "software license",
            Self::CreditCard => "credit card",
        }
    }
}

/// Draft used to create or update a vault item.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultItemDraft {
    /// Item title.
    pub title: String,
    /// Typed item content.
    pub content: VaultItemContent,
    /// User tags.
    pub tags: Vec<String>,
    /// Favorite flag.
    pub favorite: bool,
}

impl VaultItemDraft {
    /// Returns the high-level item type for this draft.
    #[must_use]
    pub fn item_type(&self) -> ItemType {
        self.content.item_type()
    }
}

/// Decrypted item returned only from an unlocked vault session.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct VaultItem {
    /// Item identifier.
    pub id: ItemId,
    /// Current item revision.
    pub revision: ItemRevision,
    /// Previous revision this item was derived from, if any.
    pub parent_revision: Option<ItemRevision>,
    /// Item status.
    pub status: ItemStatus,
    /// Editable item content.
    pub draft: VaultItemDraft,
}

/// Lightweight item summary for lists and search results.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ItemSummary {
    /// Item identifier.
    pub id: ItemId,
    /// Item revision.
    pub revision: ItemRevision,
    /// Item title.
    pub title: String,
    /// Item type.
    pub item_type: ItemType,
    /// Item status.
    pub status: ItemStatus,
    /// User tags.
    pub tags: Vec<String>,
    /// Favorite flag.
    pub favorite: bool,
}

impl ItemSummary {
    /// Builds a summary from a decrypted item.
    #[must_use]
    pub fn from_item(item: &VaultItem) -> Self {
        Self {
            id: item.id.clone(),
            revision: item.revision.clone(),
            title: item.draft.title.clone(),
            item_type: item.draft.item_type(),
            status: item.status.clone(),
            tags: item.draft.tags.clone(),
            favorite: item.draft.favorite,
        }
    }
}
