#!/usr/bin/env bash

PSW_VAULT_TYPE_IDENTIFIER="app.psw.local.vault"
PSW_VAULT_EXTENSION="pswvault"
PSW_VAULT_TYPE_NAME="KeptNear Vault"
PSW_PUBLIC_APP_NAME="KeptNear"
PSW_APP_ICON_NAME="KeptNear"

write_pswmac_info_plist() {
  local output_path="$1"
  local app_name="$2"
  local bundle_id="$3"
  local min_system_version="$4"
  local version="${5:-}"

  local version_entries=""
  if [[ -n "$version" ]]; then
    version_entries="  <key>CFBundleShortVersionString</key>
  <string>$version</string>
  <key>CFBundleVersion</key>
  <string>$version</string>
"
  fi

  cat >"$output_path" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key>
  <string>$app_name</string>
  <key>CFBundleIdentifier</key>
  <string>$bundle_id</string>
  <key>CFBundleDisplayName</key>
  <string>$PSW_PUBLIC_APP_NAME</string>
  <key>CFBundleIconFile</key>
  <string>$PSW_APP_ICON_NAME</string>
  <key>CFBundleName</key>
  <string>$PSW_PUBLIC_APP_NAME</string>
  <key>CFBundlePackageType</key>
  <string>APPL</string>
$version_entries  <key>LSMinimumSystemVersion</key>
  <string>$min_system_version</string>
  <key>NSPrincipalClass</key>
  <string>NSApplication</string>
  <key>CFBundleDocumentTypes</key>
  <array>
    <dict>
      <key>CFBundleTypeName</key>
      <string>$PSW_VAULT_TYPE_NAME</string>
      <key>CFBundleTypeRole</key>
      <string>Editor</string>
      <key>LSHandlerRank</key>
      <string>Owner</string>
      <key>LSItemContentTypes</key>
      <array>
        <string>$PSW_VAULT_TYPE_IDENTIFIER</string>
      </array>
      <key>LSTypeIsPackage</key>
      <true/>
    </dict>
  </array>
  <key>UTExportedTypeDeclarations</key>
  <array>
    <dict>
      <key>UTTypeIdentifier</key>
      <string>$PSW_VAULT_TYPE_IDENTIFIER</string>
      <key>UTTypeDescription</key>
      <string>$PSW_VAULT_TYPE_NAME</string>
      <key>UTTypeConformsTo</key>
      <array>
        <string>com.apple.package</string>
      </array>
      <key>UTTypeTagSpecification</key>
      <dict>
        <key>public.filename-extension</key>
        <string>$PSW_VAULT_EXTENSION</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>
PLIST
}
