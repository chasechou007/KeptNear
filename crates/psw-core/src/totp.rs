use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::api::TotpCode;
use crate::error::{VaultError, VaultResult};
use crate::types::SecretBytes;

type HmacSha1 = Hmac<Sha1>;

/// Normalizes user-supplied TOTP input into an RFC 4648 Base32 secret.
pub fn normalize_totp_secret(input: &str) -> VaultResult<SecretBytes> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(VaultError::InvalidVault {
            reason: "empty Base32 TOTP secret".to_owned(),
        });
    }

    let extracted = if is_otpauth_uri(trimmed) {
        extract_otpauth_secret(trimmed)?
    } else {
        trimmed.to_owned()
    };
    let normalized = normalize_base32_text(&extracted);
    let secret = SecretBytes::new(normalized.into_bytes());
    decode_base32(secret.expose())?;
    Ok(secret)
}

/// Generates a TOTP code from an RFC 4648 Base32 secret.
pub(crate) fn generate_totp_code(
    base32_secret: &SecretBytes,
    unix_time: u64,
    digits: u32,
    period_seconds: u64,
) -> VaultResult<TotpCode> {
    if digits == 0 || digits > 10 {
        return Err(VaultError::InvalidVault {
            reason: "TOTP digits must be between 1 and 10".to_owned(),
        });
    }
    if period_seconds == 0 {
        return Err(VaultError::InvalidVault {
            reason: "TOTP period must be greater than zero".to_owned(),
        });
    }

    let secret = decode_base32(base32_secret.expose())?;
    let counter = unix_time / period_seconds;
    let code = hotp(&secret, counter, digits)?;
    let elapsed = unix_time % period_seconds;
    Ok(TotpCode {
        code,
        period_seconds,
        remaining_seconds: period_seconds - elapsed,
    })
}

fn hotp(secret: &[u8], counter: u64, digits: u32) -> VaultResult<String> {
    let mut mac = HmacSha1::new_from_slice(secret).map_err(|error| VaultError::Crypto {
        operation: "create TOTP HMAC",
        reason: error.to_string(),
    })?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = usize::from(digest[digest.len() - 1] & 0x0f);
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    let modulo = 10_u32.pow(digits);
    Ok(format!(
        "{:0width$}",
        binary % modulo,
        width = digits as usize
    ))
}

fn decode_base32(input: &[u8]) -> VaultResult<Vec<u8>> {
    let mut buffer = 0_u32;
    let mut bits = 0_u8;
    let mut output = Vec::new();

    for byte in input {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            b'=' | b' ' | b'\t' | b'\n' | b'\r' | b'-' => continue,
            _ => {
                return Err(VaultError::InvalidVault {
                    reason: "invalid Base32 TOTP secret".to_owned(),
                });
            }
        };
        buffer = (buffer << 5) | u32::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((buffer >> bits) & 0xff) as u8);
        }
    }

    if output.is_empty() {
        return Err(VaultError::InvalidVault {
            reason: "empty Base32 TOTP secret".to_owned(),
        });
    }

    Ok(output)
}

fn is_otpauth_uri(value: &str) -> bool {
    const PREFIX: &str = "otpauth://";
    value
        .get(..PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
}

fn extract_otpauth_secret(uri: &str) -> VaultResult<String> {
    let query = uri
        .split_once('?')
        .map(|(_, query)| query.split('#').next().unwrap_or_default())
        .ok_or_else(|| VaultError::InvalidVault {
            reason: "otpauth URI is missing a TOTP secret".to_owned(),
        })?;
    for pair in query.split('&') {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        if key.eq_ignore_ascii_case("secret") {
            let decoded = percent_decode_query_value(value)?;
            if decoded.trim().is_empty() {
                break;
            }
            return Ok(decoded);
        }
    }
    Err(VaultError::InvalidVault {
        reason: "otpauth URI is missing a TOTP secret".to_owned(),
    })
}

fn percent_decode_query_value(value: &str) -> VaultResult<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err(VaultError::InvalidVault {
                        reason: "invalid percent encoding in otpauth URI".to_owned(),
                    });
                }
                let high = hex_value(bytes[index + 1])?;
                let low = hex_value(bytes[index + 2])?;
                output.push((high << 4) | low);
                index += 3;
            }
            b'+' => {
                output.push(b' ');
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(output).map_err(|error| VaultError::InvalidVault {
        reason: format!("invalid UTF-8 in otpauth URI: {error}"),
    })
}

fn hex_value(byte: u8) -> VaultResult<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(VaultError::InvalidVault {
            reason: "invalid percent encoding in otpauth URI".to_owned(),
        }),
    }
}

fn normalize_base32_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| {
            !character.is_ascii_whitespace() && *character != '-' && *character != '='
        })
        .flat_map(char::to_uppercase)
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::totp::{generate_totp_code, normalize_totp_secret};
    use crate::SecretBytes;

    #[test]
    fn totp_matches_rfc6238_sha1_test_vector() {
        let secret = SecretBytes::new(b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".to_vec());

        let code = generate_totp_code(&secret, 59, 8, 30).expect("generate TOTP");

        assert_eq!(code.code, "94287082");
        assert_eq!(code.remaining_seconds, 1);
    }

    #[test]
    fn totp_rejects_invalid_base32_secret() {
        let secret = SecretBytes::new(b"not valid!".to_vec());

        let error = generate_totp_code(&secret, 59, 6, 30).expect_err("invalid secret");

        assert!(matches!(error, crate::VaultError::InvalidVault { .. }));
    }

    #[test]
    fn totp_normalization_accepts_grouped_base32_and_otpauth_uri() {
        let grouped = normalize_totp_secret("gezd gnbv-gy3tqojqgezdgnbvgy3tqojq")
            .expect("normalize grouped secret");
        assert_eq!(grouped.expose(), b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");

        let uri = normalize_totp_secret(
            "otpauth://totp/Example:alice@example.com?issuer=Example&secret=JBSW%59%33DPEHPK3PXP",
        )
        .expect("normalize uri secret");
        assert_eq!(uri.expose(), b"JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn totp_normalization_rejects_otpauth_without_secret_and_bad_percent_encoding() {
        let missing = normalize_totp_secret("otpauth://totp/Example?issuer=Example")
            .expect_err("missing secret rejected");
        assert!(matches!(missing, crate::VaultError::InvalidVault { .. }));

        let malformed = normalize_totp_secret("otpauth://totp/Example?secret=JBSW%ZZDPEHPK3PXP")
            .expect_err("bad percent encoding rejected");
        assert!(matches!(malformed, crate::VaultError::InvalidVault { .. }));
    }
}
