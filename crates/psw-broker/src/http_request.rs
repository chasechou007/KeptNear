use std::fmt::{Debug, Display, Formatter};
use std::io::Read;
use std::time::Duration;

use psw_core::SecretBytes;
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use crate::protocol::BrokerErrorCode;
use crate::state_model::UsagePlacement;

/// Maximum UTF-8 byte length accepted for one outbound HTTPS URL.
pub const MAX_HTTP_URL_BYTES: usize = 4 * 1024;
/// Maximum number of caller-supplied non-secret request headers.
pub const MAX_HTTP_REQUEST_HEADERS: usize = 32;
/// Maximum byte length accepted for one request header name.
pub const MAX_HTTP_HEADER_NAME_BYTES: usize = 64;
/// Maximum byte length accepted for one request header value.
pub const MAX_HTTP_HEADER_VALUE_BYTES: usize = 8 * 1024;
/// Maximum aggregate bytes accepted across caller-supplied request headers.
pub const MAX_HTTP_REQUEST_HEADER_BYTES: usize = 64 * 1024;
/// Maximum request body accepted by `http.request` version 1.
pub const MAX_HTTP_REQUEST_BODY_BYTES: usize = 1024 * 1024;
/// Maximum response body returned by `http.request` version 1.
pub const MAX_HTTP_RESPONSE_BODY_BYTES: usize = 1024 * 1024;
/// Fixed total timeout for one explicit outbound HTTP operation.
pub const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

const MAX_HTTP_SECRET_BYTES: usize = MAX_HTTP_HEADER_VALUE_BYTES - b"Bearer ".len();
const RESPONSE_REDACTION: &[u8] = b"[REDACTED]";

/// HTTP method supported by the first Broker request capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerHttpMethod {
    /// Retrieve a representation.
    Get,
    /// Retrieve response metadata without a response body.
    Head,
    /// Submit a new representation or operation.
    Post,
    /// Replace a representation.
    Put,
    /// Partially update a representation.
    Patch,
    /// Delete a representation.
    Delete,
}

impl BrokerHttpMethod {
    /// Returns the canonical uppercase HTTP method.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// One bounded caller-supplied non-secret request header.
pub struct BrokerHttpHeader {
    name: String,
    value: String,
}

impl BrokerHttpHeader {
    /// Validates an HTTP field name and value without retaining rejected input.
    pub fn new(mut name: String, mut value: String) -> Result<Self, BrokerHttpRequestError> {
        if !is_valid_header_name(&name)
            || value.len() > MAX_HTTP_HEADER_VALUE_BYTES
            || !value.bytes().all(is_safe_header_value_byte)
        {
            name.zeroize();
            value.zeroize();
            return Err(BrokerHttpRequestError::InvalidRequest);
        }
        Ok(Self { name, value })
    }

    /// Returns the validated request header name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the validated non-secret request header value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl Debug for BrokerHttpHeader {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerHttpHeader")
            .field("name", &"<redacted>")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for BrokerHttpHeader {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

/// Bounded explicit outbound request with no credential value.
pub struct BrokerHttpRequest {
    method: BrokerHttpMethod,
    url: String,
    headers: Vec<BrokerHttpHeader>,
    body: Vec<u8>,
}

impl BrokerHttpRequest {
    /// Validates an HTTPS request before any Use Grant is consumed.
    ///
    /// Version 1 rejects plaintext HTTP, URL credentials, fragments,
    /// caller-controlled framing headers, and oversized request material.
    pub fn new(
        method: BrokerHttpMethod,
        mut url: String,
        headers: Vec<BrokerHttpHeader>,
        mut body: Vec<u8>,
    ) -> Result<Self, BrokerHttpRequestError> {
        let parsed = Url::parse(&url).ok();
        let valid_parsed_url = parsed.as_ref().is_some_and(|parsed| {
            parsed.scheme() == "https"
                && parsed.host_str().is_some()
                && parsed.username().is_empty()
                && parsed.password().is_none()
                && parsed.fragment().is_none()
                && !parsed.cannot_be_a_base()
        });
        let mut canonical_url = parsed.map(String::from).unwrap_or_default();
        let valid_url = valid_parsed_url
            && url.len() <= MAX_HTTP_URL_BYTES
            && canonical_url.len() <= MAX_HTTP_URL_BYTES;
        let header_bytes = headers.iter().try_fold(0_usize, |total, header| {
            total
                .checked_add(header.name.len())
                .and_then(|total| total.checked_add(header.value.len()))
        });
        let valid_headers = headers.len() <= MAX_HTTP_REQUEST_HEADERS
            && header_bytes.is_some_and(|bytes| bytes <= MAX_HTTP_REQUEST_HEADER_BYTES)
            && headers
                .iter()
                .all(|header| !is_reserved_request_header(&header.name));
        if !valid_url || !valid_headers || body.len() > MAX_HTTP_REQUEST_BODY_BYTES {
            url.zeroize();
            canonical_url.zeroize();
            body.zeroize();
            return Err(BrokerHttpRequestError::InvalidRequest);
        }

        url.zeroize();
        Ok(Self {
            method,
            url: canonical_url,
            headers,
            body,
        })
    }

    /// Returns the request method.
    #[must_use]
    pub const fn method(&self) -> BrokerHttpMethod {
        self.method
    }

    /// Returns the validated canonical HTTPS destination.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Returns caller-supplied non-secret request headers.
    #[must_use]
    pub fn headers(&self) -> &[BrokerHttpHeader] {
        &self.headers
    }

    /// Returns the bounded caller-supplied request body.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl Debug for BrokerHttpRequest {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerHttpRequest")
            .field("method", &self.method)
            .field("url", &"<redacted>")
            .field("header_count", &self.headers.len())
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

impl Drop for BrokerHttpRequest {
    fn drop(&mut self) {
        self.url.zeroize();
        self.body.zeroize();
    }
}

/// Bounded response representation returned to an authorized Consumer.
pub struct BrokerHttpResponse {
    status_code: u16,
    body: Vec<u8>,
    truncated: bool,
}

impl BrokerHttpResponse {
    /// Returns the numeric HTTP status without a server-controlled reason phrase.
    #[must_use]
    pub const fn status_code(&self) -> u16 {
        self.status_code
    }

    /// Returns the bounded response body after exact credential redaction.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// Returns whether transport or redaction omitted response bytes.
    #[must_use]
    pub const fn truncated(&self) -> bool {
        self.truncated
    }
}

impl Debug for BrokerHttpResponse {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerHttpResponse")
            .field("status_code", &self.status_code)
            .field("body", &"<redacted>")
            .field("body_bytes", &self.body.len())
            .field("truncated", &self.truncated)
            .finish()
    }
}

impl Drop for BrokerHttpResponse {
    fn drop(&mut self) {
        self.body.zeroize();
    }
}

/// Sanitized request-validation, placement, or network failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerHttpRequestError {
    /// The URL, headers, method payload, or size violates the v1 contract.
    InvalidRequest,
    /// The Usage Profile is not an HTTP placement supported by version 1.
    UnsupportedPlacement,
    /// The exact authorized field is no longer available with the expected kind.
    SecretUnavailable,
    /// The stored secret cannot be represented as a safe HTTP header value.
    SecretPlacementInvalid,
    /// DNS, TLS, connection, timeout, protocol, or response reading failed.
    NetworkOperationFailed,
}

impl BrokerHttpRequestError {
    /// Returns the stable machine-facing error category.
    #[must_use]
    pub const fn broker_error_code(self) -> BrokerErrorCode {
        match self {
            Self::InvalidRequest | Self::SecretPlacementInvalid => BrokerErrorCode::InvalidRequest,
            Self::UnsupportedPlacement => BrokerErrorCode::UnsupportedCapability,
            Self::SecretUnavailable => BrokerErrorCode::AccessDenied,
            Self::NetworkOperationFailed => BrokerErrorCode::OperationFailed,
        }
    }
}

impl Display for BrokerHttpRequestError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::InvalidRequest => "HTTP request is invalid",
            Self::UnsupportedPlacement => "HTTP secret placement is unsupported",
            Self::SecretUnavailable => "HTTP credential scope is unavailable",
            Self::SecretPlacementInvalid => "HTTP credential cannot be placed safely",
            Self::NetworkOperationFailed => "HTTP network operation failed",
        })
    }
}

impl std::error::Error for BrokerHttpRequestError {}

pub(crate) trait BrokerHttpTransport {
    fn send(
        &self,
        request: &BrokerHttpRequest,
        credential_header: &BrokerHttpCredentialHeader,
        response_capture_limit: usize,
    ) -> Result<BrokerHttpTransportResponse, BrokerHttpRequestError>;
}

pub(crate) struct BrokerHttpTransportResponse {
    status_code: u16,
    body: Vec<u8>,
    truncated: bool,
}

impl BrokerHttpTransportResponse {
    pub(crate) fn new(status_code: u16, body: Vec<u8>, truncated: bool) -> Self {
        Self {
            status_code,
            body,
            truncated,
        }
    }
}

pub(crate) struct BrokerHttpCredentialHeader {
    name: String,
    value: Zeroizing<String>,
}

impl BrokerHttpCredentialHeader {
    fn from_placement(
        placement: &UsagePlacement,
        secret: &SecretBytes,
    ) -> Result<Self, BrokerHttpRequestError> {
        let bytes = secret.expose();
        if bytes.is_empty()
            || bytes.len() > MAX_HTTP_SECRET_BYTES
            || !bytes.iter().copied().all(is_visible_ascii)
        {
            return Err(BrokerHttpRequestError::SecretPlacementInvalid);
        }
        let value = std::str::from_utf8(bytes)
            .map_err(|_| BrokerHttpRequestError::SecretPlacementInvalid)?;
        match placement {
            UsagePlacement::HttpBearerAuthorization {} => Ok(Self {
                name: "Authorization".to_owned(),
                value: Zeroizing::new(format!("Bearer {value}")),
            }),
            UsagePlacement::HttpHeader { header_name } => Ok(Self {
                name: header_name.clone(),
                value: Zeroizing::new(value.to_owned()),
            }),
            UsagePlacement::ProcessEnvironment { .. }
            | UsagePlacement::ProcessStdin { .. }
            | UsagePlacement::ProcessFileDescriptor { .. } => {
                Err(BrokerHttpRequestError::UnsupportedPlacement)
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    #[cfg(test)]
    pub(crate) fn value(&self) -> &str {
        &self.value
    }
}

impl Debug for BrokerHttpCredentialHeader {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerHttpCredentialHeader")
            .field("name", &"<redacted>")
            .field("value", &"<redacted>")
            .finish()
    }
}

impl Drop for BrokerHttpCredentialHeader {
    fn drop(&mut self) {
        self.name.zeroize();
    }
}

pub(crate) struct BrokerHttpRequestManager;

impl BrokerHttpRequestManager {
    pub(crate) fn execute<T>(
        transport: &T,
        request: &BrokerHttpRequest,
        placement: &UsagePlacement,
        secret: &SecretBytes,
    ) -> Result<BrokerHttpResponse, BrokerHttpRequestError>
    where
        T: BrokerHttpTransport,
    {
        let credential_header = BrokerHttpCredentialHeader::from_placement(placement, secret)?;
        if request
            .headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case(&credential_header.name))
        {
            return Err(BrokerHttpRequestError::InvalidRequest);
        }

        let capture_limit = MAX_HTTP_RESPONSE_BODY_BYTES
            .saturating_add(secret.expose().len())
            .saturating_add(1);
        let transport_response = transport.send(request, &credential_header, capture_limit)?;
        let status_code = transport_response.status_code;
        let transport_truncated = transport_response.truncated;
        let mut response_body = Zeroizing::new(transport_response.body);
        if !(100..=599).contains(&status_code) {
            return Err(BrokerHttpRequestError::NetworkOperationFailed);
        }

        let capture_truncated = response_body.len() > capture_limit;
        response_body.truncate(capture_limit);
        let (body, redaction_truncated) = redact_exact_bounded(
            &response_body,
            secret.expose(),
            MAX_HTTP_RESPONSE_BODY_BYTES,
        );
        Ok(BrokerHttpResponse {
            status_code,
            body,
            truncated: transport_truncated || capture_truncated || redaction_truncated,
        })
    }
}

pub(crate) struct UreqHttpTransport;

impl BrokerHttpTransport for UreqHttpTransport {
    fn send(
        &self,
        request: &BrokerHttpRequest,
        credential_header: &BrokerHttpCredentialHeader,
        response_capture_limit: usize,
    ) -> Result<BrokerHttpTransportResponse, BrokerHttpRequestError> {
        let agent = ureq::AgentBuilder::new()
            .redirects(0)
            .try_proxy_from_env(false)
            .timeout(HTTP_REQUEST_TIMEOUT)
            .timeout_connect(HTTP_REQUEST_TIMEOUT)
            .build();
        let mut outbound = agent.request(request.method.as_str(), &request.url);
        for header in &request.headers {
            outbound = outbound.set(&header.name, &header.value);
        }
        outbound = outbound.set(&credential_header.name, &credential_header.value);

        let result = if request.body.is_empty() {
            outbound.call()
        } else {
            outbound.send_bytes(&request.body)
        };
        let response = match result {
            Ok(response) | Err(ureq::Error::Status(_, response)) => response,
            Err(ureq::Error::Transport(_)) => {
                return Err(BrokerHttpRequestError::NetworkOperationFailed);
            }
        };
        let status_code = response.status();
        let mut body = Zeroizing::new(Vec::new());
        response
            .into_reader()
            .take(response_capture_limit.saturating_add(1) as u64)
            .read_to_end(&mut body)
            .map_err(|_| BrokerHttpRequestError::NetworkOperationFailed)?;
        let truncated = body.len() > response_capture_limit;
        body.truncate(response_capture_limit);
        Ok(BrokerHttpTransportResponse::new(
            status_code,
            std::mem::take(&mut *body),
            truncated,
        ))
    }
}

fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_HTTP_HEADER_NAME_BYTES
        && name.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn is_safe_header_value_byte(byte: u8) -> bool {
    byte == b'\t' || (b' '..=b'~').contains(&byte)
}

fn is_visible_ascii(byte: u8) -> bool {
    (b'!'..=b'~').contains(&byte)
}

fn is_reserved_request_header(name: &str) -> bool {
    [
        "connection",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

fn redact_exact_bounded(input: &[u8], secret: &[u8], limit: usize) -> (Vec<u8>, bool) {
    debug_assert!(!secret.is_empty());
    let mut output = Vec::with_capacity(input.len().min(limit));
    let mut cursor = 0;
    let mut truncated = false;

    while cursor < input.len() && output.len() < limit {
        let remaining = &input[cursor..];
        let match_offset = remaining
            .windows(secret.len())
            .position(|window| window == secret);
        let Some(match_offset) = match_offset else {
            append_bounded(&mut output, remaining, limit, &mut truncated);
            cursor = input.len();
            break;
        };
        let prefix = &remaining[..match_offset];
        if output
            .len()
            .saturating_add(prefix.len())
            .saturating_add(RESPONSE_REDACTION.len())
            > limit
        {
            let marker_start = limit.saturating_sub(RESPONSE_REDACTION.len());
            output.truncate(marker_start);
            let available_prefix = marker_start.saturating_sub(output.len());
            output.extend_from_slice(&prefix[..prefix.len().min(available_prefix)]);
            output.extend_from_slice(&RESPONSE_REDACTION[..limit.min(RESPONSE_REDACTION.len())]);
            truncated = true;
            break;
        }
        append_bounded(&mut output, prefix, limit, &mut truncated);
        append_bounded(&mut output, RESPONSE_REDACTION, limit, &mut truncated);
        cursor = cursor
            .saturating_add(match_offset)
            .saturating_add(secret.len());
    }
    if cursor < input.len() {
        truncated = true;
    }
    (output, truncated)
}

fn append_bounded(output: &mut Vec<u8>, value: &[u8], limit: usize, truncated: &mut bool) {
    let available = limit.saturating_sub(output.len());
    let copied = value.len().min(available);
    output.extend_from_slice(&value[..copied]);
    if copied != value.len() {
        *truncated = true;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    #[derive(Default)]
    struct RecordingTransport {
        request: Mutex<Option<RecordedRequest>>,
        response: Mutex<Option<Result<BrokerHttpTransportResponse, BrokerHttpRequestError>>>,
    }

    struct RecordedRequest {
        method: BrokerHttpMethod,
        url: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
        response_capture_limit: usize,
    }

    impl RecordingTransport {
        fn responding(status_code: u16, body: Vec<u8>, truncated: bool) -> Self {
            Self {
                request: Mutex::new(None),
                response: Mutex::new(Some(Ok(BrokerHttpTransportResponse::new(
                    status_code,
                    body,
                    truncated,
                )))),
            }
        }
    }

    impl BrokerHttpTransport for RecordingTransport {
        fn send(
            &self,
            request: &BrokerHttpRequest,
            credential_header: &BrokerHttpCredentialHeader,
            response_capture_limit: usize,
        ) -> Result<BrokerHttpTransportResponse, BrokerHttpRequestError> {
            let mut headers = request
                .headers
                .iter()
                .map(|header| (header.name.clone(), header.value.clone()))
                .collect::<Vec<_>>();
            headers.push((
                credential_header.name.clone(),
                credential_header.value.to_string(),
            ));
            *self.request.lock().expect("request") = Some(RecordedRequest {
                method: request.method,
                url: request.url.clone(),
                headers,
                body: request.body.clone(),
                response_capture_limit,
            });
            self.response
                .lock()
                .expect("response")
                .take()
                .expect("configured response")
        }
    }

    fn request(headers: Vec<BrokerHttpHeader>) -> BrokerHttpRequest {
        BrokerHttpRequest::new(
            BrokerHttpMethod::Post,
            "https://api.example.test/v1/items?limit=1".to_owned(),
            headers,
            br#"{"name":"release"}"#.to_vec(),
        )
        .expect("request")
    }

    #[test]
    fn request_validation_rejects_plaintext_credentials_fragments_and_framing_headers() {
        for url in [
            "http://api.example.test/v1",
            "https://user:password@api.example.test/v1",
            "https://api.example.test/v1#fragment",
            "not a URL",
        ] {
            assert_eq!(
                BrokerHttpRequest::new(
                    BrokerHttpMethod::Get,
                    url.to_owned(),
                    Vec::new(),
                    Vec::new(),
                )
                .expect_err("invalid URL"),
                BrokerHttpRequestError::InvalidRequest
            );
        }
        for name in [
            "Host",
            "Content-Length",
            "Transfer-Encoding",
            "Connection",
            "Keep-Alive",
            "Proxy-Connection",
        ] {
            let header =
                BrokerHttpHeader::new(name.to_owned(), "value".to_owned()).expect("header");
            assert_eq!(
                BrokerHttpRequest::new(
                    BrokerHttpMethod::Get,
                    "https://api.example.test".to_owned(),
                    vec![header],
                    Vec::new(),
                )
                .expect_err("reserved header"),
                BrokerHttpRequestError::InvalidRequest
            );
        }
        assert_eq!(
            BrokerHttpHeader::new("X-Test\r\nInjected".to_owned(), "value".to_owned())
                .expect_err("invalid name"),
            BrokerHttpRequestError::InvalidRequest
        );
        assert_eq!(
            BrokerHttpHeader::new("X-Test".to_owned(), "value\r\nInjected: yes".to_owned())
                .expect_err("invalid value"),
            BrokerHttpRequestError::InvalidRequest
        );
    }

    #[test]
    fn bearer_placement_is_internal_and_request_debug_is_redacted() {
        let secret_marker = "KN_HTTP_SECRET_BEARER_85";
        let url_marker = "api.example.test";
        let body_marker = "release";
        let transport = RecordingTransport::responding(201, b"{\"ok\":true}".to_vec(), false);
        let request = request(vec![BrokerHttpHeader::new(
            "Accept".to_owned(),
            "application/json".to_owned(),
        )
        .expect("header")]);
        let debug = format!("{request:?}");
        assert!(!debug.contains(url_marker));
        assert!(!debug.contains(body_marker));

        let response = BrokerHttpRequestManager::execute(
            &transport,
            &request,
            &UsagePlacement::HttpBearerAuthorization {},
            &SecretBytes::new(secret_marker.as_bytes().to_vec()),
        )
        .expect("execute");
        assert_eq!(response.status_code(), 201);
        assert_eq!(response.body(), b"{\"ok\":true}");
        assert!(!response.truncated());

        let recorded = transport
            .request
            .lock()
            .expect("request")
            .take()
            .expect("recorded");
        assert_eq!(recorded.method, BrokerHttpMethod::Post);
        assert_eq!(recorded.url, "https://api.example.test/v1/items?limit=1");
        assert_eq!(
            recorded.headers,
            vec![
                ("Accept".to_owned(), "application/json".to_owned()),
                (
                    "Authorization".to_owned(),
                    format!("Bearer {secret_marker}")
                ),
            ]
        );
        assert_eq!(recorded.body, br#"{"name":"release"}"#);
        assert_eq!(
            recorded.response_capture_limit,
            MAX_HTTP_RESPONSE_BODY_BYTES + secret_marker.len() + 1
        );
    }

    #[test]
    fn custom_header_placement_rejects_caller_override() {
        let request = request(vec![BrokerHttpHeader::new(
            "x-api-key".to_owned(),
            "caller value".to_owned(),
        )
        .expect("header")]);
        let transport = RecordingTransport::responding(200, Vec::new(), false);
        assert_eq!(
            BrokerHttpRequestManager::execute(
                &transport,
                &request,
                &UsagePlacement::HttpHeader {
                    header_name: "X-API-Key".to_owned(),
                },
                &SecretBytes::new(b"stored-token".to_vec()),
            )
            .expect_err("conflicting placement"),
            BrokerHttpRequestError::InvalidRequest
        );
        assert!(transport.request.lock().expect("request").is_none());
    }

    #[test]
    fn response_exact_echo_is_redacted_before_bounded_return() {
        let secret = b"KN_HTTP_RESPONSE_SECRET";
        let mut body = vec![b'a'; MAX_HTTP_RESPONSE_BODY_BYTES - 3];
        body.extend_from_slice(secret);
        body.extend_from_slice(b"-tail");
        let transport = RecordingTransport::responding(200, body, true);
        let response = BrokerHttpRequestManager::execute(
            &transport,
            &request(Vec::new()),
            &UsagePlacement::HttpHeader {
                header_name: "X-Token".to_owned(),
            },
            &SecretBytes::new(secret.to_vec()),
        )
        .expect("execute");

        assert_eq!(response.body().len(), MAX_HTTP_RESPONSE_BODY_BYTES);
        assert!(response.truncated());
        assert!(!response
            .body()
            .windows(secret.len())
            .any(|window| window == secret));
        assert!(response
            .body()
            .windows(RESPONSE_REDACTION.len())
            .any(|window| window == RESPONSE_REDACTION));
        let debug = format!("{response:?}");
        assert!(!debug.contains("KN_HTTP_RESPONSE_SECRET"));
        assert!(!debug.contains("[REDACTED]"));
    }

    #[test]
    fn invalid_secret_and_network_errors_are_stable_and_sanitized() {
        let request = request(Vec::new());
        let transport = RecordingTransport {
            request: Mutex::new(None),
            response: Mutex::new(Some(Err(BrokerHttpRequestError::NetworkOperationFailed))),
        };
        assert_eq!(
            BrokerHttpRequestManager::execute(
                &transport,
                &request,
                &UsagePlacement::HttpBearerAuthorization {},
                &SecretBytes::new(b"line\r\nbreak".to_vec()),
            )
            .expect_err("invalid secret"),
            BrokerHttpRequestError::SecretPlacementInvalid
        );
        let secret_marker = "KN_HTTP_TRANSPORT_SECRET";
        let error = BrokerHttpRequestManager::execute(
            &transport,
            &request,
            &UsagePlacement::HttpBearerAuthorization {},
            &SecretBytes::new(secret_marker.as_bytes().to_vec()),
        )
        .expect_err("network");
        assert_eq!(error, BrokerHttpRequestError::NetworkOperationFailed);
        assert_eq!(error.to_string(), "HTTP network operation failed");
        assert!(!format!("{error:?}").contains(secret_marker));

        let invalid_status = RecordingTransport::responding(700, b"server detail".to_vec(), false);
        assert_eq!(
            BrokerHttpRequestManager::execute(
                &invalid_status,
                &request,
                &UsagePlacement::HttpBearerAuthorization {},
                &SecretBytes::new(secret_marker.as_bytes().to_vec()),
            )
            .expect_err("invalid response status"),
            BrokerHttpRequestError::NetworkOperationFailed
        );
    }

    #[test]
    fn third_party_transport_logging_is_compiled_out() {
        assert_eq!(log::STATIC_MAX_LEVEL, log::LevelFilter::Off);
    }
}
