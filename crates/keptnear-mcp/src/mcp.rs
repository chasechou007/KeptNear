use std::fmt::{Display, Formatter};
use std::io::{BufRead, Write};

use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{json, Map, Value};

use crate::tools::{self, BrokerToolClient, ToolInvocationError};
use keptnear_client::BrokerAdapterError;

/// Latest finalized MCP revision implemented by this adapter.
pub const MCP_PROTOCOL_VERSION_LATEST: &str = "2025-11-25";
/// Earlier finalized MCP revision retained for common host compatibility.
pub const MCP_PROTOCOL_VERSION_2025_06_18: &str = "2025-06-18";
/// Maximum accepted stdio JSON-RPC message before newline framing.
pub const MAX_MCP_MESSAGE_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdapterReadiness {
    Authenticated,
    PairingPending {
        comparison_code: psw_broker::PairingComparisonCode,
    },
    BrokerUnavailable,
}

pub(crate) trait AdapterAuthenticator: BrokerToolClient {
    fn ensure_authenticated(&mut self) -> AdapterReadiness;
}

/// Sanitized stdio MCP server failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum McpServerError {
    /// Reading the MCP host stream failed.
    Read,
    /// Writing a JSON-RPC response failed.
    Write,
}

impl Display for McpServerError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read => formatter.write_str("MCP input failed"),
            Self::Write => formatter.write_str("MCP output failed"),
        }
    }
}

impl std::error::Error for McpServerError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LifecycleState {
    AwaitingInitialize,
    AwaitingInitialized,
    Ready,
}

pub(crate) struct McpServer<Authenticator> {
    authenticator: Authenticator,
    lifecycle: LifecycleState,
    tools_enabled: bool,
}

impl<Authenticator> McpServer<Authenticator>
where
    Authenticator: AdapterAuthenticator,
{
    pub(crate) const fn new(authenticator: Authenticator) -> Self {
        Self {
            authenticator,
            lifecycle: LifecycleState::AwaitingInitialize,
            tools_enabled: false,
        }
    }

    pub(crate) fn serve(
        &mut self,
        reader: &mut impl BufRead,
        writer: &mut impl Write,
    ) -> Result<(), McpServerError> {
        loop {
            let line = match read_bounded_line(reader) {
                Ok(Some(line)) => line,
                Ok(None) => return Ok(()),
                Err(BoundedLineError::Oversized) => {
                    write_json(
                        writer,
                        &json_rpc_error(Value::Null, -32600, "Invalid Request"),
                    )?;
                    continue;
                }
                Err(BoundedLineError::Read) => return Err(McpServerError::Read),
            };
            if let Some(response) = self.handle_message(&line) {
                write_json(writer, &response)?;
            }
        }
    }

    fn handle_message(&mut self, line: &[u8]) -> Option<Value> {
        let value = match parse_unique_json(line) {
            Ok(value) => value,
            Err(_) => return Some(json_rpc_error(Value::Null, -32700, "Parse error")),
        };
        let Some(object) = value.as_object() else {
            return Some(json_rpc_error(Value::Null, -32600, "Invalid Request"));
        };
        if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || object.contains_key("result")
            || object.contains_key("error")
        {
            return Some(json_rpc_error(
                valid_request_id(object).unwrap_or(Value::Null),
                -32600,
                "Invalid Request",
            ));
        }
        let Some(method) = object.get("method").and_then(Value::as_str) else {
            return Some(json_rpc_error(
                valid_request_id(object).unwrap_or(Value::Null),
                -32600,
                "Invalid Request",
            ));
        };
        let request_id = valid_request_id(object);
        if object.contains_key("id") && request_id.is_none() {
            return Some(json_rpc_error(Value::Null, -32600, "Invalid Request"));
        }

        match request_id {
            Some(request_id) => Some(self.handle_request(request_id, method, object)),
            None => {
                self.handle_notification(method, object);
                None
            }
        }
    }

    fn handle_request(
        &mut self,
        request_id: Value,
        method: &str,
        object: &Map<String, Value>,
    ) -> Value {
        match method {
            "initialize" => self.initialize(request_id, object),
            "ping" => json_rpc_result(request_id, json!({})),
            _ if self.lifecycle == LifecycleState::AwaitingInitialize => {
                json_rpc_error(request_id, -32002, "Server not initialized")
            }
            _ if self.lifecycle != LifecycleState::Ready => {
                json_rpc_error(request_id, -32002, "Server not initialized")
            }
            "tools/list" if self.tools_enabled => self.list_tools(request_id, object),
            "tools/call" if self.tools_enabled => self.call_tool(request_id, object),
            _ => json_rpc_error(request_id, -32601, "Method not found"),
        }
    }

    fn initialize(&mut self, request_id: Value, object: &Map<String, Value>) -> Value {
        if self.lifecycle != LifecycleState::AwaitingInitialize {
            return json_rpc_error(request_id, -32600, "Invalid Request");
        }
        let Some(params) = object.get("params").and_then(Value::as_object) else {
            return json_rpc_error(request_id, -32602, "Invalid params");
        };
        let Some(requested_protocol) = params.get("protocolVersion").and_then(Value::as_str) else {
            return json_rpc_error(request_id, -32602, "Invalid params");
        };
        if !params.get("capabilities").is_some_and(Value::is_object)
            || !valid_implementation(params.get("clientInfo"))
        {
            return json_rpc_error(request_id, -32602, "Invalid params");
        }

        let selected_protocol = match requested_protocol {
            MCP_PROTOCOL_VERSION_LATEST => MCP_PROTOCOL_VERSION_LATEST,
            MCP_PROTOCOL_VERSION_2025_06_18 => MCP_PROTOCOL_VERSION_2025_06_18,
            _ => MCP_PROTOCOL_VERSION_LATEST,
        };
        let readiness = self.authenticator.ensure_authenticated();
        self.tools_enabled = readiness == AdapterReadiness::Authenticated;
        self.lifecycle = LifecycleState::AwaitingInitialized;

        let mut result = json!({
            "protocolVersion": selected_protocol,
            "capabilities": if self.tools_enabled {
                json!({"tools": {"listChanged": false}})
            } else {
                json!({})
            },
            "serverInfo": {
                "name": "KeptNear",
                "version": env!("CARGO_PKG_VERSION")
            }
        });
        let instruction = match readiness {
            AdapterReadiness::Authenticated => None,
            AdapterReadiness::PairingPending { comparison_code } => Some(format!(
                "Approve the local KeptNear MCP pairing and confirm comparison code {comparison_code}."
            )),
            AdapterReadiness::BrokerUnavailable => {
                Some("Open KeptNear so its local Broker is available.".to_owned())
            }
        };
        if let Some(instruction) = instruction {
            result
                .as_object_mut()
                .expect("initialize result is an object")
                .insert("instructions".to_owned(), Value::String(instruction));
        }
        json_rpc_result(request_id, result)
    }

    fn list_tools(&self, request_id: Value, object: &Map<String, Value>) -> Value {
        if !valid_list_tools_params(object.get("params")) {
            return json_rpc_error(request_id, -32602, "Invalid params");
        }
        json_rpc_result(request_id, json!({"tools": tools::catalog()}))
    }

    fn call_tool(&mut self, request_id: Value, object: &Map<String, Value>) -> Value {
        let Some(params) = object.get("params").and_then(Value::as_object) else {
            return json_rpc_error(request_id, -32602, "Invalid params");
        };
        if params
            .keys()
            .any(|key| !matches!(key.as_str(), "name" | "arguments" | "_meta"))
            || params.get("_meta").is_some_and(|value| !value.is_object())
        {
            return json_rpc_error(request_id, -32602, "Invalid params");
        }
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return json_rpc_error(request_id, -32602, "Invalid params");
        };
        if !tools::is_known_tool(name) {
            return json_rpc_error(request_id, -32602, "Unknown tool");
        }
        let arguments = match params.get("arguments") {
            Some(Value::Object(arguments)) => arguments.clone(),
            None => Map::new(),
            Some(_) => return json_rpc_error(request_id, -32602, "Invalid params"),
        };
        match tools::invoke(&mut self.authenticator, name, &arguments) {
            Ok(result) => json_rpc_result(request_id, tool_result(result, false)),
            Err(error) => json_rpc_result(request_id, tool_error_result(error)),
        }
    }

    fn handle_notification(&mut self, method: &str, object: &Map<String, Value>) {
        match method {
            "notifications/initialized"
                if self.lifecycle == LifecycleState::AwaitingInitialized
                    && valid_optional_object(object.get("params")) =>
            {
                self.lifecycle = LifecycleState::Ready;
            }
            // The current adapter performs one bounded Broker call
            // synchronously. MCP permits cancellation to be ignored when work
            // cannot be interrupted; reasons are deliberately not logged or
            // reflected.
            "notifications/cancelled" => {}
            _ => {}
        }
    }
}

fn valid_optional_object(value: Option<&Value>) -> bool {
    value.is_none_or(Value::is_object)
}

fn valid_list_tools_params(value: Option<&Value>) -> bool {
    let Some(params) = value else {
        return true;
    };
    let Some(params) = params.as_object() else {
        return false;
    };
    params.keys().all(|key| key == "_meta") && params.get("_meta").is_none_or(Value::is_object)
}

fn tool_result(structured: Value, is_error: bool) -> Value {
    let text = serde_json::to_string(&structured).unwrap_or_else(|_| {
        "{\"errorCode\":\"adapter-protocol-failure\",\"retryable\":false}".to_owned()
    });
    let mut result = json!({
        "content": [{"type": "text", "text": text}],
        "structuredContent": structured
    });
    if is_error {
        result
            .as_object_mut()
            .expect("tool result is an object")
            .insert("isError".to_owned(), Value::Bool(true));
    }
    result
}

fn tool_error_result(error: ToolInvocationError) -> Value {
    let structured = match error {
        ToolInvocationError::InvalidInput => json!({
            "errorCode": "invalid-input",
            "retryable": false,
            "requiredAction": null,
            "approvalRequestId": null
        }),
        ToolInvocationError::UnexpectedResponse => json!({
            "errorCode": "adapter-protocol-failure",
            "retryable": false,
            "requiredAction": null,
            "approvalRequestId": null
        }),
        ToolInvocationError::Broker(
            BrokerAdapterError::Identity | BrokerAdapterError::Transport,
        ) => json!({
            "errorCode": "broker-unavailable",
            "retryable": true,
            "requiredAction": "retry-later",
            "approvalRequestId": null
        }),
        ToolInvocationError::Broker(BrokerAdapterError::Protocol) => json!({
            "errorCode": "adapter-protocol-failure",
            "retryable": false,
            "requiredAction": null,
            "approvalRequestId": null
        }),
        ToolInvocationError::Broker(BrokerAdapterError::Broker {
            error_code,
            retryable,
            required_action,
            approval_request_id,
        }) => json!({
            "errorCode": error_code.as_str(),
            "retryable": retryable,
            "requiredAction": required_action.map(|action| action.as_str()),
            "approvalRequestId": approval_request_id.map(|approval| approval.to_string())
        }),
    };
    tool_result(structured, true)
}

fn valid_request_id(object: &Map<String, Value>) -> Option<Value> {
    match object.get("id") {
        Some(Value::String(value)) => Some(Value::String(value.clone())),
        Some(Value::Number(value)) if value.is_i64() || value.is_u64() => {
            Some(Value::Number(value.clone()))
        }
        _ => None,
    }
}

fn valid_implementation(value: Option<&Value>) -> bool {
    let Some(implementation) = value.and_then(Value::as_object) else {
        return false;
    };
    implementation
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(|name| !name.is_empty())
        && implementation
            .get("version")
            .and_then(Value::as_str)
            .is_some_and(|version| !version.is_empty())
}

struct UniqueJsonValue(Value);

impl<'de> serde::Deserialize<'de> for UniqueJsonValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(UniqueJsonVisitor)
    }
}

struct UniqueJsonVisitor;

impl<'de> Visitor<'de> for UniqueJsonVisitor {
    type Value = UniqueJsonValue;

    fn expecting(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(UniqueJsonValue)
            .ok_or_else(|| E::custom("non-finite number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value.to_owned())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(UniqueJsonValue(Value::Null))
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(UniqueJsonValue(value)) = sequence.next_element()? {
            values.push(value);
        }
        Ok(UniqueJsonValue(Value::Array(values)))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some((key, UniqueJsonValue(value))) = object.next_entry::<String, _>()? {
            if values.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate object key"));
            }
        }
        Ok(UniqueJsonValue(Value::Object(values)))
    }
}

fn parse_unique_json(payload: &[u8]) -> Result<Value, ()> {
    serde_json::from_slice::<UniqueJsonValue>(payload)
        .map(|value| value.0)
        .map_err(|_| ())
}

fn json_rpc_result(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result
    })
}

fn json_rpc_error(id: Value, code: i64, message: &'static str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message
        }
    })
}

fn write_json(writer: &mut impl Write, value: &Value) -> Result<(), McpServerError> {
    serde_json::to_writer(&mut *writer, value).map_err(|_| McpServerError::Write)?;
    writer
        .write_all(b"\n")
        .and_then(|()| writer.flush())
        .map_err(|_| McpServerError::Write)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BoundedLineError {
    Read,
    Oversized,
}

fn read_bounded_line(reader: &mut impl BufRead) -> Result<Option<Vec<u8>>, BoundedLineError> {
    let mut line = Vec::new();
    let mut oversized = false;
    loop {
        let available = reader.fill_buf().map_err(|_| BoundedLineError::Read)?;
        if available.is_empty() {
            if line.is_empty() && !oversized {
                return Ok(None);
            }
            if oversized {
                return Err(BoundedLineError::Oversized);
            }
            return Ok(Some(line));
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let consumed = newline.map_or(available.len(), |index| index + 1);
        let content = newline.map_or(available, |index| &available[..index]);
        if !oversized {
            if line.len().saturating_add(content.len()) > MAX_MCP_MESSAGE_BYTES {
                oversized = true;
                line.clear();
            } else {
                line.extend_from_slice(content);
            }
        }
        reader.consume(consumed);
        if newline.is_some() {
            if oversized {
                return Err(BoundedLineError::Oversized);
            }
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io::Cursor;
    use std::rc::Rc;

    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine as _;

    use super::*;

    struct FakeAuthenticator {
        statuses: VecDeque<AdapterReadiness>,
        tool_responses: VecDeque<Result<psw_broker::BrokerResponse, BrokerAdapterError>>,
        calls: Rc<Cell<usize>>,
    }

    impl BrokerToolClient for FakeAuthenticator {
        fn execute(
            &mut self,
            _request: psw_broker::BrokerRequest,
        ) -> Result<psw_broker::BrokerResponse, BrokerAdapterError> {
            self.tool_responses
                .pop_front()
                .unwrap_or(Err(BrokerAdapterError::Protocol))
        }
    }

    impl AdapterAuthenticator for FakeAuthenticator {
        fn ensure_authenticated(&mut self) -> AdapterReadiness {
            self.calls.set(self.calls.get() + 1);
            self.statuses
                .pop_front()
                .unwrap_or(AdapterReadiness::Authenticated)
        }
    }

    fn server(statuses: Vec<AdapterReadiness>) -> (McpServer<FakeAuthenticator>, Rc<Cell<usize>>) {
        let calls = Rc::new(Cell::new(0));
        (
            McpServer::new(FakeAuthenticator {
                statuses: statuses.into(),
                tool_responses: VecDeque::new(),
                calls: calls.clone(),
            }),
            calls,
        )
    }

    fn output_messages(output: Vec<u8>) -> Vec<Value> {
        String::from_utf8(output)
            .expect("UTF-8")
            .lines()
            .map(|line| serde_json::from_str(line).expect("JSON-RPC output"))
            .collect()
    }

    fn json_lines(messages: impl IntoIterator<Item = Value>) -> Vec<u8> {
        let mut input = Vec::new();
        for message in messages {
            serde_json::to_writer(&mut input, &message).expect("input JSON");
            input.push(b'\n');
        }
        input
    }

    #[test]
    fn stdio_lifecycle_emits_only_json_rpc_and_never_reflects_unknown_input() {
        let secret_marker = "KN_MCP_SECRET_MARKER_SHOULD_NOT_RETURN";
        let input = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{{}},\"clientInfo\":{{\"name\":\"test-host\",\"version\":\"1\"}}}}}}\n\
             {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n\
             {{\"jsonrpc\":\"2.0\",\"id\":\"ping-1\",\"method\":\"ping\"}}\n\
             {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"unknown.{secret_marker}\",\"params\":{{\"value\":\"{secret_marker}\"}}}}\n"
        );
        let (mut server, calls) = server(vec![AdapterReadiness::Authenticated]);
        let mut output = Vec::new();
        server
            .serve(&mut Cursor::new(input.as_bytes()), &mut output)
            .expect("serve");

        assert_eq!(calls.get(), 1);
        assert!(!String::from_utf8_lossy(&output).contains(secret_marker));
        let messages = output_messages(output);
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["id"], 1);
        assert_eq!(
            messages[0]["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION_LATEST
        );
        assert_eq!(
            messages[0]["result"]["capabilities"],
            json!({"tools": {"listChanged": false}})
        );
        assert_eq!(messages[1]["id"], "ping-1");
        assert_eq!(messages[1]["result"], json!({}));
        assert_eq!(messages[2]["error"]["code"], -32601);
    }

    #[test]
    fn pending_pairing_returns_only_the_human_comparison_instruction() {
        let code =
            psw_broker::PairingComparisonCode::from_ascii("0123456789").expect("comparison code");
        let (mut server, _) = server(vec![AdapterReadiness::PairingPending {
            comparison_code: code,
        }]);
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":7,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"host\",\"version\":\"1\"}}}\n";
        let mut output = Vec::new();
        server
            .serve(&mut Cursor::new(input), &mut output)
            .expect("serve");

        let messages = output_messages(output);
        assert_eq!(
            messages[0]["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION_2025_06_18
        );
        assert!(messages[0]["result"]["instructions"]
            .as_str()
            .expect("instructions")
            .contains(code.as_str()));
        assert!(messages[0]["result"].get("tools").is_none());
    }

    #[test]
    fn malformed_preinitialize_and_oversized_messages_fail_with_fixed_errors() {
        let oversized = "x".repeat(MAX_MCP_MESSAGE_BYTES + 1);
        let input = format!(
            "{{bad json}}\n\
             {{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}\n\
             {oversized}\n"
        );
        let (mut server, calls) = server(vec![]);
        let mut output = Vec::new();
        server
            .serve(&mut Cursor::new(input.as_bytes()), &mut output)
            .expect("serve");

        assert_eq!(calls.get(), 0);
        let messages = output_messages(output);
        assert_eq!(messages.len(), 3);
        assert_eq!(messages[0]["error"]["code"], -32700);
        assert_eq!(messages[1]["error"]["code"], -32002);
        assert_eq!(messages[2]["error"]["code"], -32600);
    }

    #[test]
    fn duplicate_keys_are_rejected_at_every_mcp_json_depth_without_reflection() {
        let marker = "KN_DUPLICATE_VALUE_MUST_NOT_RETURN";
        let use_grant_id = psw_broker::UseGrantId::generate();
        let input = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\
             \"protocolVersion\":\"2025-11-25\",\"capabilities\":{{}},\
             \"clientInfo\":{{\"name\":\"host\",\"version\":\"1\"}}}}}}\n\
             {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n\
             {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\
             \"name\":\"grant.status\",\"arguments\":{{\
             \"useGrantId\":\"{use_grant_id}\",\"useGrantId\":\"{marker}\"}}}}}}\n"
        );
        let (mut server, _) = server(vec![AdapterReadiness::Authenticated]);
        let mut output = Vec::new();
        server
            .serve(&mut Cursor::new(input.as_bytes()), &mut output)
            .expect("serve");

        assert!(!String::from_utf8_lossy(&output).contains(marker));
        let messages = output_messages(output);
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[1]["id"], Value::Null);
        assert_eq!(messages[1]["error"]["code"], -32700);
    }

    #[test]
    fn exact_stdio_message_bound_and_crlf_framing_are_stable() {
        let mut exact = vec![b' '; MAX_MCP_MESSAGE_BYTES];
        exact.push(b'\n');
        let accepted = read_bounded_line(&mut Cursor::new(exact)).expect("exact bound accepted");
        assert_eq!(accepted.expect("line").len(), MAX_MCP_MESSAGE_BYTES);

        let mut oversized_then_valid = vec![b'x'; MAX_MCP_MESSAGE_BYTES + 1];
        oversized_then_valid.extend_from_slice(b"\n{}\r\n");
        let mut reader = Cursor::new(oversized_then_valid);
        assert_eq!(
            read_bounded_line(&mut reader),
            Err(BoundedLineError::Oversized)
        );
        assert_eq!(
            read_bounded_line(&mut reader).expect("next line"),
            Some(b"{}".to_vec())
        );
    }

    #[test]
    fn unavailable_broker_does_not_advertise_tools_or_internal_errors() {
        let (mut server, _) = server(vec![AdapterReadiness::BrokerUnavailable]);
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"unsupported\",\"capabilities\":{},\"clientInfo\":{\"name\":\"host\",\"version\":\"1\"}}}\n";
        let mut output = Vec::new();
        server
            .serve(&mut Cursor::new(input), &mut output)
            .expect("serve");
        let messages = output_messages(output);

        assert_eq!(
            messages[0]["result"]["protocolVersion"],
            MCP_PROTOCOL_VERSION_LATEST
        );
        assert_eq!(messages[0]["result"]["capabilities"], json!({}));
        assert_eq!(
            messages[0]["result"]["instructions"],
            "Open KeptNear so its local Broker is available."
        );
    }

    #[test]
    fn finalized_revisions_and_standard_meta_have_the_same_tool_contract() {
        for (requested, selected) in [
            (MCP_PROTOCOL_VERSION_LATEST, MCP_PROTOCOL_VERSION_LATEST),
            (
                MCP_PROTOCOL_VERSION_2025_06_18,
                MCP_PROTOCOL_VERSION_2025_06_18,
            ),
            ("future-host-revision", MCP_PROTOCOL_VERSION_LATEST),
        ] {
            let input = json_lines([
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": requested,
                        "capabilities": {"experimental": {}},
                        "clientInfo": {
                            "name": "compatibility-host",
                            "title": "Compatibility Host",
                            "version": "1"
                        },
                        "_meta": {"com.example/trace": "ignored"}
                    }
                }),
                json!({
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {"_meta": {"com.example/trace": "ignored"}}
                }),
                json!({
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/list",
                    "params": {"_meta": {"com.example/trace": "ignored"}}
                }),
            ]);
            let (mut server, calls) = server(vec![AdapterReadiness::Authenticated]);
            let mut output = Vec::new();
            server
                .serve(&mut Cursor::new(input), &mut output)
                .expect("serve");
            let messages = output_messages(output);

            assert_eq!(calls.get(), 1);
            assert_eq!(messages.len(), 2);
            assert_eq!(messages[0]["result"]["protocolVersion"], selected);
            assert_eq!(messages[1]["result"]["tools"].as_array().unwrap().len(), 6);
            assert!(messages[1]["result"].get("nextCursor").is_none());
        }
    }

    #[test]
    fn lifecycle_and_cancellation_notifications_are_silent_and_bounded() {
        let marker = "KN_CANCELLATION_REASON_MUST_NOT_RETURN";
        let input = json_lines([
            json!({"jsonrpc": "2.0", "id": 1, "method": "ping"}),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION_LATEST,
                    "capabilities": {},
                    "clientInfo": {"name": "host", "version": "1"}
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": marker
            }),
            json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {"_meta": {}}
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/list",
                "params": {"_meta": {}}
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 4, "reason": marker}
            }),
            json!({
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": marker
            }),
            json!({"jsonrpc": "2.0", "id": 5, "method": "ping"}),
        ]);
        let (mut server, _) = server(vec![AdapterReadiness::Authenticated]);
        let mut output = Vec::new();
        server
            .serve(&mut Cursor::new(input), &mut output)
            .expect("serve");

        assert!(!String::from_utf8_lossy(&output).contains(marker));
        let messages = output_messages(output);
        assert_eq!(messages.len(), 5);
        assert_eq!(messages[0]["result"], json!({}));
        assert_eq!(messages[2]["error"]["code"], -32002);
        assert_eq!(messages[3]["result"]["tools"].as_array().unwrap().len(), 6);
        assert_eq!(messages[4]["result"], json!({}));
    }

    #[test]
    fn authenticated_server_lists_six_tools_and_reports_invalid_input_as_tool_error() {
        let input = b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\",\"capabilities\":{},\"clientInfo\":{\"name\":\"host\",\"version\":\"1\"}}}\n\
            {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\
            {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\",\"params\":{}}\n\
            {\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/call\",\"params\":{\"name\":\"grant.status\",\"arguments\":{\"useGrantId\":\"invalid\"}}}\n";
        let (mut server, _) = server(vec![AdapterReadiness::Authenticated]);
        let mut output = Vec::new();
        server
            .serve(&mut Cursor::new(input), &mut output)
            .expect("serve");
        let messages = output_messages(output);

        assert_eq!(messages[1]["result"]["tools"].as_array().unwrap().len(), 6);
        assert_eq!(messages[2]["result"]["isError"], true);
        assert_eq!(
            messages[2]["result"]["structuredContent"]["errorCode"],
            "invalid-input"
        );
        assert!(messages[2]["result"]["content"][0]["text"]
            .as_str()
            .expect("text")
            .contains("invalid-input"));
    }

    #[test]
    fn authenticated_tool_call_returns_structured_and_compatible_text_results() {
        let use_grant_id = psw_broker::UseGrantId::generate();
        let request_id = psw_broker::BrokerRequestId::generate();
        let wire_response = format!(
            "{{\"protocol_name\":\"keptnear.broker\",\"protocol_major\":1,\"protocol_minor\":0,\
             \"message_type\":\"grant.revoke.result\",\"request_id\":\"{request_id}\",\
             \"result\":{{\"revoked\":true}}}}"
        );
        let broker_response = psw_broker::decode_broker_response(wire_response.as_bytes())
            .expect("decode Broker response")
            .response()
            .clone();
        let input = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{{\
             \"protocolVersion\":\"2025-11-25\",\"capabilities\":{{}},\
             \"clientInfo\":{{\"name\":\"host\",\"version\":\"1\"}}}}}}\n\
             {{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}}\n\
             {{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{{\
             \"name\":\"grant.revoke\",\"arguments\":{{\"useGrantId\":\"{use_grant_id}\"}}}}}}\n"
        );
        let calls = Rc::new(Cell::new(0));
        let mut server = McpServer::new(FakeAuthenticator {
            statuses: vec![AdapterReadiness::Authenticated].into(),
            tool_responses: vec![Ok(broker_response)].into(),
            calls,
        });
        let mut output = Vec::new();
        server
            .serve(&mut Cursor::new(input.as_bytes()), &mut output)
            .expect("serve");
        let messages = output_messages(output);

        assert_eq!(
            messages[1]["result"]["structuredContent"],
            json!({"revoked": true})
        );
        assert_eq!(
            messages[1]["result"]["content"][0]["text"],
            "{\"revoked\":true}"
        );
        assert!(messages[1]["result"].get("isError").is_none());
        assert!(server.authenticator.tool_responses.is_empty());
    }

    #[test]
    fn every_tool_error_path_excludes_seeded_private_input_markers() {
        let marker = "KN_MCP_PRIVATE_INPUT_MARKER";
        let use_grant_id = psw_broker::UseGrantId::generate();
        let vault_id = psw_broker::VaultId::generate();
        let credential_id = psw_broker::CredentialId::generate();
        let secret_field_id = psw_broker::SecretFieldId::generate();
        let vault_session_id = psw_broker::VaultSessionId::generate();
        let usage_profile_id = psw_broker::UsageProfileId::generate();
        let body_base64 = BASE64_STANDARD.encode(marker.as_bytes());
        let common = json!({
            "useGrantId": use_grant_id.to_string(),
            "vaultId": vault_id.to_string(),
            "credentialId": credential_id.to_string(),
            "secretFieldId": secret_field_id.to_string(),
            "secretKind": "api-token",
            "vaultSessionId": vault_session_id.to_string()
        });
        let mut credential_arguments = common.clone();
        credential_arguments
            .as_object_mut()
            .expect("credential arguments")
            .insert("query".to_owned(), Value::String(marker.to_owned()));
        let http_arguments = {
            let mut arguments = common.clone();
            arguments.as_object_mut().expect("HTTP arguments").extend([
                (
                    "usageProfileId".to_owned(),
                    Value::String(usage_profile_id.to_string()),
                ),
                ("method".to_owned(), Value::String("POST".to_owned())),
                (
                    "url".to_owned(),
                    Value::String(format!("https://example.invalid/{marker}")),
                ),
                (
                    "headers".to_owned(),
                    json!([{"name": "X-Request-Marker", "value": marker}]),
                ),
                ("bodyBase64".to_owned(), Value::String(body_base64)),
            ]);
            arguments
        };
        let process_arguments = {
            let mut arguments = common;
            arguments
                .as_object_mut()
                .expect("process arguments")
                .extend([
                    (
                        "usageProfileId".to_owned(),
                        Value::String(usage_profile_id.to_string()),
                    ),
                    (
                        "executable".to_owned(),
                        Value::String("/usr/bin/printf".to_owned()),
                    ),
                    ("arguments".to_owned(), json!([marker])),
                    (
                        "environment".to_owned(),
                        json!([{"name": "KN_TEST_VALUE", "value": marker}]),
                    ),
                    ("timeoutMillis".to_owned(), json!(1)),
                ]);
            arguments
        };
        let input = json_lines([
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": MCP_PROTOCOL_VERSION_LATEST,
                    "capabilities": {},
                    "clientInfo": {"name": "host", "version": "1"}
                }
            }),
            json!({"jsonrpc": "2.0", "method": "notifications/initialized"}),
            json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {
                    "name": "credential.search",
                    "arguments": credential_arguments,
                    "_meta": {"com.example/private": marker}
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "access.request",
                    "arguments": {
                        "requestKind": "credential",
                        "capability": "http.request",
                        "vaultId": vault_id.to_string(),
                        "description": marker
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "grant.status",
                    "arguments": {
                        "useGrantId": use_grant_id.to_string(),
                        "privateMarker": marker
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": "grant.revoke",
                    "arguments": {
                        "useGrantId": use_grant_id.to_string(),
                        "privateMarker": marker
                    }
                }
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {"name": "http.request", "arguments": http_arguments}
            }),
            json!({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {"name": "process.run", "arguments": process_arguments}
            }),
        ]);
        let broker_failure = Err(BrokerAdapterError::Broker {
            error_code: psw_broker::BrokerErrorCode::AccessDenied,
            retryable: false,
            required_action: None,
            approval_request_id: None,
        });
        let calls = Rc::new(Cell::new(0));
        let mut server = McpServer::new(FakeAuthenticator {
            statuses: vec![AdapterReadiness::Authenticated].into(),
            tool_responses: vec![broker_failure; 4].into(),
            calls,
        });
        let mut output = Vec::new();
        server
            .serve(&mut Cursor::new(input), &mut output)
            .expect("serve");

        assert!(!String::from_utf8_lossy(&output).contains(marker));
        let messages = output_messages(output);
        assert_eq!(messages.len(), 7);
        for message in &messages[1..] {
            assert_eq!(message["result"]["isError"], true);
            let structured = &message["result"]["structuredContent"];
            assert_eq!(
                message["result"]["content"][0]["text"],
                serde_json::to_string(structured).expect("compatible text")
            );
        }
        assert!(server.authenticator.tool_responses.is_empty());
    }
}
