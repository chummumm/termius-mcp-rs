//! Bounded JSONL MCP transport, with legacy Content-Length input compatibility.
use crate::tools::{Runtime, catalog};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
const MAX_HEADER_BYTES: usize = 8192;
const MAX_IN_FLIGHT: usize = 32;
const VERSIONS: &[&str] = &["2025-11-25", "2025-06-18"];

#[derive(Debug)]
pub struct FrameError {
    pub message: &'static str,
    pub fatal: bool,
}
impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message)
    }
}
impl std::error::Error for FrameError {}
fn frame_error(message: &'static str, fatal: bool) -> FrameError {
    FrameError { message, fatal }
}

async fn bounded_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    limit: usize,
) -> Result<Option<Vec<u8>>, FrameError> {
    let mut line = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|_| frame_error("Cannot read MCP input", true))?;
        if available.is_empty() {
            return if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            };
        }
        let end = available.iter().position(|b| *b == b'\n').map(|i| i + 1);
        let count = end.unwrap_or(available.len());
        if line.len() + count > limit {
            return Err(frame_error("MCP frame exceeds the size limit", true));
        }
        line.extend_from_slice(&available[..count]);
        reader.consume(count);
        if end.is_some() {
            return Ok(Some(line));
        }
    }
}

pub async fn read_message<R: AsyncBufRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Value>, FrameError> {
    let first = loop {
        let Some(line) = bounded_line(reader, MAX_FRAME_BYTES).await? else {
            return Ok(None);
        };
        if line.iter().any(|b| !b.is_ascii_whitespace()) {
            break line;
        }
    };
    let start = first
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(0);
    if matches!(first[start], b'{' | b'[') {
        return serde_json::from_slice(&first)
            .map(Some)
            .map_err(|_| frame_error("MCP body is not valid JSON", false));
    }
    let first_is_header = std::str::from_utf8(&first[start..])
        .ok()
        .and_then(|line| line.split_once(':'))
        .is_some_and(|(name, _)| {
            !name.trim().is_empty()
                && name
                    .trim()
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        });
    if !first_is_header {
        return Err(frame_error(
            "Expected a JSON object or Content-Length header",
            false,
        ));
    }
    let mut current = first;
    let mut length = None;
    let mut header_bytes = 0;
    loop {
        header_bytes += current.len();
        if header_bytes > MAX_HEADER_BYTES {
            return Err(frame_error("MCP headers exceed the size limit", true));
        }
        if current == b"\r\n" || current == b"\n" {
            break;
        }
        let text = std::str::from_utf8(&current)
            .map_err(|_| frame_error("MCP header is not valid UTF-8", true))?;
        let (key, value) = text
            .split_once(':')
            .ok_or_else(|| frame_error("Malformed MCP header", true))?;
        if key.trim().eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(frame_error("Duplicate Content-Length header", true));
            }
            let n = value
                .trim()
                .parse::<usize>()
                .map_err(|_| frame_error("Invalid Content-Length", true))?;
            if n > MAX_FRAME_BYTES {
                return Err(frame_error("MCP frame exceeds the size limit", true));
            }
            length = Some(n);
        }
        current = bounded_line(reader, MAX_HEADER_BYTES)
            .await?
            .ok_or_else(|| frame_error("Truncated MCP headers", true))?;
    }
    let mut body = vec![0u8; length.ok_or_else(|| frame_error("Missing Content-Length", true))?];
    reader
        .read_exact(&mut body)
        .await
        .map_err(|_| frame_error("Truncated MCP body", true))?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|_| frame_error("MCP body is not valid JSON", false))
}

pub fn rpc_result(id: Value, result: Value) -> Value {
    json!({"jsonrpc":"2.0","id":id,"result":result})
}
pub fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}

pub fn initialize_result(params: &Value) -> Value {
    let requested = params["protocolVersion"].as_str().unwrap_or("");
    let negotiated = if VERSIONS.contains(&requested) {
        requested
    } else {
        VERSIONS[0]
    };
    json!({
        "protocolVersion":negotiated,
        "capabilities":{"tools":{"listChanged":false}},
        "serverInfo":{"name":"termius-mcp-rs","title":"Termius Cloud (Rust)","version":env!("CARGO_PKG_VERSION")},
        "instructions":"Termius Cloud inventory, SSH execution and SFTP. Call status first. Sign in with login, then sync. Google login is completed using login_complete. Never disclose vault passwords or private keys. exec and files can change remote systems; obtain the user's authorization for the requested operation."
    })
}

struct Outgoing {
    payload: Value,
    cancel: Option<CancellationToken>,
}
type Calls = Arc<Mutex<HashMap<String, CancellationToken>>>;

pub async fn serve<R, W>(runtime: Arc<Runtime>, mut input: R, mut output: W) -> anyhow::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<Outgoing>(64);
    let mut writer = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if message
                .cancel
                .as_ref()
                .is_some_and(CancellationToken::is_cancelled)
            {
                continue;
            }
            let mut data = serde_json::to_vec(&message.payload)?;
            data.push(b'\n');
            output.write_all(&data).await?;
            output.flush().await?;
        }
        anyhow::Ok(())
    });
    let calls: Calls = Arc::new(Mutex::new(HashMap::new()));
    let tracker = TaskTracker::new();
    let mut initialized = false;
    let mut ready = false;
    let mut writer_result = None;
    loop {
        // Either half of stdio ending terminates this MCP session. In particular,
        // a broken output pipe must cancel remote work even while stdin is open.
        let incoming = tokio::select! {
            biased;
            result = &mut writer => {
                writer_result = Some(result);
                break;
            }
            message = read_message(&mut input) => message,
        };
        let message = match incoming {
            Ok(Some(m)) => m,
            Ok(None) => break,
            Err(e) => {
                if tx
                    .send(Outgoing {
                        payload: rpc_error(Value::Null, -32700, e.message),
                        cancel: None,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
                if e.fatal {
                    break;
                } else {
                    continue;
                }
            }
        };
        let id = message.get("id").cloned();
        let valid_id = id
            .as_ref()
            .is_none_or(|v| v.is_string() || v.is_i64() || v.is_u64());
        if !message.is_object()
            || message["jsonrpc"] != "2.0"
            || !message["method"].is_string()
            || !valid_id
        {
            let response_id = id
                .filter(|v| v.is_string() || v.is_i64() || v.is_u64())
                .unwrap_or(Value::Null);
            if tx
                .send(Outgoing {
                    payload: rpc_error(response_id, -32600, "Invalid JSON-RPC request"),
                    cancel: None,
                })
                .await
                .is_err()
            {
                break;
            }
            continue;
        }
        let method = message["method"].as_str().unwrap();
        let params = message.get("params").cloned().unwrap_or_else(|| json!({}));
        if !params.is_object() {
            if let Some(id) = id {
                let _ = tx
                    .send(Outgoing {
                        payload: rpc_error(id, -32602, "params must be an object"),
                        cancel: None,
                    })
                    .await;
            }
            continue;
        }
        if id.is_none() {
            match method {
                "notifications/initialized" if initialized => ready = true,
                "notifications/cancelled" => {
                    if let Some(request) = params.get("requestId")
                        && let Some(token) = calls.lock().unwrap().get(&request.to_string())
                    {
                        token.cancel();
                    }
                }
                _ => {}
            }
            continue;
        }
        let id = id.unwrap();
        let payload = match method {
            "initialize" if !initialized => {
                if !params["protocolVersion"].is_string() {
                    rpc_error(id, -32602, "protocolVersion is required")
                } else {
                    initialized = true;
                    rpc_result(id, initialize_result(&params))
                }
            }
            "initialize" => rpc_error(id, -32600, "Already initialized"),
            "ping" => rpc_result(id, json!({})),
            "tools/list" | "tools/call" if !ready => {
                rpc_error(id, -32000, "Initialize the MCP connection first")
            }
            "tools/list" => rpc_result(id, json!({"tools":catalog()})),
            "tools/call" => {
                let Some(name) = params["name"].as_str() else {
                    let _ = tx
                        .send(Outgoing {
                            payload: rpc_error(id, -32602, "Tool name is required"),
                            cancel: None,
                        })
                        .await;
                    continue;
                };
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if !args.is_object() {
                    let _ = tx
                        .send(Outgoing {
                            payload: rpc_error(id, -32602, "arguments must be an object"),
                            cancel: None,
                        })
                        .await;
                    continue;
                }
                let key = id.to_string();
                let token = CancellationToken::new();
                let rejected = {
                    let mut active = calls.lock().unwrap();
                    if active.contains_key(&key) {
                        Some("Request ID is already in flight")
                    } else if active.len() >= MAX_IN_FLIGHT {
                        Some("Too many requests in flight")
                    } else {
                        active.insert(key.clone(), token.clone());
                        None
                    }
                };
                if let Some(reason) = rejected {
                    let _ = tx
                        .send(Outgoing {
                            payload: rpc_error(id, -32000, reason),
                            cancel: None,
                        })
                        .await;
                    continue;
                }
                let (runtime, tx, calls, name) =
                    (runtime.clone(), tx.clone(), calls.clone(), name.to_string());
                tracker.spawn(async move {
                    let result=runtime.call(&name,args,token.clone()).await;
                    let result=match result {
                        Ok(data)=>json!({"content":[{"type":"text","text":serde_json::to_string(&data).unwrap_or_default()}],"structuredContent":data}),
                        Err(e)=>{
                            let data=json!({"error":e.message,"code":e.code});
                            json!({"content":[{"type":"text","text":serde_json::to_string(&data).unwrap_or_default()}],"structuredContent":data,"isError":true})
                        }
                    };
                    if !token.is_cancelled(){let _=tx.send(Outgoing{payload:rpc_result(id,result),cancel:Some(token)}).await;}
                    calls.lock().unwrap().remove(&key);
                });
                continue;
            }
            _ => rpc_error(id, -32601, "Method not found"),
        };
        if tx
            .send(Outgoing {
                payload,
                cancel: None,
            })
            .await
            .is_err()
        {
            break;
        }
    }
    for token in calls.lock().unwrap().values() {
        token.cancel();
    }
    tracker.close();
    // Do not keep a closed MCP client alive while a dead network peer stalls cleanup.
    let _ = tokio::time::timeout(Duration::from_secs(5), tracker.wait()).await;
    drop(tx);
    // A completed JoinHandle must not be polled twice. Otherwise drain queued
    // responses for a bounded interval, even if a task still owns a sender.
    match writer_result {
        Some(result) => result??,
        None => match tokio::time::timeout(Duration::from_secs(5), &mut writer).await {
            Ok(result) => result??,
            Err(_) => writer.abort(),
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;
    #[tokio::test]
    async fn jsonl_and_legacy_frames_share_a_stream() {
        let body = r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#;
        let stream = format!(
            "{{\"id\":1}}\nContent-Length: {}\r\nContent-Type: application/json\r\n\r\n{}{{\"id\":3}}\n",
            body.len(),
            body
        );
        let mut reader = BufReader::new(stream.as_bytes());
        assert_eq!(read_message(&mut reader).await.unwrap().unwrap()["id"], 1);
        assert_eq!(read_message(&mut reader).await.unwrap().unwrap()["id"], 2);
        assert_eq!(read_message(&mut reader).await.unwrap().unwrap()["id"], 3);
        assert!(read_message(&mut reader).await.unwrap().is_none());
    }
    #[tokio::test]
    async fn oversized_and_ambiguous_frames_are_rejected() {
        for input in [
            "Content-Length: 2097153\r\n\r\n",
            "Content-Length: 2\r\nContent-Length: 2\r\n\r\n{}",
            "Content-Length: -1\r\n\r\n",
        ] {
            let mut reader = BufReader::new(input.as_bytes());
            assert!(read_message(&mut reader).await.unwrap_err().fatal);
        }
        let huge = vec![b'x'; MAX_FRAME_BYTES + 1];
        assert!(
            read_message(&mut BufReader::new(huge.as_slice()))
                .await
                .unwrap_err()
                .fatal
        );
    }
    #[tokio::test]
    async fn malformed_json_recovers_at_next_line() {
        let mut reader = BufReader::new(b"{bad}\n{\"ok\":true}\n".as_slice());
        assert!(!read_message(&mut reader).await.unwrap_err().fatal);
        assert_eq!(
            read_message(&mut reader).await.unwrap().unwrap()["ok"],
            true
        );
    }
    #[test]
    fn negotiation_echoes_supported_revisions() {
        for version in VERSIONS {
            assert_eq!(
                initialize_result(&json!({"protocolVersion":version}))["protocolVersion"],
                *version
            );
        }
        assert_eq!(
            initialize_result(&json!({"protocolVersion":"future"}))["protocolVersion"],
            VERSIONS[0]
        );
    }
}
