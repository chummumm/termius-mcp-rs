//! End-to-end MCP transport and dispatch tests with disposable encrypted state.
use anyhow::{Context, Result};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use termius_mcp::{protocol, storage::Store, tools::Runtime};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::io::{
    AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader, DuplexStream, ReadHalf, WriteHalf,
};
use tokio_util::sync::CancellationToken;

const OPTIONAL_KEY_WARNING: &str =
    "Team vault keys could not be loaded; entities requiring those keys remain unavailable";

fn runtime(port: u16) -> Result<(tempfile::TempDir, Arc<Runtime>)> {
    let directory = tempfile::tempdir()?;
    let mut store = Store::open_with(
        directory.path().join("data"),
        Some("test-only-state-passphrase"),
        Some("0"),
    )?;
    store.state.session =
        Some(json!({"username":"fixture@example.invalid","apikey":"fixture-device-token"}));
    store.state.vault_password = Some("fixture-vault-password".into());
    store.state.last_synced = Some(OffsetDateTime::now_utc().format(&Rfc3339)?);
    store.state.inventory = json!({
        "host_set":[{"id":1,"label":"stall","address":"127.0.0.1","ssh_config":10}],
        "group_set":[{"id":2,"label":"fixture-group"}],
        "sshconfig_set":[{"id":10,"identity":100,"port":port}],
        "identity_set":[{"id":100,"username":"fixture","is_visible":true,"label":"fixture-identity","password":"fixture-ssh-password"}],
        "sshkeycrypt_set":[{"id":300,"label":"fixture-key","private_key":"fixture-private-material"}],
        "snippet_set":[{"id":400,"label":"fixture-snippet","script":"echo fixture"}],
        "unreadable_entities":0,
        "sync_warnings":[OPTIONAL_KEY_WARNING]
    });
    store.save()?;
    Ok((directory, Runtime::new(store)))
}
async fn send(writer: &mut WriteHalf<DuplexStream>, value: Value) -> Result<()> {
    let mut text = serde_json::to_vec(&value)?;
    text.push(b'\n');
    writer.write_all(&text).await?;
    writer.flush().await?;
    Ok(())
}
async fn receive(reader: &mut BufReader<ReadHalf<DuplexStream>>) -> Result<Value> {
    let mut text = String::new();
    let read = tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut text)).await??;
    anyhow::ensure!(read > 0, "MCP output closed unexpectedly");
    serde_json::from_str(&text).context("MCP output must be JSONL without logs")
}
async fn initialize(
    reader: &mut BufReader<ReadHalf<DuplexStream>>,
    writer: &mut WriteHalf<DuplexStream>,
) -> Result<()> {
    send(writer,json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"integration","version":"1"}}})).await?;
    assert_eq!(
        receive(reader).await?["result"]["protocolVersion"],
        "2025-11-25"
    );
    send(
        writer,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
    )
    .await
}

#[tokio::test]
async fn all_inventory_tools_have_flat_safe_envelopes() -> Result<()> {
    let (_dir, runtime) = runtime(22)?;
    for kind in ["groups", "identities", "keys", "snippets"] {
        let data = runtime
            .call("inventory", json!({"kind":kind}), CancellationToken::new())
            .await?;
        assert!(
            data["items"].is_array(),
            "{kind} must expose an array, not a nested result"
        );
        assert_eq!(data["count"], 1);
        assert_eq!(data["kind"], kind);
        let encoded = data.to_string();
        for secret in [
            "fixture-device-token",
            "fixture-vault-password",
            "fixture-ssh-password",
            "fixture-private-material",
        ] {
            assert!(!encoded.contains(secret));
        }
    }
    let data = runtime
        .call("hosts", json!({}), CancellationToken::new())
        .await?;
    assert_eq!(data["count"], 1);
    assert!(data["hosts"].is_array());
    Ok(())
}

#[tokio::test]
async fn optional_key_diagnostics_are_explicit_and_legacy_text_matches_structured_data()
-> Result<()> {
    let (_dir, runtime) = runtime(22)?;
    for (name, args) in [
        ("status", json!({})),
        ("hosts", json!({})),
        ("host", json!({"name":"1"})),
        ("inventory", json!({"kind":"snippets"})),
    ] {
        let data = runtime.call(name, args, CancellationToken::new()).await?;
        assert!(data.get("sync_warnings").is_none(), "{name}");
        assert!(data.get("unreadable_entities").is_none(), "{name}");
        assert!(!data.to_string().contains(OPTIONAL_KEY_WARNING));
    }

    let (client, server) = tokio::io::duplex(65536);
    let (server_read, server_write) = tokio::io::split(server);
    let task = tokio::spawn(protocol::serve(
        runtime,
        BufReader::new(server_read),
        server_write,
    ));
    let (read, mut write) = tokio::io::split(client);
    let mut read = BufReader::new(read);
    initialize(&mut read, &mut write).await?;
    for (id, diagnostics) in [(2, false), (3, true)] {
        send(&mut write, json!({"jsonrpc":"2.0","id":id,"method":"tools/call","params":{"name":"status","arguments":{"diagnostics":diagnostics}}})).await?;
        let result = receive(&mut read).await?["result"].clone();
        let text = result["content"][0]["text"]
            .as_str()
            .context("text result")?;
        let decoded: Value = serde_json::from_str(text)?;
        assert_eq!(decoded, result["structuredContent"]);
        assert_eq!(result["content"].as_array().unwrap().len(), 1);
        assert_eq!(text.contains(OPTIONAL_KEY_WARNING), diagnostics);
        if diagnostics {
            assert_eq!(decoded["sync_warnings"], json!([OPTIONAL_KEY_WARNING]));
        }
    }
    write.shutdown().await?;
    task.await??;
    Ok(())
}

#[tokio::test]
async fn partial_inventory_is_disclosed_without_repeating_transport_warnings() -> Result<()> {
    let (dir, runtime) = runtime(22)?;
    let mut store = Store::open_with(
        dir.path().join("data"),
        Some("test-only-state-passphrase"),
        Some("0"),
    )?;
    store.state.inventory["host_set"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id":2,"_undecryptable":true}));
    store.state.inventory["unreadable_entities"] = json!(1);
    store.save()?;
    for (name, args) in [
        ("status", json!({})),
        ("hosts", json!({})),
        ("inventory", json!({"kind":"groups"})),
    ] {
        let data = runtime.call(name, args, CancellationToken::new()).await?;
        assert_eq!(data["unreadable_entities"], 1, "{name}");
        assert!(data.get("sync_warnings").is_none(), "{name}");
        if name == "hosts" {
            assert_eq!(data["count"], 1);
        }
    }
    let readable = runtime
        .call("host", json!({"name":"1"}), CancellationToken::new())
        .await?;
    assert!(readable.get("unreadable_entities").is_none());
    let error = runtime
        .call(
            "exec",
            json!({"name":"2","command":"true"}),
            CancellationToken::new(),
        )
        .await
        .expect_err("an unavailable target must still fail before opening a socket");
    assert_eq!(error.code, "ssh_failed");
    Ok(())
}

#[tokio::test]
async fn optional_pagination_and_script_projection_preserve_default_results() -> Result<()> {
    let (dir, runtime) = runtime(22)?;
    let mut store = Store::open_with(
        dir.path().join("data"),
        Some("test-only-state-passphrase"),
        Some("0"),
    )?;
    store.state.inventory["host_set"]
        .as_array_mut()
        .unwrap()
        .extend([
            json!({"id":2,"label":"other","address":"127.0.0.2","ssh_config":10}),
            json!({"id":3,"label":"match-a","address":"127.0.0.3","ssh_config":10}),
            json!({"id":4,"label":"match-b","address":"127.0.0.4","ssh_config":10}),
        ]);
    store.save()?;
    let all = runtime
        .call("hosts", json!({}), CancellationToken::new())
        .await?;
    assert_eq!(all["count"], 4);
    assert!(all.get("total").is_none());
    for (offset, expected_id, next) in [(0, 3, Some(1)), (1, 4, None)] {
        let page = runtime
            .call(
                "hosts",
                json!({"query":"match", "limit":1, "offset":offset}),
                CancellationToken::new(),
            )
            .await?;
        assert_eq!(page["total"], 2);
        assert_eq!(page["count"], 1);
        assert_eq!(page["offset"], offset);
        assert_eq!(page["next_offset"], json!(next));
        assert_eq!(page["hosts"][0]["id"], expected_id);
    }
    let empty = runtime
        .call(
            "hosts",
            json!({"limit":1,"offset":usize::MAX}),
            CancellationToken::new(),
        )
        .await?;
    assert_eq!(empty["count"], 0);
    assert_eq!(empty["total"], 4);
    assert_eq!(empty["next_offset"], Value::Null);
    assert_eq!(empty["hosts"], json!([]));
    let full = runtime
        .call(
            "inventory",
            json!({"kind":"snippets"}),
            CancellationToken::new(),
        )
        .await?;
    assert_eq!(full["items"][0]["script"], "echo fixture");
    assert!(full.get("total").is_none());
    let compact = runtime
        .call(
            "inventory",
            json!({"kind":"snippets","include_script":false,"limit":1}),
            CancellationToken::new(),
        )
        .await?;
    assert_eq!(
        compact["items"],
        json!([{"id":400,"label":"fixture-snippet"}])
    );
    assert_eq!(compact["count"], 1);
    assert_eq!(compact["total"], 1);
    assert_eq!(compact["next_offset"], Value::Null);
    Ok(())
}

#[tokio::test]
async fn handshake_protocol_errors_and_tool_errors_are_separate() -> Result<()> {
    let (_dir, runtime) = runtime(22)?;
    let (client, server) = tokio::io::duplex(65536);
    let (server_read, server_write) = tokio::io::split(server);
    let task = tokio::spawn(protocol::serve(
        runtime,
        BufReader::new(server_read),
        server_write,
    ));
    let (read, mut write) = tokio::io::split(client);
    let mut read = BufReader::new(read);
    send(
        &mut write,
        json!({"jsonrpc":"2.0","id":0,"method":"tools/list"}),
    )
    .await?;
    assert_eq!(receive(&mut read).await?["error"]["code"], -32000);
    initialize(&mut read, &mut write).await?;
    send(
        &mut write,
        json!({"jsonrpc":"2.0","id":2,"method":"tools/list"}),
    )
    .await?;
    assert_eq!(
        receive(&mut read).await?["result"]["tools"]
            .as_array()
            .unwrap()
            .len(),
        10
    );
    send(&mut write,json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"files","arguments":{"name":"stall","action":"rm","recursive":"false","path":"/tmp/x"}}})).await?;
    let error = receive(&mut read).await?;
    assert_eq!(error["result"]["isError"], true);
    assert_eq!(
        error["result"]["structuredContent"]["code"],
        "invalid_argument"
    );
    write.write_all(b"{broken}\n").await?;
    assert_eq!(receive(&mut read).await?["error"]["code"], -32700);
    send(&mut write, json!({"jsonrpc":"2.0","id":4,"method":"ping"})).await?;
    assert_eq!(receive(&mut read).await?["id"], 4);
    write.shutdown().await?;
    task.await??;
    Ok(())
}

#[tokio::test]
async fn stalled_ssh_does_not_block_status_and_cancellation_closes_transport() -> Result<()> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let (_dir, runtime) = runtime(listener.local_addr()?.port())?;
    let (client, server) = tokio::io::duplex(65536);
    let (server_read, server_write) = tokio::io::split(server);
    let task = tokio::spawn(protocol::serve(
        runtime,
        BufReader::new(server_read),
        server_write,
    ));
    let (read, mut write) = tokio::io::split(client);
    let mut read = BufReader::new(read);
    initialize(&mut read, &mut write).await?;
    send(&mut write,json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":{"name":"stall","command":"true","timeout":30}}})).await?;
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept()).await??;
    send(&mut write,json!({"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"status","arguments":{}}})).await?;
    let response = tokio::time::timeout(Duration::from_secs(2), receive(&mut read)).await??;
    assert_eq!(response["id"], 3);
    assert_eq!(response["result"]["structuredContent"]["logged_in"], true);
    send(
        &mut write,
        json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":2}}),
    )
    .await?;
    let mut drained = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut drained)).await??;
    send(&mut write, json!({"jsonrpc":"2.0","id":4,"method":"ping"})).await?;
    assert_eq!(
        receive(&mut read).await?["id"],
        4,
        "cancelled request must not emit a response"
    );
    write.shutdown().await?;
    task.await??;
    Ok(())
}
