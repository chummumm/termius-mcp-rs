//! Independent regressions for transport and state-boundary design contracts.
use anyhow::Result;
use serde_json::json;
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use termius_mcp::{protocol, storage::Store, tools::Runtime};
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::oneshot,
};

struct BrokenOutput {
    fail: Arc<AtomicBool>,
    attempted: Option<oneshot::Sender<()>>,
}
impl AsyncWrite for BrokenOutput {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.fail.load(Ordering::Relaxed) {
            return Poll::Ready(Ok(bytes.len()));
        }
        if let Some(attempted) = self.attempted.take() {
            let _ = attempted.send(());
        }
        Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn failed_output_ends_protocol_even_if_input_remains_open() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let runtime = Runtime::new(Store::open_with(
        directory.path().join("state"),
        Some("test-only-design-review-key"),
        Some("0"),
    )?);
    let (mut client, input) = tokio::io::duplex(4096);
    let (attempted, observed) = oneshot::channel();
    let mut serving = tokio::spawn(protocol::serve(
        runtime,
        BufReader::new(input),
        BrokenOutput {
            fail: Arc::new(AtomicBool::new(true)),
            attempted: Some(attempted),
        },
    ));
    client
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\"}}\n")
        .await?;
    tokio::time::timeout(Duration::from_secs(2), observed).await??;
    // Keep the input peer alive: a failed output must terminate the whole
    // transport, rather than waiting for unrelated future input or EOF.
    let result = match tokio::time::timeout(Duration::from_secs(1), &mut serving).await {
        Ok(joined) => joined?,
        Err(_) => {
            serving.abort();
            panic!("MCP server stayed alive after its output pipe failed");
        }
    };
    assert!(result.is_err(), "the output error must reach the caller");
    Ok(())
}

#[tokio::test]
async fn failed_output_cancels_an_active_ssh_connection() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let directory = tempfile::tempdir()?;
    let mut store = Store::open_with(
        directory.path().join("state"),
        Some("test-only-design-review-key"),
        Some("0"),
    )?;
    store.state.session =
        Some(json!({"username":"fixture@example.invalid","apikey":"fixture-token"}));
    store.state.vault_password = Some("fixture-vault-password".into());
    store.state.last_synced = Some(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .to_string(),
    );
    store.state.inventory = json!({
        "host_set":[{"id":1,"label":"stall","address":"127.0.0.1","ssh_config":10}],
        "sshconfig_set":[{"id":10,"identity":100,"port":listener.local_addr()?.port(),"strict_host_key_check":false}],
        "identity_set":[{"id":100,"username":"fixture","password":"fixture-ssh-password"}]
    });
    store.save()?;
    let (mut client, input) = tokio::io::duplex(8192);
    let fail = Arc::new(AtomicBool::new(false));
    let (attempted, observed) = oneshot::channel();
    let mut serving = tokio::spawn(protocol::serve(
        Runtime::new(store),
        BufReader::new(input),
        BrokenOutput {
            fail: fail.clone(),
            attempted: Some(attempted),
        },
    ));
    for message in [
        json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}),
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"exec","arguments":{"name":"stall","command":"true","timeout":30}}}),
    ] {
        client.write_all(format!("{message}\n").as_bytes()).await?;
    }
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(3), listener.accept()).await??;
    // The real TCP connection is now waiting for an SSH banner. Fail a later
    // ping response while preserving the client input stream.
    fail.store(true, Ordering::Relaxed);
    client
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"ping\"}\n")
        .await?;
    tokio::time::timeout(Duration::from_secs(2), observed).await??;
    let mut buffered = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), socket.read_to_end(&mut buffered)).await??;
    let result = tokio::time::timeout(Duration::from_secs(2), &mut serving).await??;
    assert!(result.is_err(), "the output failure must reach the caller");
    Ok(())
}
