//! Real protocol checks against OpenSSH, with generated disposable keys.
//! Run explicitly: cargo test --test ssh_openssh -- --ignored
//! Requires ssh-keygen and sshd; no existing SSH configuration is modified.
#![cfg(unix)]
use anyhow::{Context, Result, ensure};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use termius_mcp::{
    ConnectionSpec, Endpoint,
    ssh::{run_exec, run_files},
    storage::Store,
    tools::Runtime,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio_util::sync::CancellationToken;

struct Fixture {
    child: Child,
    directory: tempfile::TempDir,
    endpoint: Endpoint,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Fixture {
    fn start() -> Result<Self> {
        let directory = tempfile::tempdir()?;
        let path = directory.path();
        for filename in ["host_key", "client_key"] {
            ensure!(
                Command::new("ssh-keygen")
                    .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                    .arg(path.join(filename))
                    .status()?
                    .success(),
                "ssh-keygen failed"
            );
        }
        let username = String::from_utf8(Command::new("id").arg("-un").output()?.stdout)?
            .trim()
            .to_owned();
        ensure!(!username.is_empty(), "Could not determine current username");
        let socket = std::net::TcpListener::bind("127.0.0.1:0")?;
        let port = socket.local_addr()?.port();
        drop(socket);
        let config = format!(
            "Port {port}\nListenAddress 127.0.0.1\nHostKey {}/host_key\nAuthorizedKeysFile {}/client_key.pub\nPidFile {}/pid\nStrictModes no\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nPubkeyAuthentication yes\nPermitRootLogin yes\nAllowUsers {username}\nAllowTcpForwarding yes\nSubsystem sftp internal-sftp\nLogLevel ERROR\n",
            path.display(),
            path.display(),
            path.display()
        );
        std::fs::write(path.join("sshd_config"), config)?;
        let log = std::fs::File::create(path.join("sshd.log"))?;
        let sshd = std::env::var_os("TERMIUS_TEST_SSHD")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/usr/sbin/sshd"));
        let child = Command::new(sshd)
            .args(["-D", "-e", "-f"])
            .arg(path.join("sshd_config"))
            .stdin(Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()
            .context("Start local OpenSSH server")?;
        let endpoint = Endpoint {
            address: "127.0.0.1".into(),
            port,
            username: Some(username),
            password: None,
            private_key: Some(std::fs::read_to_string(path.join("client_key"))?),
            passphrase: None,
            strict_host_key_check: true,
            known_host_keys: vec![std::fs::read_to_string(path.join("host_key.pub"))?],
            connect_timeout: 5,
            keep_alive: 0,
        };
        let mut fixture = Self {
            child,
            directory,
            endpoint,
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
                break;
            }
            if let Some(status) = fixture.child.try_wait()? {
                anyhow::bail!(
                    "sshd exited {status}: {}",
                    std::fs::read_to_string(fixture.directory.path().join("sshd.log"))?
                );
            }
            ensure!(
                Instant::now() < deadline,
                "OpenSSH fixture failed to listen"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(fixture)
    }
    fn spec(&self) -> ConnectionSpec {
        ConnectionSpec {
            host_id: json!(1),
            label: "OpenSSH fixture".into(),
            target: self.endpoint.clone(),
            jumps: vec![],
        }
    }
    fn remote(&self, name: &str) -> String {
        self.directory
            .path()
            .join(name)
            .to_string_lossy()
            .into_owned()
    }
}
fn token() -> CancellationToken {
    CancellationToken::new()
}

fn file_sha256(path: &str) -> Result<[u8; 32]> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(digest.finalize().into())
}

#[tokio::test]
#[ignore = "requires sshd and ssh-keygen; uses only a disposable localhost server"]
async fn openssh_get_put_stream_files_larger_than_fifty_mib() -> Result<()> {
    let fixture = Fixture::start()?;
    let spec = fixture.spec();
    let source = fixture.remote("large-source.bin");
    let uploaded = fixture.remote("large-uploaded.bin");
    let downloaded = fixture.remote("large-downloaded.bin");
    let size = 50 * 1024 * 1024 + 32 * 1024 + 123u64;

    // Sparse generation and streaming digests keep test memory independent of
    // file size. Distinct markers check data before and beyond the old limit.
    let mut file = std::fs::File::create(&source)?;
    file.set_len(size)?;
    for (offset, marker) in [
        (0, b"start of transfer".as_slice()),
        (
            50 * 1024 * 1024 - 8,
            b"crossing the former limit".as_slice(),
        ),
        (size - 64, b"end of transfer".as_slice()),
    ] {
        file.seek(SeekFrom::Start(offset))?;
        file.write_all(marker)?;
    }
    drop(file);
    let expected_hash = file_sha256(&source)?;

    let result = run_files(
        &spec,
        &json!({
            "action":"put", "path":uploaded, "local_path":source, "timeout":120
        }),
        token(),
    )
    .await?;
    assert_eq!(result["size"], size);
    assert_eq!(std::fs::metadata(&uploaded)?.len(), size);
    assert_eq!(file_sha256(&uploaded)?, expected_hash);

    std::fs::write(&downloaded, "replace only after a complete transfer")?;
    let result = run_files(
        &spec,
        &json!({
            "action":"get", "path":uploaded, "local_path":downloaded, "timeout":120
        }),
        token(),
    )
    .await?;
    assert_eq!(result["size"], size);
    assert_eq!(std::fs::metadata(&downloaded)?.len(), size);
    assert_eq!(file_sha256(&downloaded)?, expected_hash);
    Ok(())
}

#[tokio::test]
#[ignore = "requires sshd and ssh-keygen; uses only a disposable localhost server"]
async fn openssh_exec_and_all_sftp_actions() -> Result<()> {
    let fixture = Fixture::start()?;
    let spec = fixture.spec();
    let result = run_exec(
        &spec,
        &json!({"command":"printf hello; printf warning >&2; exit 7", "timeout":10}),
        token(),
    )
    .await?;
    assert_eq!(result["stdout"], "hello");
    assert_eq!(result["stderr"], "warning");
    assert_eq!(result["exit_code"], 7);
    assert_eq!(result["timed_out"], false);
    assert_eq!(
        result["host_key_verification"],
        json!({"target":"strict","jumps":[]})
    );
    let base = fixture.remote("files");
    run_files(
        &spec,
        &json!({"action":"mkdir", "path":base, "recursive":true}),
        token(),
    )
    .await?;
    let first = format!("{base}/first.bin");
    run_files(
        &spec,
        &json!({"action":"write", "path":first, "content":"AAECAw==", "encoding":"base64"}),
        token(),
    )
    .await?;
    let read = run_files(&spec, &json!({"action":"read", "path":first}), token()).await?;
    assert_eq!(read["content"], "AAECAw==");
    assert_eq!(read["encoding"], "base64");
    let stat = run_files(&spec, &json!({"action":"stat", "path":first}), token()).await?;
    assert_eq!(stat["size"], 4);
    let list = run_files(&spec, &json!({"action":"list", "path":base}), token()).await?;
    assert_eq!(list["count"], 1);
    assert_eq!(list["entries"][0]["name"], "first.bin");
    let download = fixture.remote("download.bin");
    std::fs::write(&download, "previous file")?;
    run_files(
        &spec,
        &json!({"action":"get", "path":first,"local_path":download}),
        token(),
    )
    .await?;
    assert_eq!(std::fs::read(&download)?, [0, 1, 2, 3]);
    let uploaded = format!("{base}/uploaded.bin");
    run_files(
        &spec,
        &json!({"action":"put","path":uploaded,"local_path":download}),
        token(),
    )
    .await?;
    assert_eq!(std::fs::read(&uploaded)?, [0, 1, 2, 3]);
    let renamed = format!("{base}/renamed.bin");
    run_files(
        &spec,
        &json!({"action":"rename","path":uploaded,"dest":renamed}),
        token(),
    )
    .await?;
    assert!(!std::path::Path::new(&uploaded).exists());
    run_files(&spec, &json!({"action":"rm","path":first}), token()).await?;
    run_files(
        &spec,
        &json!({"action":"rm","path":base,"recursive":true}),
        token(),
    )
    .await?;
    assert!(!std::path::Path::new(&base).exists());

    // Exercise tool dispatch as well as the SFTP transport against this server.
    // The state deliberately contains diagnostics for unrelated unreadable hosts.
    let paged = fixture.remote("paged");
    std::fs::create_dir(&paged)?;
    std::fs::write(format!("{paged}/B.txt"), "second file")?;
    std::fs::write(format!("{paged}/a.txt"), "first file")?;
    std::fs::create_dir(format!("{paged}/z-dir"))?;
    let mut store = Store::open_with(
        fixture.directory.path().join("runtime-state"),
        Some("test-only-state-passphrase"),
        Some("0"),
    )?;
    store.state.session =
        Some(json!({"username":"fixture@example.invalid","apikey":"fixture-device-token"}));
    store.state.vault_password = Some("fixture-vault-password".into());
    store.state.last_synced = Some(OffsetDateTime::now_utc().format(&Rfc3339)?);
    store.state.inventory = json!({
        "host_set":[
            {"id":1,"label":"fixture","address":spec.target.address,"ssh_config":10},
            {"id":2,"_undecryptable":true},
            {"id":3,"_undecryptable":true}
        ],
        "sshconfig_set":[{"id":10,"identity":100,"port":spec.target.port,"strict_host_key_check":true}],
        "identity_set":[{"id":100,"username":spec.target.username,"ssh_key":300}],
        "sshkeycrypt_set":[{"id":300,"label":"fixture-key","private_key":spec.target.private_key}],
        "knownhost_set":[{"id":400,"hostnames":format!("[{}]:{}",spec.target.address,spec.target.port),"key":spec.target.known_host_keys[0]}],
        "unreadable_entities":2,
        "sync_warnings":["Team vault keys could not be loaded; entities requiring those keys remain unavailable"]
    });
    store.save()?;
    let runtime = Runtime::new(store);
    let full = runtime
        .call(
            "files",
            json!({"name":"1","action":"list","path":paged}),
            token(),
        )
        .await?;
    assert_eq!(full["count"], 3);
    assert_eq!(full["entries"][0]["name"], "z-dir");
    assert_eq!(full["entries"][1]["name"], "a.txt");
    assert_eq!(full["entries"][2]["name"], "B.txt");
    for field in ["total", "offset", "next_offset"] {
        assert!(full.get(field).is_none());
    }
    let first_page = runtime
        .call(
            "files",
            json!({"name":"1","action":"list","path":paged,"limit":2,"offset":0}),
            token(),
        )
        .await?;
    assert_eq!(first_page["count"], 2);
    assert_eq!(first_page["total"], 3);
    assert_eq!(first_page["offset"], 0);
    assert_eq!(first_page["next_offset"], 2);
    assert_eq!(first_page["entries"][0], full["entries"][0]);
    assert_eq!(first_page["entries"][1], full["entries"][1]);
    let last_page = runtime
        .call(
            "files",
            json!({"name":"1","action":"list","path":paged,"limit":2,"offset":2}),
            token(),
        )
        .await?;
    assert_eq!(last_page["count"], 1);
    assert_eq!(last_page["total"], 3);
    assert_eq!(last_page["offset"], 2);
    assert_eq!(last_page["next_offset"], json!(null));
    assert_eq!(last_page["entries"][0], full["entries"][2]);
    let executed = runtime
        .call(
            "exec",
            json!({"name":"1","command":"printf runtime-ok","max_output_chars":16}),
            token(),
        )
        .await?;
    assert_eq!(executed["stdout"], "runtime-ok");
    assert_eq!(executed["exit_code"], 0);
    for result in [&full, &first_page, &last_page, &executed] {
        assert_eq!(result["ok"], true);
        assert!(result.get("sync_warnings").is_none());
        assert!(result.get("unreadable_entities").is_none());
    }

    // The SSH subsystem follows a real direct-tcpip jump into another SSH session.
    let mut jumped = fixture.spec();
    jumped.jumps.push(fixture.endpoint.clone());
    let result = run_exec(
        &jumped,
        &json!({"command":"printf jump-ok", "timeout":10}),
        token(),
    )
    .await?;
    assert_eq!(result["stdout"], "jump-ok");
    assert_eq!(
        result["host_key_verification"],
        json!({"target":"strict","jumps":["strict"]})
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires sshd and ssh-keygen; uses only a disposable localhost server"]
async fn openssh_honors_each_endpoints_host_key_verification_setting() -> Result<()> {
    let fixture = Fixture::start()?;
    let stale_key = std::fs::read_to_string(fixture.directory.path().join("client_key.pub"))?;
    let mut direct = fixture.spec();
    direct.target.known_host_keys = vec![stale_key.clone()];
    assert!(
        run_exec(&direct, &json!({"command":"true"}), token())
            .await
            .is_err()
    );

    direct.target.strict_host_key_check = false;
    let result = run_exec(&direct, &json!({"command":"printf direct-ok"}), token()).await?;
    assert_eq!(result["stdout"], "direct-ok");
    assert!(result.get("host_key_verification").is_none());
    let result = run_files(
        &direct,
        &json!({"action":"stat","path":fixture.remote("client_key.pub")}),
        token(),
    )
    .await?;
    assert_eq!(result["ok"], true);
    assert!(result.get("host_key_verification").is_none());

    let mut hop = fixture.endpoint.clone();
    hop.strict_host_key_check = false;
    hop.known_host_keys.clear();
    let mut jumped = direct;
    jumped.jumps.push(hop);
    let result = run_exec(&jumped, &json!({"command":"printf jump-ok"}), token()).await?;
    assert_eq!(result["stdout"], "jump-ok");
    assert!(result.get("host_key_verification").is_none());
    let result = run_files(
        &jumped,
        &json!({"action":"stat","path":fixture.remote("client_key.pub")}),
        token(),
    )
    .await?;
    assert_eq!(result["ok"], true);
    assert!(result.get("host_key_verification").is_none());

    // Strict verification remains effective at either position in a route.
    jumped.target.strict_host_key_check = true;
    assert!(
        run_exec(&jumped, &json!({"command":"true"}), token())
            .await
            .is_err()
    );
    jumped.target.known_host_keys = fixture.endpoint.known_host_keys.clone();
    let result = run_files(
        &jumped,
        &json!({"action":"stat","path":fixture.remote("client_key.pub")}),
        token(),
    )
    .await?;
    assert_eq!(
        result["host_key_verification"],
        json!({"target":"strict","jumps":["disabled"]})
    );

    jumped.jumps[0].strict_host_key_check = true;
    jumped.jumps[0].known_host_keys = vec![stale_key];
    assert!(
        run_exec(&jumped, &json!({"command":"true"}), token())
            .await
            .is_err()
    );

    jumped.jumps[0].known_host_keys = fixture.endpoint.known_host_keys.clone();
    jumped.target.strict_host_key_check = false;
    let result = run_exec(
        &jumped,
        &json!({"command":"printf strict-jump-ok"}),
        token(),
    )
    .await?;
    assert_eq!(result["stdout"], "strict-jump-ok");
    assert_eq!(
        result["host_key_verification"],
        json!({"target":"disabled","jumps":["strict"]})
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires sshd and ssh-keygen; uses only a disposable localhost server"]
async fn openssh_limits_timeout_cancellation_and_symlinks() -> Result<()> {
    let fixture = Fixture::start()?;
    let spec = fixture.spec();
    let result = run_exec(
        &spec,
        &json!({"command":"printf before; sleep 5", "timeout":1}),
        token(),
    )
    .await?;
    assert_eq!(result["timed_out"], true);
    assert_eq!(result["exit_code"], json!(null));
    assert_eq!(result["stdout"], "before");
    let cancellation = token();
    let trigger = cancellation.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        trigger.cancel();
    });
    let start = Instant::now();
    assert!(
        run_exec(
            &spec,
            &json!({"command":"sleep 30", "timeout":10}),
            cancellation
        )
        .await
        .is_err()
    );
    assert!(start.elapsed() < Duration::from_secs(2));
    let result = run_exec(&spec, &json!({"command":"head -c 1000000 /dev/zero; head -c 1000000 /dev/zero >&2", "timeout":10}), token()).await?;
    assert_eq!(result["truncated"], true);
    assert!(result["stdout"].as_str().unwrap().len() < 201000);
    assert!(result["stderr"].as_str().unwrap().len() < 201000);
    assert_eq!(result["exit_code"], 0);
    assert_eq!(result["timed_out"], false);
    // Each stream exceeds the SSH receive window. Stopping reads at the
    // output budget would block the remote writer before it can exit 23.
    for max_output_chars in [16, 0] {
        let result = run_exec(
            &spec,
            &json!({
                "command":"head -c 8388608 /dev/zero; head -c 8388608 /dev/zero >&2; exit 23",
                "timeout":15,
                "max_output_chars":max_output_chars
            }),
            token(),
        )
        .await?;
        assert_eq!(result["exit_code"], 23);
        assert_eq!(result["timed_out"], false);
        assert_eq!(result["truncated"], true);
        for stream in ["stdout", "stderr"] {
            assert_eq!(
                result[stream],
                format!(
                    "{}\n...[{stream} truncated]...",
                    "\0".repeat(max_output_chars)
                )
            );
        }
    }
    let mut wrong = fixture.spec();
    wrong.target.known_host_keys = vec![std::fs::read_to_string(
        fixture.directory.path().join("client_key.pub"),
    )?];
    assert!(
        run_exec(&wrong, &json!({"command":"true"}), token())
            .await
            .is_err()
    );
    let existing = fixture.remote("preserved.bin");
    std::fs::write(&existing, "keep me")?;
    assert!(
        run_files(
            &spec,
            &json!({"action":"get","path":fixture.remote("absent"),"local_path":existing}),
            token()
        )
        .await
        .is_err()
    );
    assert_eq!(std::fs::read_to_string(&existing)?, "keep me");
    let oversized = fixture.remote("large.bin");
    std::fs::File::create(&oversized)?.set_len(200001)?;
    assert!(
        run_files(&spec, &json!({"action":"read","path":oversized}), token())
            .await
            .is_err()
    );
    let protected = fixture.remote("protected");
    std::fs::create_dir(&protected)?;
    std::fs::write(format!("{protected}/important"), "preserve")?;
    let link = fixture.remote("link");
    std::os::unix::fs::symlink(&protected, &link)?;
    run_files(
        &spec,
        &json!({"action":"rm","path":link,"recursive":true}),
        token(),
    )
    .await?;
    assert!(!std::path::Path::new(&link).exists());
    assert_eq!(
        std::fs::read_to_string(format!("{protected}/important"))?,
        "preserve"
    );
    Ok(())
}
