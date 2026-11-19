//! Independent Python-CLI compatibility checks through the published binaries.
//! All credentials are synthetic and no cloud login is attempted.
use anyhow::{Context, Result};
use serde_json::json;
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use termius_mcp::storage::Store;

const STORAGE_KEY: &str = "test-only-cli-review-storage-key";

fn binaries() -> [(&'static str, &'static str); 2] {
    [
        ("termius", env!("CARGO_BIN_EXE_termius")),
        ("termius-mcp", env!("CARGO_BIN_EXE_termius-mcp")),
    ]
}

struct Invocation {
    code: Option<i32>,
    stdout: String,
    stderr: String,
}

fn invoke(binary: &str, data: &Path, arguments: &[&str], input: &str) -> Result<Invocation> {
    let mut child = Command::new(binary)
        .args(arguments)
        .env("TERMIUS_DATA_DIR", data)
        .env("TERMIUS_SECRETS_KEY", STORAGE_KEY)
        .env("TERMIUS_KEYRING", "0")
        .env("TERMIUS_SYNC_TTL", "60")
        .env_remove("TERMIUS_VAULT_PASSWORD")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start local CLI under review")?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(input.as_bytes())?;
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while child.try_wait()?.is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("offline CLI case did not terminate within 30 seconds");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let output = child.wait_with_output()?;
    Ok(Invocation {
        code: output.status.code(),
        stdout: String::from_utf8(output.stdout)?,
        stderr: String::from_utf8(output.stderr)?,
    })
}

fn seed(data: &Path, fresh: bool) -> Result<()> {
    let mut store = Store::open_with(data.to_path_buf(), Some(STORAGE_KEY), Some("0"))?;
    store.state.session =
        Some(json!({"username":"fixture@example.invalid","apikey":"fixture-token"}));
    store.state.vault_password = Some("fixture-vault-password".into());
    store.state.pending_sso = Some(json!({"request_id":"fixture-request"}));
    store.state.last_synced = Some(if fresh {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            .to_string()
    } else {
        "0".into()
    });
    store.state.inventory = json!({
        "host_set":[
            {"id":1,"label":"fixture-one","address":"192.0.2.1"},
            {"id":2,"label":"fixture-two","address":"192.0.2.2"}
        ]
    });
    store.save()
}

#[test]
fn only_the_two_original_binary_names_are_exposed() {
    let _ = binaries();
    assert!(
        option_env!("CARGO_BIN_EXE_termius-mcp-rs").is_none(),
        "the user explicitly removed the extra Rust-named entry point"
    );
}

#[test]
fn both_original_entry_points_print_plain_signed_out_status() -> Result<()> {
    for (name, binary) in binaries() {
        let directory = tempfile::tempdir()?;
        let result = invoke(
            binary,
            directory.path().join("state").as_path(),
            &["status"],
            "",
        )?;
        assert_eq!(result.code, Some(0), "{name}: {}", result.stderr);
        assert_eq!(result.stdout, "Not signed in.\n", "{name}");
        assert!(result.stderr.is_empty(), "{name}: {}", result.stderr);
    }
    Ok(())
}

#[test]
fn status_uses_the_original_summary_without_cloud_access() -> Result<()> {
    for (name, binary) in binaries() {
        for (fresh, expected) in [(true, "fresh"), (false, "stale")] {
            let directory = tempfile::tempdir()?;
            let data = directory.path().join("state");
            seed(&data, fresh)?;
            let result = invoke(binary, &data, &["status"], "")?;
            assert_eq!(result.code, Some(0), "{name}: {}", result.stderr);
            assert_eq!(
                result.stdout,
                format!("Signed in as fixture@example.invalid, 2 hosts, cache {expected}.\n"),
                "{name}"
            );
            assert!(result.stderr.is_empty(), "{name}: {}", result.stderr);
        }
    }
    Ok(())
}

#[test]
fn logout_prints_original_message_and_clears_saved_state() -> Result<()> {
    for (name, binary) in binaries() {
        let directory = tempfile::tempdir()?;
        let data = directory.path().join("state");
        seed(&data, true)?;
        let result = invoke(binary, &data, &["logout"], "")?;
        assert_eq!(result.code, Some(0), "{name}: {}", result.stderr);
        assert_eq!(result.stdout, "Signed out.\n", "{name}");
        assert!(result.stderr.is_empty(), "{name}: {}", result.stderr);
        let store = Store::open_with(data, Some(STORAGE_KEY), Some("0"))?;
        assert!(store.state.session.is_none());
        assert!(store.state.vault_password.is_none());
        assert!(store.state.pending_sso.is_none());
        assert!(store.state.last_synced.is_none());
        assert_eq!(
            termius_mcp::inventory::counts(&store.state.inventory)["hosts"],
            0
        );
    }
    Ok(())
}

#[test]
fn no_arguments_still_serve_mcp_without_cli_text_on_stdout() -> Result<()> {
    for (name, binary) in binaries() {
        let directory = tempfile::tempdir()?;
        let input = "{\"jsonrpc\":\"2.0\",\"id\":17,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\"}}\n";
        let result = invoke(binary, directory.path().join("state").as_path(), &[], input)?;
        assert_eq!(result.code, Some(0), "{name}: {}", result.stderr);
        let messages = result
            .stdout
            .lines()
            .map(serde_json::from_str::<serde_json::Value>)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        assert_eq!(messages.len(), 1, "{name}: {}", result.stdout);
        assert_eq!(messages[0]["id"], 17);
        assert_eq!(messages[0]["result"]["protocolVersion"], "2025-11-25");
        assert!(result.stderr.is_empty(), "{name}: {}", result.stderr);
    }
    Ok(())
}

#[test]
fn help_and_rejected_arguments_preserve_the_original_command_surface() -> Result<()> {
    for (name, binary) in binaries() {
        let directory = tempfile::tempdir()?;
        let data = directory.path().join("state");
        let help = invoke(binary, &data, &["login", "--help"], "")?;
        assert_eq!(help.code, Some(0), "{name}: {}", help.stderr);
        for expected in ["google", "email", "--username", "--otp", "--no-remember"] {
            assert!(help.stdout.contains(expected), "{name}: missing {expected}");
        }
        for arguments in [
            vec!["sync"],
            vec!["login", "unsupported-method"],
            vec!["login", "email", "--password", "fixture-secret"],
        ] {
            let result = invoke(binary, &data, &arguments, "")?;
            assert_eq!(
                result.code,
                Some(2),
                "{name} {arguments:?}: {}",
                result.stderr
            );
            assert!(result.stdout.is_empty(), "{name} {arguments:?}");
            assert!(!result.stderr.is_empty(), "{name} {arguments:?}");
        }
    }
    Ok(())
}

#[test]
fn missing_noninteractive_login_input_matches_source_validation() -> Result<()> {
    for (name, binary) in binaries() {
        let directory = tempfile::tempdir()?;
        let data = directory.path().join("state");
        for (arguments, message) in [
            (vec!["login"], "specify google or email\n"),
            (
                vec!["login", "email"],
                "username is required for email login (use -u)\n",
            ),
            (
                vec!["login", "email", "-u", "   "],
                "username is required for email login (use -u)\n",
            ),
        ] {
            let result = invoke(binary, &data, &arguments, "")?;
            assert_eq!(result.code, Some(1), "{name} {arguments:?}");
            assert!(result.stdout.is_empty(), "{name} {arguments:?}");
            assert_eq!(result.stderr, message, "{name} {arguments:?}");
        }
    }
    Ok(())
}

#[test]
fn google_uses_the_source_callback_prompt_with_piped_input() -> Result<()> {
    for (name, binary) in binaries() {
        let directory = tempfile::tempdir()?;
        let data = directory.path().join("state");
        // Empty callback input fails before password collection or cloud access.
        let result = invoke(binary, &data, &["login", "google"], "\n")?;
        assert_eq!(result.code, Some(1), "{name}");
        assert_eq!(result.stdout, "Paste callback URL: ", "{name}");
        assert!(
            result.stderr.contains("Open this URL in a browser:"),
            "{name}"
        );
        assert!(
            result.stderr.contains("https://account.termius.com/"),
            "{name}"
        );
        assert!(
            result.stderr.ends_with("callback URL is required\n"),
            "{name}"
        );
    }
    Ok(())
}
