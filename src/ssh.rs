//! Native SSH/SFTP transport. Every operation owns one cancellable TCP route.
//!
//! Dropping a future aborts the transport pump, so cancellation also terminates
//! a handshake, authentication attempt, SFTP request, or a multi-hop route.
use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hmac::{Hmac, Mac};
use russh::{
    ChannelMsg, client,
    keys::{self, PrivateKeyWithHashAlg, PublicKey, PublicKeyOrCertificate},
};
use russh_sftp::{
    client::{RawSftpSession, error::Error as SftpError},
    protocol::{FileAttributes, OpenFlags, StatusCode},
};
use serde_json::{Value, json};
use sha1::Sha1;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{ConnectionSpec, Endpoint};

const MAX_OUTPUT: usize = 200_000;
const MAX_CAPTURE_BYTES: usize = MAX_OUTPUT * 4;
// Inline content crosses the MCP message boundary. File get/put instead stream
// fixed-size chunks and have no application-imposed total byte limit.
const MAX_CONTENT: usize = 200_000;
const CHUNK: usize = 32 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 10_000;
const MAX_REMOVE_ENTRIES: usize = 100_000;
const MAX_PATH: usize = 32 * 1024;

fn timeout_seconds(args: &Value) -> Result<u64> {
    let timeout = match args.get("timeout") {
        None | Some(Value::Null) => 60,
        Some(value) => value
            .as_u64()
            .context("timeout must be a positive integer")?,
    };
    ensure!(
        (1..=86400).contains(&timeout),
        "timeout must be between 1 and 86400 seconds"
    );
    Ok(timeout)
}

/// A small bounded capture continues draining after the output limit is hit.
#[derive(Default)]
struct Capture {
    bytes: Vec<u8>,
    dropped: bool,
}
impl Capture {
    fn add(&mut self, bytes: &[u8]) {
        let take = bytes
            .len()
            .min(MAX_CAPTURE_BYTES.saturating_sub(self.bytes.len()));
        self.bytes.extend_from_slice(&bytes[..take]);
        self.dropped |= take < bytes.len();
    }
    fn finish(self, label: &str) -> (String, bool) {
        let text = String::from_utf8_lossy(&self.bytes);
        let mut chars = text.chars();
        let mut output: String = chars.by_ref().take(MAX_OUTPUT).collect();
        let truncated = self.dropped || chars.next().is_some();
        if truncated {
            output.push_str(&format!("\n...[{label} truncated]..."));
        }
        (output, truncated)
    }
}

struct HostVerifier {
    endpoint: Endpoint,
    known_hosts: Vec<String>,
}
impl HostVerifier {
    async fn new(endpoint: &Endpoint) -> Result<Self> {
        let mut known_hosts = Vec::new();
        if endpoint.strict_host_key_check && endpoint.known_host_keys.is_empty() {
            let mut paths = vec![PathBuf::from("/etc/ssh/ssh_known_hosts")];
            if let Some(home) = dirs::home_dir() {
                paths.push(home.join(".ssh/known_hosts"));
            }
            for path in paths {
                match tokio::fs::File::open(&path).await {
                    Ok(file) => {
                        let mut bytes = Vec::new();
                        file.take(4 * 1024 * 1024 + 1)
                            .read_to_end(&mut bytes)
                            .await
                            .map_err(|_| anyhow!("Could not read SSH known_hosts"))?;
                        ensure!(
                            bytes.len() <= 4 * 1024 * 1024,
                            "SSH known_hosts exceeds 4 MiB"
                        );
                        known_hosts.push(
                            String::from_utf8(bytes).context("SSH known_hosts is not UTF-8")?,
                        );
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(_) => bail!("Could not read SSH known_hosts"),
                }
            }
        }
        Ok(Self {
            endpoint: endpoint.clone(),
            known_hosts,
        })
    }

    fn verify(&self, received: &PublicKeyOrCertificate) -> Result<bool> {
        if !self.endpoint.strict_host_key_check {
            return Ok(true);
        }
        ensure!(
            received.certificate().is_none(),
            "SSH host certificates are not supported; enroll the server's plain host key"
        );
        let key = received.public_key();
        if !self.endpoint.known_host_keys.is_empty() {
            let mut matching = false;
            for encoded in &self.endpoint.known_host_keys {
                let trusted = PublicKey::from_openssh(encoded)
                    .map_err(|_| anyhow!("An enrolled Termius SSH host key is invalid"))?;
                matching |= trusted.key_data() == key.key_data();
            }
            ensure!(
                matching,
                "SSH host key does not match the enrolled Termius keys"
            );
            return Ok(true);
        }
        let host = if self.endpoint.port == 22 {
            self.endpoint.address.clone()
        } else {
            format!("[{}]:{}", self.endpoint.address, self.endpoint.port)
        };
        let mut matching = false;
        for contents in &self.known_hosts {
            matching |= verify_known_hosts(contents, &host, &key)?;
        }
        ensure!(
            matching,
            "SSH host key is not trusted. Enroll it in Termius or verify and add it to ~/.ssh/known_hosts"
        );
        Ok(true)
    }
}
impl client::Handler for HostVerifier {
    type Error = anyhow::Error;
    async fn check_server_key(&mut self, key: &PublicKeyOrCertificate) -> Result<bool> {
        self.verify(key)
    }
}

fn verify_known_hosts(contents: &str, host: &str, key: &PublicKey) -> Result<bool> {
    use keys::ssh_key::known_hosts::{HostPatterns, Marker};
    let mut matching = false;
    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // The upstream parser expects one space; OpenSSH also accepts tabs.
        let normalized = line.split_whitespace().collect::<Vec<_>>().join(" ");
        let entry: keys::ssh_key::known_hosts::Entry = normalized
            .parse()
            .map_err(|_| anyhow!("Invalid entry in SSH known_hosts"))?;
        let selected = match entry.host_patterns() {
            HostPatterns::HashedName { salt, hash } => {
                let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(salt)
                    .map_err(|_| anyhow!("Invalid hashed hostname in known_hosts"))?;
                mac.update(host.as_bytes());
                mac.verify_slice(hash).is_ok()
            }
            HostPatterns::Patterns(patterns) => {
                let mut positive = false;
                let mut excluded = false;
                for pattern in patterns {
                    if let Some(negative) = pattern.strip_prefix('!') {
                        excluded |= wildcard(negative.as_bytes(), host.as_bytes());
                    } else {
                        positive |= wildcard(pattern.as_bytes(), host.as_bytes());
                    }
                }
                positive && !excluded
            }
        };
        if !selected {
            continue;
        }
        let same = entry.public_key().key_data() == key.key_data();
        if entry.marker() == Some(&Marker::Revoked) && same {
            bail!("SSH host key is revoked in known_hosts");
        }
        if entry.marker().is_none() && same {
            matching = true;
        }
    }
    Ok(matching)
}

fn wildcard(pattern: &[u8], text: &[u8]) -> bool {
    let (mut p, mut t, mut star, mut retry) = (0, 0, None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p].eq_ignore_ascii_case(&text[t])) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            retry = t;
        } else if let Some(s) = star {
            retry += 1;
            t = retry;
            p = s + 1;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

/// Aborting this one pump closes the original socket and every tunneled session.
struct TransportPump(tokio::task::JoinHandle<()>);
impl Drop for TransportPump {
    fn drop(&mut self) {
        self.0.abort();
    }
}
struct Route {
    handles: Vec<client::Handle<HostVerifier>>,
    _pump: TransportPump,
}
impl Route {
    fn target(&self) -> &client::Handle<HostVerifier> {
        self.handles.last().expect("connected route")
    }
}

async fn connect_route(spec: &ConnectionSpec) -> Result<Route> {
    ensure!(spec.jumps.len() <= 32, "SSH route exceeds 32 jump hosts");
    let endpoints: Vec<&Endpoint> = spec
        .jumps
        .iter()
        .chain(std::iter::once(&spec.target))
        .collect();
    for endpoint in &endpoints {
        ensure!(
            !endpoint.address.is_empty()
                && endpoint.address.len() <= 1024
                && !endpoint.address.contains(['\0', '\r', '\n']),
            "Invalid SSH address"
        );
        ensure!(endpoint.port != 0, "Invalid SSH port");
        ensure!(
            endpoint
                .username
                .as_deref()
                .is_some_and(|u| !u.is_empty() && !u.contains('\0')),
            "Host has no valid SSH username"
        );
    }
    let first = endpoints[0];
    let stream = tokio::time::timeout(
        Duration::from_secs(first.connect_timeout.max(1)),
        TcpStream::connect((first.address.as_str(), first.port)),
    )
    .await
    .map_err(|_| anyhow!("SSH TCP connection timed out"))?
    .map_err(|_| anyhow!("Could not establish SSH TCP connection"))?;
    stream
        .set_nodelay(true)
        .map_err(|_| anyhow!("Could not configure SSH TCP connection"))?;
    let (client_stream, mut pump_stream) = tokio::io::duplex(64 * 1024);
    let pump = TransportPump(tokio::spawn(async move {
        let mut stream = stream;
        let _ = tokio::io::copy_bidirectional(&mut stream, &mut pump_stream).await;
    }));
    let mut route = Route {
        handles: Vec::new(),
        _pump: pump,
    };
    let verifier = HostVerifier::new(first).await?;
    let first_config = config(first);
    let handle = tokio::time::timeout(
        Duration::from_secs(first.connect_timeout.max(1)),
        client::connect_stream(first_config, client_stream, verifier),
    )
    .await
    .map_err(|_| anyhow!("SSH handshake timed out"))??;
    route.handles.push(handle);
    authenticate(
        route.handles.last_mut().expect("first handle"),
        first,
        spec.jumps.is_empty(),
    )
    .await?;
    for endpoint in endpoints.into_iter().skip(1) {
        let channel = route
            .target()
            .channel_open_direct_tcpip(
                endpoint.address.as_str(),
                u32::from(endpoint.port),
                "127.0.0.1",
                0,
            )
            .await
            .map_err(|_| anyhow!("SSH server refused a jump-host forwarding channel"))?;
        let verifier = HostVerifier::new(endpoint).await?;
        let handle = tokio::time::timeout(
            Duration::from_secs(endpoint.connect_timeout.max(1)),
            client::connect_stream(config(endpoint), channel.into_stream(), verifier),
        )
        .await
        .map_err(|_| anyhow!("SSH jump-host handshake timed out"))??;
        route.handles.push(handle);
        authenticate(
            route.handles.last_mut().expect("next handle"),
            endpoint,
            false,
        )
        .await?;
    }
    Ok(route)
}

fn config(endpoint: &Endpoint) -> Arc<client::Config> {
    Arc::new(client::Config {
        keepalive_interval: (endpoint.keep_alive > 0)
            .then(|| Duration::from_secs(u64::from(endpoint.keep_alive))),
        channel_buffer_size: 16,
        maximum_packet_size: CHUNK as u32,
        nodelay: true,
        ..Default::default()
    })
}

async fn authenticate(
    handle: &mut client::Handle<HostVerifier>,
    endpoint: &Endpoint,
    allow_local: bool,
) -> Result<()> {
    let username = endpoint
        .username
        .as_deref()
        .context("Host has no SSH username")?;
    if let Some(encoded) = endpoint.private_key.as_deref().filter(|s| !s.is_empty()) {
        let key = keys::decode_secret_key(
            encoded,
            endpoint.passphrase.as_deref().filter(|s| !s.is_empty()),
        )
        .map_err(|_| anyhow!("Could not parse or unlock the SSH private key"))?;
        let hash = handle
            .best_supported_rsa_hash()
            .await
            .map_err(|_| anyhow!("SSH key negotiation failed"))?
            .flatten();
        if handle
            .authenticate_publickey(username, PrivateKeyWithHashAlg::new(Arc::new(key), hash))
            .await
            .map_err(|_| anyhow!("SSH public-key authentication failed"))?
            .success()
        {
            return Ok(());
        }
    }
    if let Some(password) = endpoint.password.as_deref().filter(|s| !s.is_empty()) {
        if handle
            .authenticate_password(username, password)
            .await
            .map_err(|_| anyhow!("SSH password authentication failed"))?
            .success()
        {
            return Ok(());
        }
        // Match Paramiko's password-to-keyboard-interactive fallback, but never
        // send a password to a prompt requesting echoed text or multiple factors.
        let mut response = handle
            .authenticate_keyboard_interactive_start(username, None)
            .await
            .map_err(|_| anyhow!("SSH keyboard-interactive authentication failed"))?;
        for _ in 0..3 {
            match &response {
                client::KeyboardInteractiveAuthResponse::Success => return Ok(()),
                client::KeyboardInteractiveAuthResponse::InfoRequest { prompts, .. }
                    if prompts.len() == 1 && !prompts[0].echo =>
                {
                    response = handle
                        .authenticate_keyboard_interactive_respond(vec![password.to_owned()])
                        .await
                        .map_err(|_| anyhow!("SSH keyboard-interactive authentication failed"))?;
                }
                _ => break,
            }
        }
        if matches!(response, client::KeyboardInteractiveAuthResponse::Success) {
            return Ok(());
        }
    }
    let explicit = endpoint
        .private_key
        .as_deref()
        .is_some_and(|s| !s.is_empty())
        || endpoint.password.as_deref().is_some_and(|s| !s.is_empty());
    if allow_local && !explicit {
        #[cfg(unix)]
        if let Ok(mut agent) = keys::agent::client::AgentClient::connect_env().await
            && authenticate_agent(handle, username, &mut agent)
                .await
                .unwrap_or(false)
        {
            return Ok(());
        }
        #[cfg(windows)]
        #[allow(clippy::collapsible_if)]
        if let Ok(mut agent) =
            keys::agent::client::AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent")
                .await
        {
            if authenticate_agent(handle, username, &mut agent)
                .await
                .unwrap_or(false)
            {
                return Ok(());
            }
        }
        if let Some(home) = dirs::home_dir() {
            for filename in ["id_ed25519", "id_ecdsa", "id_rsa"] {
                let path = home.join(".ssh").join(filename);
                let Ok(file) = tokio::fs::File::open(path).await else {
                    continue;
                };
                let mut contents = Vec::new();
                if file
                    .take(1024 * 1024 + 1)
                    .read_to_end(&mut contents)
                    .await
                    .is_err()
                    || contents.len() > 1024 * 1024
                {
                    continue;
                }
                let Ok(encoded) = std::str::from_utf8(&contents) else {
                    continue;
                };
                let Ok(key) = keys::decode_secret_key(encoded, None) else {
                    continue;
                };
                let hash = handle
                    .best_supported_rsa_hash()
                    .await
                    .map_err(|_| anyhow!("SSH key negotiation failed"))?
                    .flatten();
                if handle
                    .authenticate_publickey(
                        username,
                        PrivateKeyWithHashAlg::new(Arc::new(key), hash),
                    )
                    .await
                    .map_err(|_| anyhow!("SSH local-key authentication failed"))?
                    .success()
                {
                    return Ok(());
                }
            }
        }
    }
    bail!("SSH authentication failed with the configured credentials")
}

async fn authenticate_agent<S: AsyncRead + AsyncWrite + Unpin + Send>(
    handle: &mut client::Handle<HostVerifier>,
    username: &str,
    agent: &mut keys::agent::client::AgentClient<S>,
) -> Result<bool> {
    if let Some(binding) = handle.agent_session_binding() {
        // Older agents do not implement the extension. Destination-constrained
        // agents will still refuse identities/signatures when binding fails.
        let _ = agent.bind_session(binding, false).await;
    }
    let identities = agent
        .request_identities()
        .await
        .map_err(|_| anyhow!("Could not list SSH agent identities"))?;
    for identity in identities.into_iter().take(32) {
        let hash = handle
            .best_supported_rsa_hash()
            .await
            .map_err(|_| anyhow!("SSH key negotiation failed"))?
            .flatten();
        let result = match identity {
            keys::agent::AgentIdentity::PublicKey { key, .. } => {
                handle
                    .authenticate_publickey_with(username, key, hash, agent)
                    .await
            }
            keys::agent::AgentIdentity::Certificate { certificate, .. } => {
                handle
                    .authenticate_certificate_with(username, certificate, hash, agent)
                    .await
            }
        };
        if result.is_ok_and(|r| r.success()) {
            return Ok(true);
        }
    }
    Ok(false)
}

fn host_key_verification(spec: &ConnectionSpec) -> Value {
    let mode = |endpoint: &Endpoint| {
        if endpoint.strict_host_key_check {
            "strict"
        } else {
            "disabled"
        }
    };
    json!({"target":mode(&spec.target),"jumps":spec.jumps.iter().map(mode).collect::<Vec<_>>()})
}

pub async fn run_exec(
    spec: &ConnectionSpec,
    args: &Value,
    cancel: CancellationToken,
) -> Result<Value> {
    let command = args
        .get("command")
        .and_then(Value::as_str)
        .context("command is required")?;
    ensure!(
        !command.trim().is_empty() && !command.contains('\0'),
        "command must be nonempty and cannot contain NUL"
    );
    ensure!(command.len() <= 1024 * 1024, "command exceeds 1 MiB");
    let timeout = timeout_seconds(args)?;
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let mut out = Capture::default();
    let mut err = Capture::default();
    let mut exit_code = None;
    let mut timed_out = false;
    let completed = {
        let operation = async {
            let route = connect_route(spec).await?;
            let mut channel = route
                .target()
                .channel_open_session()
                .await
                .map_err(|_| anyhow!("Could not open SSH command channel"))?;
            channel
                .exec(true, command)
                .await
                .map_err(|_| anyhow!("Could not send SSH command request"))?;
            channel
                .eof()
                .await
                .map_err(|_| anyhow!("Could not close SSH command input"))?;
            let mut grace = None;
            loop {
                let stop = grace.unwrap_or(deadline).min(deadline);
                let message = match tokio::time::timeout_at(stop, channel.wait()).await {
                    Ok(message) => message,
                    Err(_) if grace.is_some_and(|g| g <= Instant::now()) => break,
                    Err(_) => {
                        timed_out = true;
                        break;
                    }
                };
                match message {
                    Some(ChannelMsg::Data { data }) => out.add(&data),
                    Some(ChannelMsg::ExtendedData { data, ext: 1 }) => err.add(&data),
                    Some(ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = Some(exit_status);
                        grace = Some(Instant::now() + Duration::from_secs(2));
                    }
                    Some(ChannelMsg::Failure) => bail!("SSH server rejected the command request"),
                    Some(ChannelMsg::Close) | None => break,
                    _ => {}
                }
            }
            // Route Drop cuts off the underlying TCP transport. Waiting for a peer
            // to acknowledge channel close could otherwise exceed the deadline.
            drop(channel);
            drop(route);
            Ok::<_, anyhow::Error>(())
        };
        tokio::select! {
            biased;
            _ = cancel.cancelled() => bail!("SSH operation cancelled"),
            result = tokio::time::timeout_at(deadline, operation) => match result {
                Ok(result) => { result?; true },
                Err(_) => false,
            }
        }
    };
    if !completed {
        timed_out = true;
    }
    if timed_out {
        exit_code = None;
    }
    let (stdout, out_truncated) = out.finish("stdout");
    let (stderr, err_truncated) = err.finish("stderr");
    Ok(
        json!({"host":spec.label,"address":spec.target.address,"username":spec.target.username,
        "command":command,"exit_code":exit_code,"stdout":stdout,"stderr":stderr,
        "truncated":out_truncated || err_truncated,"timed_out":timed_out,"timeout":timeout,
        "host_key_verification":host_key_verification(spec)}),
    )
}

fn sf<T>(result: std::result::Result<T, SftpError>) -> Result<T> {
    result.map_err(|error| match error {
        SftpError::Status(status) => anyhow!("SFTP request failed: {}", status.status_code),
        SftpError::Timeout => anyhow!("SFTP request timed out"),
        _ => anyhow!("SFTP transport or protocol error"),
    })
}
fn is_eof(error: &SftpError) -> bool {
    matches!(error, SftpError::Status(s) if s.status_code == StatusCode::Eof)
}
fn is_missing(error: &SftpError) -> bool {
    matches!(error, SftpError::Status(s) if s.status_code == StatusCode::NoSuchFile)
}
fn validate_path(path: &str) -> Result<()> {
    ensure!(
        !path.is_empty() && path.len() <= MAX_PATH && !path.contains('\0'),
        "Path must be nonempty, contain no NUL, and be at most 32768 bytes"
    );
    Ok(())
}
fn remote_basename(path: &str) -> &str {
    path.trim_end_matches('/').rsplit('/').next().unwrap_or("")
}

/// A POSIX remote name must remain one filename on the local platform. Reject
/// Windows drive/stream syntax even on Unix so this boundary is portable.
fn local_download_name(name: &str) -> Result<&str> {
    use std::path::{Component, Path};

    let mut components = Path::new(name).components();
    let normal = matches!(components.next(), Some(Component::Normal(part)) if part == name);
    ensure!(
        normal && components.next().is_none() && !name.contains([':', '\\', '\0']),
        "Remote filename cannot be used as a local destination"
    );
    Ok(name)
}
fn remote_parent(path: &str) -> &str {
    path.trim_end_matches('/')
        .rsplit_once('/')
        .map(|(p, _)| if p.is_empty() { "/" } else { p })
        .unwrap_or(".")
}
fn remote_join(base: &str, child: &str) -> String {
    if base.ends_with('/') {
        format!("{base}{child}")
    } else {
        format!("{base}/{child}")
    }
}

async fn canonical(sftp: &RawSftpSession, path: &str) -> Result<String> {
    let response = sf(sftp.realpath(path).await)?;
    let first = response
        .files
        .first()
        .context("SFTP server returned no canonical path")?;
    validate_path(&first.filename)?;
    Ok(first.filename.clone())
}
async fn remote_path(sftp: &RawSftpSession, input: &str, preserve_leaf: bool) -> Result<String> {
    validate_path(input)?;
    let input = if input == "~" {
        "."
    } else {
        input.strip_prefix("~/").unwrap_or(input)
    };
    let path = if input.starts_with('/') {
        input.to_owned()
    } else {
        remote_join(&canonical(sftp, ".").await?, input)
    };
    if preserve_leaf {
        let parent = remote_parent(&path);
        let parent = canonical(sftp, parent)
            .await
            .unwrap_or_else(|_| parent.to_owned());
        Ok(remote_join(&parent, remote_basename(&path)))
    } else {
        Ok(canonical(sftp, &path).await.unwrap_or(path))
    }
}
fn file_mode(bits: Option<u32>) -> Option<String> {
    bits.map(|mode| {
        let kind = match mode & 0o170000 {
            0o040000 => 'd',
            0o120000 => 'l',
            0o020000 => 'c',
            0o060000 => 'b',
            0o010000 => 'p',
            0o140000 => 's',
            _ => '-',
        };
        let mut chars = vec![kind];
        for shift in [6, 3, 0] {
            chars.push(if mode & (0o4 << shift) != 0 { 'r' } else { '-' });
            chars.push(if mode & (0o2 << shift) != 0 { 'w' } else { '-' });
            chars.push(if mode & (0o1 << shift) != 0 { 'x' } else { '-' });
        }
        if mode & 0o4000 != 0 {
            chars[3] = if chars[3] == 'x' { 's' } else { 'S' };
        }
        if mode & 0o2000 != 0 {
            chars[6] = if chars[6] == 'x' { 's' } else { 'S' };
        }
        if mode & 0o1000 != 0 {
            chars[9] = if chars[9] == 'x' { 't' } else { 'T' };
        }
        chars.into_iter().collect()
    })
}
fn is_directory(attrs: &FileAttributes) -> bool {
    attrs.permissions.is_some_and(|m| m & 0o170000 == 0o040000)
}
fn is_symlink(attrs: &FileAttributes) -> bool {
    attrs.permissions.is_some_and(|m| m & 0o170000 == 0o120000)
}
fn entry(name: &str, attrs: &FileAttributes) -> Value {
    json!({"name":name,"type":if is_directory(attrs) {"dir"} else if is_symlink(attrs) {"link"} else {"file"},"size":attrs.size,"mtime":attrs.mtime,"mode":file_mode(attrs.permissions)})
}

async fn directory(sftp: &RawSftpSession, path: &str) -> Result<Vec<(String, FileAttributes)>> {
    let handle = sf(sftp.opendir(path).await)?.handle;
    let mut result = Vec::new();
    let mut seen = HashSet::new();
    loop {
        match sftp.readdir(handle.clone()).await {
            Ok(names) => {
                ensure!(
                    !names.files.is_empty(),
                    "SFTP directory returned an empty non-EOF page"
                );
                for file in names.files {
                    if file.filename == "." || file.filename == ".." {
                        continue;
                    }
                    ensure!(
                        !file.filename.contains(['/', '\\', '\0']) && !file.filename.is_empty(),
                        "SFTP server returned an unsafe directory entry"
                    );
                    ensure!(
                        seen.insert(file.filename.clone()),
                        "SFTP server returned a repeated directory entry"
                    );
                    ensure!(
                        result.len() < MAX_DIRECTORY_ENTRIES,
                        "Directory exceeds 10000 entries"
                    );
                    result.push((file.filename, file.attrs));
                }
            }
            Err(error) if is_eof(&error) => break,
            Err(error) => return sf(Err(error)),
        }
    }
    sf(sftp.close(handle).await)?;
    Ok(result)
}

async fn mkdir_parents(sftp: &RawSftpSession, path: &str) -> Result<()> {
    let mut missing = Vec::new();
    let mut cursor = path;
    loop {
        if cursor == "/" || cursor == "." || cursor.is_empty() {
            break;
        }
        match sftp.stat(cursor).await {
            Ok(attrs) => {
                ensure!(
                    is_directory(&attrs.attrs),
                    "Remote parent is not a directory"
                );
                break;
            }
            Err(error) if is_missing(&error) => {
                ensure!(
                    missing.len() < 128,
                    "Remote path exceeds 128 directory levels"
                );
                missing.push(cursor.to_owned());
                cursor = remote_parent(cursor);
            }
            Err(error) => return sf(Err(error)),
        }
    }
    for path in missing.into_iter().rev() {
        sf(sftp
            .mkdir(
                path,
                FileAttributes {
                    permissions: Some(0o700),
                    ..Default::default()
                },
            )
            .await)?;
    }
    Ok(())
}

async fn remove_tree(sftp: &RawSftpSession, path: &str) -> Result<()> {
    // Canonicalize directories for the root guard, while preserving symlinks.
    // A lexical check alone would miss /tmp/.. and /./.
    let initial = sf(sftp.lstat(path).await)?.attrs;
    let path = if is_directory(&initial) {
        canonical(sftp, path).await?
    } else {
        path.to_owned()
    };
    ensure!(
        path != "/",
        "Refusing to recursively remove the remote root"
    );
    let mut stack = vec![(path, false, 0usize)];
    let mut visited = 0;
    while let Some((path, expanded, depth)) = stack.pop() {
        ensure!(
            depth <= 128,
            "Recursive removal exceeds 128 directory levels"
        );
        if expanded {
            sf(sftp.rmdir(path).await)?;
            continue;
        }
        visited += 1;
        ensure!(
            visited <= MAX_REMOVE_ENTRIES,
            "Recursive removal exceeds 100000 entries"
        );
        // lstat is essential: a symlink must be removed, never traversed.
        let attrs = sf(sftp.lstat(path.clone()).await)?.attrs;
        if is_directory(&attrs) {
            stack.push((path.clone(), true, depth));
            for (name, _) in directory(sftp, &path).await? {
                stack.push((remote_join(&path, &name), false, depth + 1));
            }
        } else {
            sf(sftp.remove(path).await)?;
        }
    }
    Ok(())
}

fn decode_write(args: &Value) -> Result<Vec<u8>> {
    let content = args
        .get("content")
        .and_then(Value::as_str)
        .context("content is required for write")?;
    let encoding = args
        .get("encoding")
        .and_then(Value::as_str)
        .unwrap_or("utf-8");
    let bytes = match encoding {
        "utf-8" => {
            ensure!(
                content.len() <= MAX_CONTENT,
                "Write content exceeds 200000 bytes"
            );
            content.as_bytes().to_vec()
        }
        "base64" => {
            ensure!(
                content.len() <= MAX_CONTENT.div_ceil(3) * 4,
                "Write content exceeds 200000 bytes"
            );
            STANDARD
                .decode(content)
                .context("Write content is invalid base64")?
        }
        _ => bail!("encoding must be utf-8 or base64"),
    };
    ensure!(
        bytes.len() <= MAX_CONTENT,
        "Write content exceeds 200000 bytes"
    );
    Ok(bytes)
}
async fn local_path(args: &Value) -> Result<PathBuf> {
    let text = args
        .get("local_path")
        .and_then(Value::as_str)
        .context("local_path is required for get and put")?;
    validate_path(text)?;
    let path = if text == "~" {
        dirs::home_dir().context("Home directory unavailable")?
    } else if let Some(relative) = text.strip_prefix("~/").or_else(|| text.strip_prefix("~\\")) {
        dirs::home_dir()
            .context("Home directory unavailable")?
            .join(relative)
    } else {
        PathBuf::from(text)
    };
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()
            .context("Current directory unavailable")?
            .join(path))
    }
}
async fn read_chunk(
    sftp: &RawSftpSession,
    handle: &str,
    offset: u64,
    limit: usize,
) -> Result<Option<Vec<u8>>> {
    match sftp.read(handle.to_owned(), offset, limit as u32).await {
        Ok(data) => {
            ensure!(
                !data.data.is_empty() && data.data.len() <= limit,
                "SFTP server returned an invalid read length"
            );
            Ok(Some(data.data))
        }
        Err(error) if is_eof(&error) => Ok(None),
        Err(error) => sf(Err(error)),
    }
}

fn advance_transfer_offset(offset_bytes: u64, chunk_bytes: usize) -> Result<u64> {
    let chunk_bytes =
        u64::try_from(chunk_bytes).context("SFTP chunk length exceeds the 64-bit offset range")?;
    offset_bytes
        .checked_add(chunk_bytes)
        .context("SFTP transfer exceeds the protocol's 64-bit offset range")
}

async fn remote_write(sftp: &RawSftpSession, path: &str, bytes: &[u8]) -> Result<()> {
    let handle = sf(sftp
        .open(
            path,
            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
            FileAttributes {
                permissions: Some(0o600),
                ..Default::default()
            },
        )
        .await)?
    .handle;
    for (index, chunk) in bytes.chunks(CHUNK).enumerate() {
        sf(sftp
            .write(handle.clone(), (index * CHUNK) as u64, chunk.to_vec())
            .await)?;
    }
    sf(sftp.close(handle).await)?;
    Ok(())
}

async fn file_action(
    sftp: &RawSftpSession,
    action: &str,
    path: &str,
    args: &Value,
) -> Result<Value> {
    let recursive = match args.get("recursive") {
        None | Some(Value::Null) => false,
        Some(v) => v.as_bool().context("recursive must be a boolean")?,
    };
    match action {
        "list" => {
            let mut entries: Vec<_> = directory(sftp, path)
                .await?
                .into_iter()
                .map(|(name, attrs)| entry(&name, &attrs))
                .collect();
            entries.sort_by_key(|item| {
                (
                    item["type"] != "dir",
                    item["name"].as_str().unwrap_or("").to_lowercase(),
                )
            });
            Ok(json!({"path":path,"count":entries.len(),"entries":entries}))
        }
        "stat" => {
            let attrs = sf(sftp.stat(path).await)?.attrs;
            let mut result = entry(remote_basename(path), &attrs);
            result["path"] = json!(path);
            Ok(result)
        }
        "read" => {
            let attrs = sf(sftp.stat(path).await)?.attrs;
            ensure!(!is_directory(&attrs), "Remote path is a directory");
            ensure!(
                attrs.size.unwrap_or(0) <= MAX_CONTENT as u64,
                "Remote file exceeds 200000 bytes"
            );
            let handle = sf(sftp
                .open(path, OpenFlags::READ, FileAttributes::default())
                .await)?
            .handle;
            let mut bytes = Vec::new();
            while let Some(chunk) = read_chunk(
                sftp,
                &handle,
                bytes.len() as u64,
                CHUNK.min(MAX_CONTENT + 1 - bytes.len()),
            )
            .await?
            {
                bytes.extend(chunk);
                ensure!(
                    bytes.len() <= MAX_CONTENT,
                    "Remote file exceeds 200000 bytes"
                );
            }
            sf(sftp.close(handle).await)?;
            let (content, encoding) = if !bytes.contains(&0) {
                match std::str::from_utf8(&bytes) {
                    Ok(text) => (text.to_owned(), "utf-8"),
                    Err(_) => (STANDARD.encode(&bytes), "base64"),
                }
            } else {
                (STANDARD.encode(&bytes), "base64")
            };
            Ok(json!({"path":path,"size":bytes.len(),"encoding":encoding,"content":content}))
        }
        "write" => {
            let bytes = decode_write(args)?;
            if recursive {
                mkdir_parents(sftp, remote_parent(path)).await?;
            }
            remote_write(sftp, path, &bytes).await?;
            Ok(json!({"path":path,"size":bytes.len(),"ok":true}))
        }
        "get" => {
            let attrs = sf(sftp.stat(path).await)?.attrs;
            ensure!(
                !is_directory(&attrs),
                "Remote path is a directory; get needs a file"
            );
            let mut destination = local_path(args).await?;
            if tokio::fs::metadata(&destination)
                .await
                .is_ok_and(|m| m.is_dir())
            {
                let name = local_download_name(remote_basename(path))?;
                destination.push(name);
            }
            let parent = destination
                .parent()
                .context("Local destination has no parent")?;
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|_| anyhow!("Could not create local destination directory"))?;
            let temp = tempfile::NamedTempFile::new_in(parent)
                .map_err(|_| anyhow!("Could not create a temporary download file"))?;
            let mut file = tokio::fs::File::from_std(
                temp.as_file()
                    .try_clone()
                    .map_err(|_| anyhow!("Could not open temporary download file"))?,
            );
            let handle = sf(sftp
                .open(path, OpenFlags::READ, FileAttributes::default())
                .await)?
            .handle;
            let mut offset = 0;
            while let Some(chunk) = read_chunk(sftp, &handle, offset, CHUNK).await? {
                let next_offset = advance_transfer_offset(offset, chunk.len())?;
                file.write_all(&chunk)
                    .await
                    .map_err(|_| anyhow!("Could not write local download file"))?;
                offset = next_offset;
            }
            sf(sftp.close(handle).await)?;
            file.flush()
                .await
                .map_err(|_| anyhow!("Could not flush local download file"))?;
            file.sync_all()
                .await
                .map_err(|_| anyhow!("Could not synchronize local download file"))?;
            drop(file);
            // Persist only after the whole streamed transfer succeeds. A timeout
            // or cancellation removes the temporary file and preserves the old destination.
            temp.persist(&destination)
                .map_err(|_| anyhow!("Could not atomically replace local destination"))?;
            Ok(json!({"path":path,"local_path":destination,"size":offset,"ok":true}))
        }
        "put" => {
            let source = local_path(args).await?;
            let mut options = tokio::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            options.custom_flags(libc::O_NONBLOCK);
            let mut file = options
                .open(&source)
                .await
                .map_err(|_| anyhow!("Could not open local upload file"))?;
            let metadata = file
                .metadata()
                .await
                .map_err(|_| anyhow!("Could not read local upload metadata"))?;
            ensure!(
                metadata.is_file(),
                "Local upload source must be a regular file"
            );
            let mut destination = path.to_owned();
            if sftp.stat(path).await.is_ok_and(|a| is_directory(&a.attrs)) {
                let name = source
                    .file_name()
                    .and_then(|n| n.to_str())
                    .context("Local filename is not UTF-8")?;
                destination = remote_join(path, name);
            }
            if recursive {
                mkdir_parents(sftp, remote_parent(&destination)).await?;
            }
            let handle = sf(sftp
                .open(
                    destination.clone(),
                    OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::TRUNCATE,
                    FileAttributes {
                        permissions: Some(0o600),
                        ..Default::default()
                    },
                )
                .await)?
            .handle;
            let mut offset = 0;
            let mut buffer = vec![0; CHUNK];
            loop {
                let n = file
                    .read(&mut buffer)
                    .await
                    .map_err(|_| anyhow!("Could not read local upload file"))?;
                if n == 0 {
                    break;
                }
                let next_offset = advance_transfer_offset(offset, n)?;
                sf(sftp
                    .write(handle.clone(), offset, buffer[..n].to_vec())
                    .await)?;
                offset = next_offset;
            }
            sf(sftp.close(handle).await)?;
            Ok(json!({"path":destination,"local_path":source,"size":offset,"ok":true}))
        }
        "mkdir" => {
            if recursive {
                mkdir_parents(sftp, path).await?;
            } else {
                sf(sftp
                    .mkdir(
                        path,
                        FileAttributes {
                            permissions: Some(0o700),
                            ..Default::default()
                        },
                    )
                    .await)?;
            }
            Ok(json!({"path":path,"ok":true}))
        }
        "rm" => {
            if recursive {
                remove_tree(sftp, path).await?;
            } else {
                let attrs = sf(sftp.lstat(path).await)?.attrs;
                if is_directory(&attrs) {
                    sf(sftp.rmdir(path).await)?;
                } else {
                    sf(sftp.remove(path).await)?;
                }
            }
            Ok(json!({"path":path,"ok":true}))
        }
        "rename" => {
            let dest = args
                .get("dest")
                .and_then(Value::as_str)
                .context("dest is required for rename")?;
            let dest = remote_path(sftp, dest, true).await?;
            sf(sftp.rename(path, dest.clone()).await)?;
            Ok(json!({"path":path,"dest":dest,"ok":true}))
        }
        _ => bail!("Unknown SFTP action"),
    }
}

pub async fn run_files(
    spec: &ConnectionSpec,
    args: &Value,
    cancel: CancellationToken,
) -> Result<Value> {
    let action = args
        .get("action")
        .and_then(Value::as_str)
        .context("action is required")?;
    ensure!(
        [
            "list", "stat", "read", "write", "get", "put", "mkdir", "rm", "rename"
        ]
        .contains(&action),
        "Unknown SFTP action"
    );
    let path = args
        .get("path")
        .and_then(Value::as_str)
        .filter(|p| !p.trim().is_empty());
    ensure!(
        action == "list" || path.is_some(),
        "path is required for this SFTP action"
    );
    let path = path.unwrap_or(".");
    validate_path(path)?;
    if action == "write" {
        decode_write(args)?;
    }
    let timeout = timeout_seconds(args)?;
    let deadline = Instant::now() + Duration::from_secs(timeout);
    let operation = async {
        let route = connect_route(spec).await?;
        let channel = route
            .target()
            .channel_open_session()
            .await
            .map_err(|_| anyhow!("Could not open SFTP channel"))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|_| anyhow!("Could not request SFTP subsystem"))?;
        let sftp = RawSftpSession::new_with_config(
            channel.into_stream(),
            russh_sftp::client::Config {
                request_timeout_secs: timeout,
                max_packet_len: 262144,
                ..Default::default()
            },
        );
        let version = sf(sftp.init().await)?;
        ensure!(
            version.version == 3,
            "SFTP server does not support protocol version 3"
        );
        let path = remote_path(&sftp, path, matches!(action, "rm" | "rename")).await?;
        let mut result = file_action(&sftp, action, &path, args).await?;
        result["host"] = json!(spec.label);
        result["address"] = json!(spec.target.address);
        result["username"] = json!(spec.target.username);
        result["action"] = json!(action);
        result["host_key_verification"] = host_key_verification(spec);
        if result.get("ok").is_none() {
            result["ok"] = json!(true);
        }
        let _ = sftp.close_session();
        drop(route);
        Ok::<_, anyhow::Error>(result)
    };
    tokio::select! {
        biased;
        _ = cancel.cancelled() => bail!("SFTP operation cancelled"),
        result = tokio::time::timeout_at(deadline, operation) => result.map_err(|_| anyhow!("SFTP operation timed out; connection closed"))?,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streamed_transfer_offsets_are_checked_at_the_protocol_boundary() {
        assert_eq!(
            advance_transfer_offset(50 * 1024 * 1024, CHUNK).unwrap(),
            50 * 1024 * 1024 + CHUNK as u64
        );
        assert_eq!(advance_transfer_offset(u64::MAX - 3, 3).unwrap(), u64::MAX);
        assert_eq!(advance_transfer_offset(u64::MAX, 0).unwrap(), u64::MAX);
        assert!(advance_transfer_offset(u64::MAX, 1).is_err());
        assert!(advance_transfer_offset(u64::MAX - 3, 4).is_err());
    }

    #[test]
    fn download_basenames_cannot_change_local_directory_or_drive() {
        for name in [
            "",
            ".",
            "..",
            "C:payload",
            "c:payload",
            "C:",
            "C:\\payload",
            "C:/payload",
            "\\\\server\\share",
            "/absolute",
            "a/b",
            "a\\b",
            "a\0b",
            "a/.",
        ] {
            assert!(local_download_name(name).is_err(), "accepted {name:?}");
        }
        for path in ["/foo/..", "/foo/.", "/foo/..///", "/"] {
            assert!(local_download_name(remote_basename(path)).is_err());
        }
        for name in [
            "file.bin",
            ".profile",
            "中文.txt",
            "my file.txt",
            "..safe",
            "file.name",
        ] {
            assert_eq!(local_download_name(name).unwrap(), name);
        }
    }

    #[tokio::test]
    async fn cancellation_during_handshake_closes_the_tcp_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (seen, connected) = tokio::sync::oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 256];
            assert!(socket.read(&mut buffer).await.unwrap() > 0);
            seen.send(()).unwrap();
            // Deliberately never send an SSH banner. Cancellation must still
            // close the transport, rather than orphaning the russh task.
            loop {
                if socket.read(&mut buffer).await.unwrap() == 0 {
                    break;
                }
            }
        });
        let spec = ConnectionSpec {
            host_id: json!(1),
            label: "stalled test peer".into(),
            jumps: vec![],
            target: Endpoint {
                address: "127.0.0.1".into(),
                port,
                username: Some("test".into()),
                password: None,
                private_key: None,
                passphrase: None,
                strict_host_key_check: false,
                known_host_keys: vec![],
                connect_timeout: 30,
                keep_alive: 0,
            },
        };
        let cancel = CancellationToken::new();
        let cancellation = cancel.clone();
        let operation = tokio::spawn(async move {
            run_exec(
                &spec,
                &json!({"command":"true", "timeout":30}),
                cancellation,
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(2), connected)
            .await
            .unwrap()
            .unwrap();
        cancel.cancel();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), operation)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(2), peer)
            .await
            .unwrap()
            .unwrap();
    }
    #[test]
    fn output_is_bounded_and_utf8_safe() {
        let mut out = Capture::default();
        out.add("雪".repeat(MAX_OUTPUT + 1).as_bytes());
        let (text, truncated) = out.finish("stdout");
        assert!(truncated);
        assert!(text.starts_with('雪'));
        assert!(text.ends_with("...[stdout truncated]..."));
        assert_eq!(text.chars().filter(|c| *c == '雪').count(), MAX_OUTPUT);
    }
    #[test]
    fn capture_drops_after_byte_cap() {
        let mut out = Capture::default();
        out.add(&vec![b'x'; MAX_CAPTURE_BYTES + 100]);
        assert_eq!(out.bytes.len(), MAX_CAPTURE_BYTES);
        assert!(out.dropped);
    }
    #[test]
    fn strict_base64_and_size_limits() {
        assert!(decode_write(&json!({"content":"***","encoding":"base64"})).is_err());
        assert!(decode_write(&json!({"content":"a","encoding":"latin-1"})).is_err());
        assert!(decode_write(&json!({"content":"a".repeat(MAX_CONTENT+1)})).is_err());
        assert_eq!(
            decode_write(&json!({"content":"AAEC","encoding":"base64"})).unwrap(),
            [0, 1, 2]
        );
    }
    #[test]
    fn wildcard_negation_and_ports() {
        assert!(wildcard(b"*.example.com", b"host.example.com"));
        assert!(wildcard(b"[example.com]:2222", b"[example.com]:2222"));
        assert!(!wildcard(b"[example.com]:2222", b"[example.com]:22"));
        assert!(!wildcard(b"?.example.com", b"ab.example.com"));
    }
    #[test]
    fn modes_and_path_parents() {
        assert_eq!(file_mode(Some(0o1004755)).unwrap(), "-rwsr-xr-x");
        assert_eq!(file_mode(Some(0o41777)).unwrap(), "drwxrwxrwt");
        assert_eq!(remote_parent("/file"), "/");
        assert_eq!(remote_parent("/a/b/"), "/a");
        assert!(validate_path("a\0b").is_err());
        assert!(!is_directory(&FileAttributes {
            permissions: Some(0o120777),
            ..Default::default()
        }));
    }
    #[test]
    fn validate_timeout() {
        assert_eq!(timeout_seconds(&json!({})).unwrap(), 60);
        for value in [json!(-1), json!(0), json!(true), json!(1.1), json!(86401)] {
            assert!(timeout_seconds(&json!({"timeout":value})).is_err());
        }
    }
    #[test]
    fn known_hosts_supports_hashes_wildcards_and_revocation() {
        let encoded =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJdD7y3aLq454yWBdwLWbieU1ebz9/cu7/QEXn9OIeZJ";
        let key = PublicKey::from_openssh(encoded).unwrap();
        assert!(
            verify_known_hosts(
                &format!("*.example.com,!bad.example.com {encoded}"),
                "ok.example.com",
                &key
            )
            .unwrap()
        );
        assert!(
            !verify_known_hosts(
                &format!("*.example.com,!bad.example.com {encoded}"),
                "bad.example.com",
                &key
            )
            .unwrap()
        );
        assert!(
            verify_known_hosts(
                &format!("good.example.com {encoded}\n@revoked good.example.com {encoded}"),
                "good.example.com",
                &key
            )
            .is_err()
        );
        let salt = b"test known host salt";
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(salt).unwrap();
        mac.update(b"[example.com]:2222");
        let hashed = format!(
            "|1|{}|{} {}",
            STANDARD.encode(salt),
            STANDARD.encode(mac.finalize().into_bytes()),
            encoded
        );
        assert!(verify_known_hosts(&hashed, "[example.com]:2222", &key).unwrap());
        assert!(!verify_known_hosts(&hashed, "example.com", &key).unwrap());
    }
}
