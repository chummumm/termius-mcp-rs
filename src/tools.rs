//! MCP tool dispatch. Cloud mutations are serialized; SSH work runs independently.
use crate::{
    cloud, inventory, ssh,
    storage::{Store, StoredState},
};
use serde_json::{Value, json};
use std::{
    sync::{Arc, OnceLock},
    time::Duration,
};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

pub const DEFAULT_SYNC_TTL: u64 = 60;

pub fn catalog() -> &'static Value {
    static CATALOG: OnceLock<Value> = OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("tool_catalog.json"))
            .expect("embedded catalog is valid JSON")
    })
}

#[derive(Debug)]
pub struct ToolError {
    pub code: &'static str,
    pub message: String,
}

impl ToolError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ToolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}
impl std::error::Error for ToolError {}

pub type ToolResult = Result<Value, ToolError>;

fn error(code: &'static str, e: impl std::fmt::Display) -> ToolError {
    ToolError::new(code, e.to_string())
}

fn login_failure(e: anyhow::Error) -> ToolError {
    let code = if e.downcast_ref::<cloud::OtpRequired>().is_some() {
        "otp_required"
    } else {
        "login_failed"
    };
    error(code, e)
}

pub struct Runtime {
    store: Mutex<Store>,
    mutation: Mutex<()>,
}

impl Runtime {
    pub fn new(store: Store) -> Arc<Self> {
        Arc::new(Self {
            store: Mutex::new(store),
            mutation: Mutex::new(()),
        })
    }

    async fn snapshot(&self) -> Result<StoredState, ToolError> {
        let mut store = self.store.lock().await;
        store.reload().map_err(|e| error("storage_error", e))?;
        Ok(store.state.clone())
    }

    async fn commit(&self, previous: &StoredState, next: StoredState) -> Result<(), ToolError> {
        let mut store = self.store.lock().await;
        store.reload().map_err(|e| error("storage_error", e))?;
        // A CLI in another process may have logged out while the HTTP request ran.
        // Never resurrect its old session or replace newer inventory.
        if serde_json::to_value(&store.state).ok() != serde_json::to_value(previous).ok() {
            return Err(ToolError::new(
                "state_changed",
                "Local state changed in another process; retry the operation.",
            ));
        }
        store.state = next;
        if let Err(e) = store.save() {
            let _ = store.reload();
            return Err(error("storage_error", e));
        }
        Ok(())
    }

    pub async fn call(&self, name: &str, args: Value, cancel: CancellationToken) -> ToolResult {
        validate(name, &args)?;
        if matches!(name, "exec" | "files") {
            // The SSH layer owns cancellation and closes every hop before returning.
            let snapshot = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(ToolError::new("cancelled", "Cancelled by the client")),
                value = self.ensure_fresh(sync_ttl(), false) => value?,
            };
            if cancel.is_cancelled() {
                return Err(ToolError::new("cancelled", "Cancelled by the client"));
            }
            let spec = inventory::resolve(&snapshot.0.inventory, required_string(&args, "name")?)
                .map_err(|e| error("ssh_failed", e))?;
            let mut out = if name == "exec" {
                ssh::run_exec(&spec, &args, cancel)
                    .await
                    .map_err(|e| error("ssh_failed", e))?
            } else {
                ssh::run_files(&spec, &args, cancel)
                    .await
                    .map_err(|e| error("file_failed", e))?
            };
            if name == "exec" {
                out["ok"] = json!(out["timed_out"] != true && out["exit_code"] == 0);
            }
            append_sync_metadata(&mut out, &snapshot.0.inventory);
            return Ok(out);
        }
        tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ToolError::new("cancelled", "Cancelled by the client")),
            value = self.call_inner(name, &args) => value,
        }
    }

    async fn call_inner(&self, name: &str, args: &Value) -> ToolResult {
        match name {
            "status" => {
                let state = self.snapshot().await?;
                let session = state.session.as_ref().unwrap_or(&Value::Null);
                let mut out = inventory::counts(&state.inventory);
                out["logged_in"] = json!(signed_in(&state));
                out["username"] = session.get("username").cloned().unwrap_or(json!(""));
                out["encryption_schema"] = session
                    .get("encryption_schema")
                    .cloned()
                    .unwrap_or(json!(""));
                out["is_team"] = json!(session["is_team"] == true || session["is_team"] == "yes");
                out["has_keypair"] = json!(
                    session["private_key"]
                        .as_str()
                        .is_some_and(|s| !s.is_empty())
                );
                out["last_synced"] = json!(state.last_synced.as_deref().unwrap_or(""));
                out["stale"] = json!(is_stale(state.last_synced.as_deref(), sync_ttl()));
                out["vault_remembered"] = json!(vault_password(&state).is_some());
                out["sync_ttl"] = json!(sync_ttl());
                append_sync_metadata(&mut out, &state.inventory);
                Ok(out)
            }
            "login" => {
                let method = args["method"].as_str().unwrap_or("email");
                let _guard = self.mutation.lock().await;
                let previous = self.snapshot().await?;
                let mut next = previous.clone();
                if method == "google" {
                    let pending =
                        cloud::login_google_start().map_err(|e| error("login_failed", e))?;
                    next.pending_sso = Some(pending.clone());
                    self.commit(&previous, next).await?;
                    return Ok(pending);
                }
                let username = required_string(args, "username")?;
                let password = required_secret(args, "password")?;
                let session = cloud::login_email(username, password, args["otp"].as_str())
                    .await
                    .map_err(login_failure)?;
                let remember = args["remember"].as_bool().unwrap_or(true);
                let out = login_summary(&session, remember);
                next.session = Some(session);
                next.vault_password = remember.then(|| password.to_string());
                next.inventory = json!({});
                next.last_synced = None;
                next.pending_sso = None;
                self.commit(&previous, next).await?;
                Ok(out)
            }
            "login_complete" => {
                let _guard = self.mutation.lock().await;
                let previous = self.snapshot().await?;
                let pending = previous.pending_sso.as_ref().ok_or_else(|| {
                    ToolError::new(
                        "login_failed",
                        "Start Google sign-in with login(method=google) first.",
                    )
                })?;
                let password = required_secret(args, "password")?;
                let session = cloud::login_google_complete(
                    pending,
                    required_string(args, "callback_url")?,
                    password,
                    args["otp"].as_str(),
                )
                .await
                .map_err(login_failure)?;
                let remember = args["remember"].as_bool().unwrap_or(true);
                let out = login_summary(&session, remember);
                let mut next = previous.clone();
                next.session = Some(session);
                next.vault_password = remember.then(|| password.to_string());
                next.inventory = json!({});
                next.last_synced = None;
                next.pending_sso = None;
                self.commit(&previous, next).await?;
                Ok(out)
            }
            "logout" => {
                let _guard = self.mutation.lock().await;
                let previous = self.snapshot().await?;
                self.commit(&previous, StoredState::default()).await?;
                Ok(json!({"ok":true,"logged_in":false}))
            }
            "sync" => {
                let _guard = self.mutation.lock().await;
                let previous = self.snapshot().await?;
                require_signed_in(&previous)?;
                let supplied = args["password"].as_str().filter(|s| !s.is_empty());
                let password = supplied
                    .map(str::to_owned)
                    .or_else(|| vault_password(&previous))
                    .ok_or_else(password_required)?;
                let mut next = self.pull_state(&previous, &password).await?;
                if let Some(password) = supplied
                    && args["remember"].as_bool().unwrap_or(true)
                {
                    next.vault_password = Some(password.to_string());
                }
                let counts = inventory::counts(&next.inventory);
                let mut out = json!({"ok":true,"last_synced":next.last_synced,"hosts":counts["hosts"],"counts":counts,"vault_remembered":vault_password(&next).is_some()});
                append_sync_metadata(&mut out, &next.inventory);
                self.commit(&previous, next).await?;
                Ok(out)
            }
            "hosts" | "host" => {
                let (state, warning) = self.ensure_fresh(600, true).await?;
                let mut out = if name == "hosts" {
                    let hosts = inventory::hosts(&state.inventory, args["query"].as_str())
                        .map_err(|e| error("inventory_failed", e))?;
                    json!({"count":hosts.as_array().map_or(0, Vec::len),"hosts":hosts})
                } else {
                    inventory::host_details(&state.inventory, required_string(args, "name")?)
                        .map_err(|e| error("host_not_found", e))?
                };
                append_sync_metadata(&mut out, &state.inventory);
                if let Some(message) = warning {
                    out["stale"] = json!(true);
                    out["sync_error"] = json!(message);
                    if name == "host" {
                        out["ssh_command"] = Value::Null;
                        out["ssh_command_reason"] = json!("Sync before generating an SSH command.");
                    }
                }
                Ok(out)
            }
            "inventory" => {
                let (state, _) = self.ensure_fresh(sync_ttl(), false).await?;
                let kind = required_string(args, "kind")?;
                let mut out = inventory::list(&state.inventory, kind, true)
                    .map_err(|e| error("inventory_failed", e))?;
                append_sync_metadata(&mut out, &state.inventory);
                Ok(out)
            }
            _ => Err(ToolError::new("unknown_tool", "Unknown tool")),
        }
    }

    async fn pull_state(
        &self,
        previous: &StoredState,
        password: &str,
    ) -> Result<StoredState, ToolError> {
        let mut next = previous.clone();
        let session = next.session.as_mut().ok_or_else(not_signed_in)?;
        let snapshot =
            tokio::time::timeout(Duration::from_secs(120), cloud::pull(session, password))
                .await
                .map_err(|_| ToolError::new("sync_failed", "Cloud synchronization timed out."))?
                .map_err(|e| error("sync_failed", e))?;
        let timestamp = match snapshot.get("last_synced") {
            Some(Value::String(s)) if !s.is_empty() => s.clone(),
            Some(v) if v.is_number() => v.to_string(),
            _ => now_timestamp(),
        };
        next.inventory = snapshot;
        next.last_synced = Some(timestamp);
        Ok(next)
    }

    async fn ensure_fresh(
        &self,
        ttl: u64,
        allow_stale: bool,
    ) -> Result<(StoredState, Option<String>), ToolError> {
        let _guard = self.mutation.lock().await;
        let previous = self.snapshot().await?;
        require_signed_in(&previous)?;
        let password = vault_password(&previous).ok_or_else(password_required)?;
        if !is_stale(previous.last_synced.as_deref(), ttl)
            && previous.inventory.get("host_set").is_some()
        {
            return Ok((previous, None));
        }
        match self.pull_state(&previous, &password).await {
            Ok(next) => {
                self.commit(&previous, next.clone()).await?;
                Ok((next, None))
            }
            Err(e) if allow_stale => Ok((previous, Some(e.message))),
            Err(e) => Err(e),
        }
    }
}

fn login_summary(session: &Value, remembered: bool) -> Value {
    json!({"ok":true,"username":session["username"],"encryption_schema":session["encryption_schema"],"vault_remembered":remembered})
}

fn append_sync_metadata(out: &mut Value, snapshot: &Value) {
    out["unreadable_entities"] = json!(snapshot["unreadable_entities"].as_u64().unwrap_or(0));
    if let Some(warnings) = snapshot["sync_warnings"].as_array()
        && !warnings.is_empty()
    {
        out["sync_warnings"] = json!(warnings);
    }
}

fn not_signed_in() -> ToolError {
    ToolError::new("not_signed_in", "Not signed in. Call login.")
}
fn password_required() -> ToolError {
    ToolError::new(
        "vault_password_required",
        "Vault password is required. Pass it to sync, set TERMIUS_VAULT_PASSWORD, or sign in with remember=true.",
    )
}
fn signed_in(state: &StoredState) -> bool {
    state.session.as_ref().is_some_and(|s| {
        s["username"].as_str().is_some_and(|v| !v.is_empty())
            && s["apikey"].as_str().is_some_and(|v| !v.is_empty())
    })
}
fn require_signed_in(state: &StoredState) -> Result<(), ToolError> {
    if signed_in(state) {
        Ok(())
    } else {
        Err(not_signed_in())
    }
}
fn vault_password(state: &StoredState) -> Option<String> {
    std::env::var("TERMIUS_VAULT_PASSWORD")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| state.vault_password.clone().filter(|s| !s.is_empty()))
}
pub fn sync_ttl() -> u64 {
    std::env::var("TERMIUS_SYNC_TTL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_SYNC_TTL)
}
pub fn is_stale(raw: Option<&str>, ttl: u64) -> bool {
    let Some(raw) = raw else { return true };
    let raw = raw.trim();
    let seconds = raw
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite())
        .or_else(|| {
            OffsetDateTime::parse(raw, &Rfc3339)
                .ok()
                .map(|d| d.unix_timestamp() as f64)
        })
        .or_else(|| {
            // Source-compatible naive ISO timestamps explicitly mean UTC.
            // Appending Z cannot turn an already offset-aware malformed value valid.
            let normalized = format!("{}Z", raw.replacen(' ', "T", 1));
            OffsetDateTime::parse(&normalized, &Rfc3339)
                .ok()
                .map(|date| date.unix_timestamp() as f64)
        });
    match seconds {
        Some(v) => {
            let age = OffsetDateTime::now_utc().unix_timestamp() as f64 - v;
            age < -300.0 || age >= ttl as f64
        }
        None => true,
    }
}
fn now_timestamp() -> String {
    let now = OffsetDateTime::now_utc();
    now.format(&Rfc3339)
        .unwrap_or_else(|_| now.unix_timestamp().to_string())
}
fn required_string<'a>(args: &'a Value, key: &str) -> Result<&'a str, ToolError> {
    args[key]
        .as_str()
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ToolError::new("invalid_argument", format!("{key} is required")))
}
fn required_secret<'a>(args: &'a Value, key: &str) -> Result<&'a str, ToolError> {
    args[key]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ToolError::new("invalid_argument", format!("{key} is required")))
}
pub fn validate(name: &str, args: &Value) -> Result<(), ToolError> {
    let tool = catalog()
        .as_array()
        .expect("catalog array")
        .iter()
        .find(|t| t["name"] == name)
        .ok_or_else(|| ToolError::new("unknown_tool", "Unknown tool"))?;
    let object = args
        .as_object()
        .ok_or_else(|| ToolError::new("invalid_argument", "arguments must be an object"))?;
    let schema = &tool["inputSchema"];
    if let Some(required) = schema["required"].as_array() {
        for key in required {
            if !object.contains_key(key.as_str().expect("property name")) {
                return Err(ToolError::new(
                    "invalid_argument",
                    format!("{} is required", key.as_str().unwrap()),
                ));
            }
        }
    }
    for (key, property) in schema["properties"].as_object().unwrap() {
        if let Some(value) = object.get(key) {
            let valid = match property["type"].as_str() {
                Some("string") => value.is_string(),
                Some("integer") => value.is_u64() || value.is_i64(),
                Some("boolean") => value.is_boolean(),
                _ => true,
            };
            if !valid {
                return Err(ToolError::new(
                    "invalid_argument",
                    format!("{key} has an invalid type"),
                ));
            }
            if let Some(values) = property["enum"].as_array()
                && !values.contains(value)
            {
                return Err(ToolError::new(
                    "invalid_argument",
                    format!("{key} has an unsupported value"),
                ));
            }
        }
    }
    if let Some(v) = object.get("timeout")
        && !v.as_u64().is_some_and(|n| (1..=86400).contains(&n))
    {
        return Err(ToolError::new(
            "invalid_argument",
            "timeout must be an integer from 1 to 86400 seconds",
        ));
    }
    if name == "exec" {
        required_string(args, "command")?;
    }
    if name == "files" {
        let action = required_string(args, "action")?;
        if action != "list" {
            required_string(args, "path")?;
        }
        if matches!(action, "get" | "put") {
            required_string(args, "local_path")?;
        }
        if action == "rename" {
            required_string(args, "dest")?;
        }
        if action == "write" && args["content"].as_str().is_none() {
            return Err(ToolError::new("invalid_argument", "content is required"));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn otp_retry_code_depends_on_the_challenge_type_not_error_text() {
        let challenge = anyhow::Error::new(cloud::OtpRequired).context("Sign-in challenge");
        assert_eq!(login_failure(challenge).code, "otp_required");
        let ordinary = anyhow::anyhow!("A non-challenge error mentioning OTP or 2FA");
        assert_eq!(login_failure(ordinary).code, "login_failed");
    }

    #[test]
    fn validation_does_not_coerce_destructive_arguments() {
        assert!(
            validate(
                "files",
                &json!({"name":"x","action":"rm","path":"/x","recursive":"false"})
            )
            .is_err()
        );
        assert!(validate("exec", &json!({"name":"x","command":"true","timeout":0})).is_err());
        assert!(validate("exec", &json!({"name":"x","command":"true","timeout":1.5})).is_err());
        assert!(validate("status", &json!({"i":"client-injected intent"})).is_ok());
        assert!(
            validate(
                "files",
                &json!({"name":"x","action":"write","path":"/x","content":""})
            )
            .is_ok()
        );
        assert!(validate("files", &json!({"name":"x","action":"get","path":"/x"})).is_err());
    }
    #[test]
    fn stale_dates_are_conservative() {
        assert!(is_stale(None, 60));
        assert!(is_stale(Some("NaN"), 60));
        assert!(is_stale(Some("not-a-date"), 60));
        assert!(is_stale(Some("2999-01-01T00:00:00Z"), 60));
        assert!(!is_stale(Some(&now_timestamp()), 60));
        assert!(is_stale(Some("0"), 60));
    }
    #[test]
    fn tool_catalog_is_compatible() {
        let tools = catalog().as_array().unwrap();
        assert_eq!(tools.len(), 10);
        for tool in tools {
            assert_eq!(tool["outputSchema"]["type"], "object");
        }
        assert!(validate("unrecognized", &json!({})).is_err());
    }
}
