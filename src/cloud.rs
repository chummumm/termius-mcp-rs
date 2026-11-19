//! Termius Cloud API and desktop-compatible Socket.IO/SRP login.
//! No callback URL, token, upstream response body, or password is logged.
use crate::crypto::{self, SrpSession, VaultCryptor, bytes_field, decode_b64, key_bytes};
use anyhow::{Context, Result, anyhow, bail, ensure};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use reqwest::{Client, Method, StatusCode, header};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::net::TcpStream;
use tokio::time::{Instant, timeout, timeout_at};
use tokio_tungstenite::{
    MaybeTlsStream, WebSocketStream, connect_async_with_config,
    tungstenite::{Message, protocol::WebSocketConfig},
};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const API: &str = "https://api.termius.com/api/";
const LOGIN_WS: &str = "wss://api.termius.com/socket.io/grpc-proxy/?EIO=4&transport=websocket";
const APP_VERSION: &str = "10.0.6";
const MAX_BODY: usize = 64 * 1024 * 1024;
const MAX_WS: usize = 8 * 1024 * 1024;
const STAGE_TIMEOUT: Duration = Duration::from_secs(120);
type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[derive(Debug)]
struct HttpStatus(u16);
impl fmt::Display for HttpStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Termius Cloud returned HTTP {}", self.0)
    }
}
impl std::error::Error for HttpStatus {}
#[derive(Debug)]
struct NotMigrated;
impl fmt::Display for NotMigrated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Account requires legacy REST login")
    }
}
impl std::error::Error for NotMigrated {}

fn client() -> Result<Client> {
    let mut headers = header::HeaderMap::new();
    headers.insert(
        "X-DEVICE-APP-VERSION",
        header::HeaderValue::from_static(APP_VERSION),
    );
    headers.insert(
        "X-DEVICE-PLATFORM",
        header::HeaderValue::from_static("Desktop"),
    );
    Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(20))
        .timeout(Duration::from_secs(180))
        .default_headers(headers)
        .build()
        .map_err(|_| anyhow!("Unable to initialize HTTPS client"))
}
async fn response_json(mut response: reqwest::Response) -> Result<(StatusCode, Value)> {
    let status = response.status();
    ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= MAX_BODY as u64),
        "Cloud response exceeds size limit"
    );
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| anyhow!("Cloud response transfer failed"))?
    {
        ensure!(
            body.len() + chunk.len() <= MAX_BODY,
            "Cloud response exceeds size limit"
        );
        body.extend_from_slice(&chunk);
    }
    // Error bodies are parsed only for a small set of numeric login codes. Never echo them.
    let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
    if status.is_success() {
        ensure!(!json.is_null(), "Cloud response is not valid JSON");
    }
    Ok((status, json))
}
async fn request(
    client: &Client,
    method: Method,
    endpoint: &str,
    token: Option<&str>,
    body: Option<&Value>,
) -> Result<(StatusCode, Value)> {
    // endpoint values are fixed source constants; no user-controlled origin is accepted.
    let mut req = client.request(method, format!("{API}{endpoint}"));
    if let Some(token) = token {
        req = req.header(header::AUTHORIZATION, format!("DeviceToken {token}"));
    }
    if let Some(body) = body {
        req = req.json(body);
    }
    let response = req
        .send()
        .await
        .map_err(|_| anyhow!("Unable to reach Termius Cloud over HTTPS"))?;
    response_json(response).await
}
async fn get(client: &Client, endpoint: &str, token: &str) -> Result<Value> {
    let (status, value) = request(client, Method::GET, endpoint, Some(token), None).await?;
    if !status.is_success() {
        return Err(HttpStatus(status.as_u16()).into());
    }
    ensure!(
        value.is_object() || value.is_array(),
        "Unexpected Cloud response shape"
    );
    Ok(value)
}
fn is_missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<HttpStatus>()
        .is_some_and(|s| matches!(s.0, 404 | 405 | 410))
}

pub fn login_google_start() -> Result<Value> {
    let id = Uuid::new_v4().to_string();
    Ok(
        json!({"ok":true,"method":"google","url":format!("https://account.termius.com/sso/desktop?provider=google&request={id}"),
        "request_id":id,"created_at":SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        "next":"login_complete","instructions":"Open the URL and sign in with Google, then provide the termius://app/continue-sso callback and your Termius vault encryption password."}),
    )
}

fn parse_callback(pending: &Value, input: &str) -> Result<(String, String)> {
    let request_id = pending["request_id"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("Start Google sign-in with the login tool first")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let created = pending["created_at"]
        .as_u64()
        .context("Missing SSO start time; start Google sign-in again")?;
    ensure!(
        now >= created && now - created <= 3600,
        "Google sign-in expired; start it again"
    );
    let input = input.trim().trim_matches(['\'', '"']);
    let mut raw = input.to_owned();
    // Accept copied query strings and documented desktop callback forms.
    if raw.starts_with("email=") || raw.starts_with("firebaseToken=") {
        raw = format!("termius://app/continue-sso?{raw}");
    } else if raw.starts_with("app/continue-sso?") {
        raw = format!("termius://{raw}");
    } else if raw.starts_with("continue-sso?") {
        raw = format!("termius://app/{raw}");
    }
    let parsed = Url::parse(&raw).map_err(|_| anyhow!("Invalid Termius SSO callback URL"))?;
    ensure!(
        parsed.scheme() == "termius"
            && parsed.host_str() == Some("app")
            && parsed.path().trim_end_matches('/') == "/continue-sso",
        "Expected termius://app/continue-sso callback"
    );
    let encoded = parsed.query().or_else(|| parsed.fragment()).unwrap_or("");
    let mut query: HashMap<String, String> = HashMap::new();
    for (key, value) in url::form_urlencoded::parse(encoded.as_bytes()) {
        ensure!(
            !query.contains_key(key.as_ref()),
            "Duplicate SSO callback field"
        );
        query.insert(key.into_owned(), value.into_owned());
    }
    let pick = |keys: &[&str]| {
        keys.iter()
            .find_map(|key| query.get(*key))
            .filter(|s| !s.is_empty())
    };
    let returned = pick(&["requestId", "request_id", "request"])
        .context("SSO callback is missing requestId")?;
    ensure!(
        returned == request_id,
        "SSO request id does not match; use the URL from login"
    );
    let token = pick(&["firebaseToken", "firebase_token", "accessToken"])
        .context("SSO callback is missing firebaseToken")?;
    Ok((
        query.get("email").cloned().unwrap_or_default(),
        token.clone(),
    ))
}

pub async fn login_google_complete(
    pending: &Value,
    callback: &str,
    password: &str,
    otp: Option<&str>,
) -> Result<Value> {
    ensure!(
        !password.is_empty(),
        "Vault encryption password is required"
    );
    let (email, token) = parse_callback(pending, callback)?;
    let token = Zeroizing::new(token);
    let http = client()?;
    let (status, detected) = request(
        &http,
        Method::POST,
        "v4.1/auth/sso/firebase/detect_action/",
        None,
        Some(&json!({"firebase_token":&*token})),
    )
    .await?;
    if !status.is_success() {
        return Err(HttpStatus(status.as_u16()).into());
    }
    ensure!(
        detected["action"] != "sign-up",
        "Create the Termius account in the Termius app before signing in here"
    );
    let email = detected["email"]
        .as_str()
        .filter(|x| !x.is_empty())
        .unwrap_or(&email);
    ensure!(!email.is_empty(), "SSO did not return an account email");
    let token = detected["firebase_token"]
        .as_str()
        .filter(|x| !x.is_empty())
        .unwrap_or(&token);
    login(email, password, otp, Some(token)).await
}
pub async fn login_email(username: &str, password: &str, otp: Option<&str>) -> Result<Value> {
    ensure!(
        !username.is_empty() && !password.is_empty(),
        "Email and vault password are required"
    );
    login(username, password, otp, None).await
}

fn device(grpc: bool) -> Value {
    json!({"token":Uuid::new_v4().to_string(),"app_version":APP_VERSION,
        "os_version":std::env::consts::OS,"name":"Termius MCP Rust","sub_name":"",
        "mobile_type":if grpc {json!(3)} else {json!("Desktop")}})
}
async fn login(
    username: &str,
    password: &str,
    otp: Option<&str>,
    firebase: Option<&str>,
) -> Result<Value> {
    let payload = match timeout(
        Duration::from_secs(360),
        grpc_login(username, password, otp, firebase),
    )
    .await
    .map_err(|_| anyhow!("Termius SRP login timed out"))?
    {
        Ok(payload) => payload,
        Err(error) if error.downcast_ref::<NotMigrated>().is_some() => {
            rest_login(username, password, otp, firebase).await?
        }
        Err(error) => return Err(error),
    };
    normalize_session(username, &payload)
}
fn normalize_session(username: &str, payload: &Value) -> Result<Value> {
    let payload = snake_payload(payload);
    let credentials = payload
        .get("credentials")
        .filter(|value| value.as_object().is_some_and(|map| !map.is_empty()))
        .unwrap_or(&payload);
    let field = |name: &str| {
        credentials
            .get(name)
            .filter(|value| !value.is_null() && value.as_str() != Some(""))
            .or_else(|| {
                payload
                    .get(name)
                    .filter(|value| !value.is_null() && value.as_str() != Some(""))
            })
    };
    let token = field("token")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .context("Login response is missing DeviceToken")?;
    let salt = field("salt").context("Login response is missing salt")?;
    let hmac = field("hmac_salt").context("Login response is missing HMAC salt")?;
    let salt = bytes_field(salt)?;
    let hmac = bytes_field(hmac)?;
    ensure!(
        salt.len() == 8 && hmac.len() == 8,
        "Login response contains invalid vault salts"
    );
    let account = payload
        .pointer("/bulk_account/account")
        .or_else(|| payload.get("account"))
        .unwrap_or(&Value::Null);
    let schema = account
        .pointer("/feature_toggles/encryption_schema")
        .or_else(|| payload.get("encryption_schema"));
    let schema = match schema.and_then(Value::as_str) {
        Some("v5" | "2") => "v5",
        Some("v3" | "0" | "1" | "undefined") | None => {
            if schema.and_then(Value::as_i64) == Some(2) {
                "v5"
            } else {
                "v3"
            }
        }
        Some(_) => bail!("Unsupported Termius encryption schema"),
    };
    let mut session = json!({"username":username,"apikey":token,"token_type":"device",
        "salt":STANDARD.encode(salt),"hmac_salt":STANDARD.encode(hmac),"encryption_schema":schema,
        "is_team":payload.pointer("/bulk_account/team").or_else(||payload.get("team")).is_some_and(|x| x.is_object() && !x.as_object().unwrap().is_empty())});
    if let Some(id) = account.get("user_id") {
        session["user_id"] = id.clone();
    }
    if let Some(keys) = credentials["personal_keyset"].as_object() {
        for name in [
            "public_key",
            "encrypted_private_key",
            "encrypted_personal_key",
        ] {
            if let Some(value) = keys.get(name) {
                session[name] = if value.is_string() {
                    value.clone()
                } else {
                    json!(STANDARD.encode(bytes_field(value)?))
                };
            }
        }
    }
    Ok(session)
}
async fn rest_login(
    username: &str,
    password: &str,
    otp: Option<&str>,
    firebase: Option<&str>,
) -> Result<Value> {
    let http = client()?;
    let password_hash = format!("{:x}", Sha256::digest(password.as_bytes()));
    let mut payload = json!({"email":if firebase.is_some(){""}else{username},"password":password_hash,"device":device(false)});
    if let Some(otp) = otp {
        payload["authy_token"] = json!(otp);
    }
    if let Some(firebase) = firebase {
        payload["firebase_token"] = json!(firebase);
    }
    let (mut status, mut value) = request(
        &http,
        Method::POST,
        "v3.3/auth/device/login/",
        None,
        Some(&payload),
    )
    .await?;
    if !status.is_success()
        && firebase.is_none()
        && !matches!(status.as_u16(), 401 | 403 | 487 | 490)
    {
        let mut legacy = vec![("email", username), ("password", password_hash.as_str())];
        if let Some(otp) = otp {
            legacy.push(("authy_token", otp));
        }
        let response = http
            .post(format!("{API}v3.1/login/"))
            .form(&legacy)
            .send()
            .await
            .map_err(|_| anyhow!("Legacy Termius login request failed"))?;
        let result = response_json(response).await?;
        if result.0.is_success() {
            (status, value) = result;
        }
    }
    if status.as_u16() == 487 || matches!(value["code"].as_i64(), Some(3 | 10)) {
        bail!("OTP is required or invalid; retry login with an authenticator code");
    }
    if status.as_u16() == 490 {
        bail!("Termius Cloud rejected this client version");
    }
    if !status.is_success() {
        return Err(HttpStatus(status.as_u16()).into());
    }
    Ok(value)
}

fn snake_name(name: &str) -> String {
    let name = name
        .strip_suffix("List")
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    let chars: Vec<char> = name.chars().collect();
    let mut result = String::new();
    for (i, c) in chars.iter().enumerate() {
        if c.is_ascii_uppercase()
            && i > 0
            && (chars[i - 1].is_ascii_lowercase()
                || chars[i - 1].is_ascii_digit()
                || (chars[i - 1].is_ascii_uppercase()
                    && chars.get(i + 1).is_some_and(char::is_ascii_lowercase)))
        {
            result.push('_');
        }
        result.push(c.to_ascii_lowercase());
    }
    result
}
fn snake_payload(value: &Value) -> Value {
    match value {
        Value::Object(map) if value["type"] != "Buffer" => Value::Object(
            map.iter()
                .map(|(k, v)| (snake_name(k), snake_payload(v)))
                .collect(),
        ),
        Value::Array(rows) => Value::Array(rows.iter().map(snake_payload).collect()),
        _ => value.clone(),
    }
}
async fn send(socket: &mut Socket, text: String) -> Result<()> {
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|_| anyhow!("Termius login socket write failed"))
}
async fn next_packet(socket: &mut Socket, deadline: Instant) -> Result<String> {
    loop {
        let packet = timeout_at(deadline, socket.next())
            .await
            .map_err(|_| anyhow!("Termius login response timed out"))?
            .context("Termius login socket closed")?
            .map_err(|_| anyhow!("Termius login socket failed"))?;
        match packet {
            Message::Text(text) => {
                if let Some(suffix) = text.strip_prefix('2') {
                    send(socket, format!("3{suffix}")).await?;
                    continue;
                }
                if text.starts_with('1') || text.starts_with("41/login_v2") {
                    bail!("Termius login socket disconnected");
                }
                return Ok(text.to_string());
            }
            Message::Ping(bytes) => socket
                .send(Message::Pong(bytes))
                .await
                .map_err(|_| anyhow!("Termius login heartbeat failed"))?,
            Message::Close(_) => bail!("Termius login socket closed"),
            Message::Binary(_) => bail!("Unexpected binary login packet"),
            _ => {}
        }
    }
}
fn login_error(error: &Value) -> anyhow::Error {
    let code = error["code"].as_i64();
    let key = error["key"].as_str().unwrap_or("");
    if code == Some(7) || key == "NOT_MIGRATED" {
        return NotMigrated.into();
    }
    let message = match (code, key) {
        (Some(3 | 10), _) | (_, "OTP_TOKEN_REQUIRED" | "OTP_TOKEN_ERROR") => {
            "OTP is required or invalid; retry login with an authenticator code"
        }
        (Some(2), _) | (_, "UNAUTHENTICATED") => {
            "Termius authentication failed; for Google SSO start login again"
        }
        (Some(4), _) | (_, "THROTTLED") => "Termius login is throttled; wait and retry",
        (Some(6), _) | (_, "APP_OUTDATED") => "Termius Cloud rejected this client version",
        (Some(8), _) | (_, "INVALID_PROOF") => {
            "SRP proof was rejected; check your Termius vault encryption password"
        }
        (Some(9), _) | (_, "INVALID_PUBLIC_DATA") => "Termius Cloud rejected the SRP public value",
        (Some(12), _) | (_, "LOGIN_APPROVE_REQUIRED") => {
            "Approve this login in the Termius app, then retry"
        }
        _ => "Termius Cloud rejected the login handshake",
    };
    anyhow!(message)
}
async fn event(socket: &mut Socket, wanted: &str) -> Result<Value> {
    let deadline = Instant::now() + STAGE_TIMEOUT;
    loop {
        let packet = next_packet(socket, deadline).await?;
        if let Some(data) = packet.strip_prefix("42/login_v2,") {
            let values: Value =
                serde_json::from_str(data).map_err(|_| anyhow!("Malformed Termius login event"))?;
            let name = values[0].as_str().context("Missing login event name")?;
            if matches!(
                name,
                "grpc-error-response" | "grpc-stream-error" | "proxy-error" | "error"
            ) {
                return Err(login_error(&values[1]));
            }
            if name == wanted {
                ensure!(values[1].is_object(), "Malformed login event payload");
                return Ok(snake_payload(&values[1]));
            }
        } else if packet.starts_with("44") {
            bail!("Termius login namespace was rejected");
        }
    }
}
async fn grpc_login(
    username: &str,
    password: &str,
    otp: Option<&str>,
    firebase: Option<&str>,
) -> Result<Value> {
    let config = WebSocketConfig::default()
        .max_message_size(Some(MAX_WS))
        .max_frame_size(Some(MAX_WS));
    let (mut socket, _) = timeout(
        Duration::from_secs(30),
        connect_async_with_config(LOGIN_WS, Some(config), false),
    )
    .await
    .map_err(|_| anyhow!("Termius login socket connection timed out"))?
    .map_err(|_| anyhow!("Unable to connect to Termius login over TLS"))?;
    let opened = next_packet(&mut socket, Instant::now() + STAGE_TIMEOUT).await?;
    ensure!(opened.starts_with('0'), "Missing Engine.IO handshake");
    send(&mut socket, "40/login_v2,".to_owned()).await?;
    let deadline = Instant::now() + STAGE_TIMEOUT;
    loop {
        let packet = next_packet(&mut socket, deadline).await?;
        if packet.starts_with("40/login_v2,") {
            break;
        }
        if packet.starts_with("44") {
            bail!("Termius login namespace was rejected");
        }
    }
    let mut initial =
        json!({"email":if firebase.is_some(){""}else{username},"device":device(true)});
    if let Some(otp) = otp {
        initial["otp_token"] = json!(otp);
    }
    if let Some(firebase) = firebase {
        initial["firebase_token"] = json!(firebase);
    }
    send(
        &mut socket,
        format!("42/login_v2,{}", json!(["initialRequest", initial])),
    )
    .await?;
    let initial = event(&mut socket, "initialResponse").await?;
    let identifier = initial["identifier"]
        .as_str()
        .filter(|x| !x.is_empty())
        .unwrap_or(username)
        .to_owned();
    let salt = bytes_field(&initial["salt"])?;
    let server = initial["public_data"].clone();
    let pass = Zeroizing::new(password.to_owned());
    let session =
        tokio::task::spawn_blocking(move || SrpSession::new(&identifier, &pass, &salt, &server))
            .await
            .map_err(|_| anyhow!("SRP computation failed"))??;
    send(&mut socket,format!("42/login_v2,{}",json!(["finalRequest",{"public_data":session.public_value,"proof":session.client_proof}]))).await?;
    let mut final_response = event(&mut socket, "finalResponse").await?;
    // The Python implementation continued after a bad proof. Authentication must fail closed.
    session.validate_server_proof(&final_response["proof"])?;
    let salt = bytes_field(&final_response["session_salt"])?;
    let token = bytes_field(&final_response["credentials"]["token"])?;
    let token = tokio::task::spawn_blocking(move || session.unwrap_token(&salt, &token))
        .await
        .map_err(|_| anyhow!("DeviceToken decryption failed"))??;
    ensure!(!token.is_empty(), "Login returned an empty DeviceToken");
    final_response["credentials"]["token"] = json!(token);
    let _ = timeout(Duration::from_secs(2), socket.close(None)).await;
    Ok(final_response)
}

#[derive(Default)]
struct KeyRing {
    public: Option<[u8; 32]>,
    private: Option<Zeroizing<[u8; 32]>>,
    personal: Option<Zeroizing<[u8; 32]>>,
    vaults: HashMap<String, Zeroizing<[u8; 32]>>,
}
impl KeyRing {
    fn restore(session: &Value) -> Result<Self> {
        let read = |name: &str| -> Result<Option<[u8; 32]>> {
            session[name]
                .as_str()
                .filter(|x| !x.is_empty())
                .map(|text| key_bytes(&decode_b64(text)?))
                .transpose()
        };
        Ok(Self {
            public: read("public_key")?,
            private: read("private_key")?.map(Zeroizing::new),
            personal: read("personal_v4_key")?.map(Zeroizing::new),
            vaults: HashMap::new(),
        })
    }
    fn unwrap(&mut self, cryptor: &VaultCryptor, keys: &Value) -> Result<bool> {
        let Some(encrypted) = keys["encrypted_private_key"]
            .as_str()
            .filter(|x| !x.is_empty())
        else {
            return Ok(false);
        };
        let public = keys["public_key"]
            .as_str()
            .context("Personal keyset has no public key")?;
        let private = Zeroizing::new(key_bytes(&cryptor.decrypt_password_bytes(encrypted)?)?);
        let public = key_bytes(&decode_b64(public)?)?;
        ensure!(
            crypto_box::SecretKey::from(*private)
                .public_key()
                .as_bytes()
                == &public,
            "Personal keypair does not match"
        );
        let personal = if let Some(encrypted) = keys["encrypted_personal_key"]
            .as_str()
            .filter(|x| !x.is_empty())
        {
            let bytes = Zeroizing::new(crypto::box_open(
                &public,
                &private,
                &decode_b64(encrypted)?,
            )?);
            Some(Zeroizing::new(key_bytes(&bytes)?))
        } else {
            None
        };
        self.public = Some(public);
        self.private = Some(private);
        self.personal = personal;
        Ok(true)
    }
    fn load_vaults(&mut self, records: &Value) {
        let Some(private) = self.private.as_ref() else {
            return;
        };
        let rows = records.as_array().or_else(|| {
            ["objects", "keys", "results", "vault_keys"]
                .iter()
                .find_map(|key| records[*key].as_array())
        });
        let singleton = vec![records.clone()];
        for row in rows.unwrap_or(&singleton) {
            let result = (|| -> Result<[u8; 32]> {
                let public = key_bytes(&bytes_field(&row["encrypted_with"]["public_key"])?)?;
                let ciphertext = bytes_field(&row["encrypted_key"])?;
                // Do not accept unauthenticated raw 32-byte keys as an unwrap fallback.
                let bytes = Zeroizing::new(crypto::box_open(&public, private, &ciphertext)?);
                key_bytes(&bytes)
            })();
            if let Ok(key) = result {
                for name in ["original_key", "vault"] {
                    if let Some(id) = reference_key(&row[name]) {
                        self.vaults.insert(id, Zeroizing::new(key));
                    }
                }
            }
        }
    }
    fn persist(&self, session: &mut Value) {
        if let Some(key) = &self.public {
            session["public_key"] = json!(STANDARD.encode(key));
        }
        if let Some(key) = &self.private {
            session["private_key"] = json!(STANDARD.encode(**key));
        }
        if let Some(key) = &self.personal {
            session["personal_v4_key"] = json!(STANDARD.encode(**key));
        }
    }
}
fn reference_key(value: &Value) -> Option<String> {
    match value {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Object(m) => ["original_key", "id", "public_key"]
            .iter()
            .find_map(|k| m.get(*k).and_then(reference_key)),
        _ => None,
    }
}
fn crypto_fields(name: &str) -> &'static [&'static str] {
    match name {
        "host_set" => &["label", "address"],
        "group_set" | "tag_set" => &["label"],
        "identity_set" => &["label", "username", "password"],
        "sshkeycrypt_set" => &["label", "private_key", "public_key", "passphrase"],
        "snippet_set" => &["label", "script"],
        "knownhost_set" => &["hostnames", "key"],
        "pfrule_set" => &["label", "hostname"],
        _ => &[],
    }
}
fn decrypt_row(cryptor: &VaultCryptor, ring: &KeyRing, name: &str, row: &Value) -> Value {
    let Some(original) = row.as_object() else {
        return json!({"_undecryptable":true});
    };
    let result = (|| -> Result<Map<String, Value>> {
        let shared = row["is_shared"].as_bool().unwrap_or(false)
            || row.get("encrypted_with").is_some_and(|x| {
                !x.is_null()
                    && x.as_str() != Some("")
                    && x.as_object().is_none_or(|m| !m.is_empty())
            });
        let vault = if shared {
            Some(
                ring.vaults
                    .get(
                        &reference_key(&row["encrypted_with"])
                            .context("Shared entity has no vault key reference")?,
                    )
                    .context("Shared entity key is unavailable")?,
            )
        } else {
            None
        };
        let decrypt = |text: &str, required: bool| -> Result<Vec<u8>> {
            if let Some(key) = vault {
                crypto::secret_open(&**key, &decode_b64(text)?)
            } else if required {
                cryptor.decrypt_bytes(text)
            } else {
                Ok(cryptor.decrypt_field(text)?.into_bytes())
            }
        };
        let mut out = original.clone();
        if let Some(content) = row["content"].as_str().filter(|s| !s.is_empty()) {
            let decoded: Value = serde_json::from_slice(&decrypt(content, true)?)
                .map_err(|_| anyhow!("Invalid decrypted entity JSON"))?;
            let decoded = decoded
                .as_object()
                .context("Decrypted entity must be an object")?;
            for (key, value) in decoded {
                // Cloud identity and sharing ownership are envelope metadata, not encrypted fields.
                if matches!(
                    key.as_str(),
                    "id" | "encrypted_with" | "is_shared" | "_undecryptable"
                ) {
                    continue;
                }
                out.insert(key.clone(), value.clone());
            }
            out.remove("content");
        } else {
            for field in crypto_fields(name) {
                if let Some(text) = row[*field].as_str().filter(|s| !s.is_empty()) {
                    let plaintext = String::from_utf8(decrypt(text, false)?)
                        .map_err(|_| anyhow!("Decrypted entity text is not UTF-8"))?;
                    out.insert((*field).to_owned(), json!(plaintext));
                }
            }
        }
        Ok(out)
    })();
    match result {
        Ok(map) => Value::Object(map),
        Err(_) => {
            let mut out = original.clone();
            out.insert("_undecryptable".into(), json!(true));
            Value::Object(out)
        }
    }
}

/// Keyserver and team-key APIs are optional for personal inventories. Swallow
/// their errors without reflecting remote text, while retaining missing-key
/// markers on every shared row that cannot be authenticated.
fn optional_key_response(
    result: Result<Value>,
    description: &str,
    warnings: &mut Vec<String>,
) -> Option<Value> {
    match result {
        Ok(value) => Some(value),
        Err(_) => {
            warnings.push(format!("{description} could not be loaded; entities requiring those keys remain unavailable"));
            None
        }
    }
}

/// Pull a complete snapshot and refresh the session's settings and cached keys.
/// Pass a detached session copy and commit that updated session together with the
/// returned snapshot atomically, only after success. Do not persist one without
/// the other. Unreadable rows retain their IDs so route resolution fails closed.
pub async fn pull(session: &mut Value, password: &str) -> Result<Value> {
    ensure!(!password.is_empty(), "Vault password is required to sync");
    let token = session["apikey"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("Not signed in")?
        .to_owned();
    let token = Zeroizing::new(token);
    let salt = bytes_field(&session["salt"])?;
    let hmac = bytes_field(&session["hmac_salt"])?;
    let pass = Zeroizing::new(password.to_owned());
    let mut cryptor = tokio::task::spawn_blocking(move || VaultCryptor::new(&pass, &salt, &hmac))
        .await
        .map_err(|_| anyhow!("Vault key derivation failed"))??;
    let http = client()?;
    let mut ring = KeyRing::restore(session)?;
    let has_login_keys = ring.unwrap(&cryptor, session)?;
    let mut warnings = Vec::new();
    if !has_login_keys
        && ring.private.is_none()
        && let Some(keys) = optional_key_response(
            get(&http, "v3/keyserver/key/my/", &token).await,
            "Personal keyserver keys",
            &mut warnings,
        )
        && ring.unwrap(&cryptor, &keys).is_err()
    {
        warnings.push("Personal keyserver keys could not be authenticated; entities requiring those keys remain unavailable".to_owned());
    }
    if ring.private.is_some()
        && let Some(records) = optional_key_response(
            get(&http, "v4/team/vault/keys/", &token).await,
            "Team vault keys",
            &mut warnings,
        )
    {
        ring.load_vaults(&records);
    }
    if let Some(key) = &ring.personal {
        cryptor.set_personal_key(**key);
    }
    let settings = get(&http, "v3/setting/mobile/", &token).await?;
    let snapshot = match get(&http, "v4/terminal/sync/", &token).await {
        Ok(snapshot) => snapshot,
        Err(error) if is_missing(&error) => get(&http, "v3/terminal/bulk/", &token).await?,
        Err(error) => return Err(error),
    };
    ensure!(snapshot.is_object(), "Invalid Cloud inventory response");
    let mut snapshot = snapshot;
    let names: Vec<String> = snapshot
        .as_object()
        .unwrap()
        .keys()
        .filter(|key| key.ends_with("_set"))
        .cloned()
        .collect();
    let mut unreadable = 0usize;
    let sync_keys = settings["synchronize_key"].as_bool().unwrap_or(true);
    for name in names {
        let rows = snapshot[&name]
            .as_array()
            .context("Cloud inventory set is not an array")?;
        let decrypted: Vec<Value> = rows
            .iter()
            .map(|row| {
                if !sync_keys && matches!(name.as_str(), "identity_set" | "sshkeycrypt_set") {
                    json!({"id":row["id"],"_undecryptable":true})
                } else {
                    decrypt_row(&cryptor, &ring, &name, row)
                }
            })
            .collect();
        unreadable += decrypted
            .iter()
            .filter(|row| row["_undecryptable"] == true)
            .count();
        snapshot[&name] = Value::Array(decrypted);
    }
    snapshot["last_synced"] = snapshot
        .get("now")
        .or_else(|| snapshot.get("last_synced"))
        .cloned()
        .context("Cloud snapshot is missing its timestamp")?;
    snapshot["unreadable_entities"] = json!(unreadable);
    snapshot["sync_warnings"] = json!(warnings);
    session["settings"] = settings;
    ring.persist(session);
    Ok(snapshot)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn proto_names_and_session_schema() {
        let value = snake_payload(
            &json!({"hmacSalt":"x","personalKeyset":{"publicKey":"p"},"thingsList":[{"userId":1}]}),
        );
        assert_eq!(value["hmac_salt"], "x");
        assert_eq!(value["things"][0]["user_id"], 1);
        let payload = json!({"credentials":{"token":"fixture","salt":"AAAAAAAAAAA=","hmacSalt":"AAAAAAAAAAA="},
            "bulkAccount":{"account":{"featureToggles":{"encryptionSchema":2}}}});
        assert_eq!(
            normalize_session("sample@example.com", &payload).unwrap()["encryption_schema"],
            "v5"
        );
    }
    #[test]
    fn mixed_legacy_credentials_use_nonempty_top_level_fallbacks() {
        for credentials in [
            Value::Null,
            json!({}),
            json!({"token":"", "salt":null, "hmac_salt":""}),
        ] {
            let payload = json!({"credentials":credentials,"token":"fixture-device-token",
                "salt":"AAAAAAAAAAA=","hmac_salt":"AQEBAQEBAQE="});
            let session = normalize_session("fixture@example.com", &payload).unwrap();
            assert_eq!(session["apikey"], "fixture-device-token");
            assert_eq!(session["salt"], "AAAAAAAAAAA=");
            assert_eq!(session["hmac_salt"], "AQEBAQEBAQE=");
        }
    }
    #[test]
    fn optional_key_failures_preserve_personal_reads_and_fail_shared_closed() {
        let mut warnings = Vec::new();
        assert!(
            optional_key_response(
                Err(HttpStatus(403).into()),
                "Team vault keys",
                &mut warnings
            )
            .is_none()
        );
        assert!(
            optional_key_response(
                Err(anyhow!("network error containing fixture-token")),
                "Personal keyserver keys",
                &mut warnings
            )
            .is_none()
        );
        assert_eq!(warnings.len(), 2);
        assert!(!warnings.join(" ").contains("fixture-token"));
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/fixtures/crypto_vectors.json")).unwrap();
        let rn = &vectors["rncryptor"];
        let cryptor = VaultCryptor::new(
            rn["password"].as_str().unwrap(),
            &decode_b64(rn["salt"].as_str().unwrap()).unwrap(),
            &decode_b64(rn["hmac_salt"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        let ring = KeyRing::default();
        let personal = json!({"id":1,"label":rn["ciphertext"],"address":"192.0.2.10"});
        let readable = decrypt_row(&cryptor, &ring, "host_set", &personal);
        assert_eq!(readable["label"], rn["plaintext"]);
        assert!(readable.get("_undecryptable").is_none());
        let shared = json!({"id":2,"is_shared":true,"encrypted_with":7,"ssh_config":3,"content":vectors["entity"]["ciphertext"]});
        let unreadable = decrypt_row(&cryptor, &ring, "host_set", &shared);
        assert_eq!(unreadable["id"], 2);
        assert_eq!(unreadable["ssh_config"], 3);
        assert_eq!(unreadable["_undecryptable"], true);
    }
    #[test]
    fn sso_callback_requires_matching_state_and_expiry() {
        let mut pending = login_google_start().unwrap();
        let id = pending["request_id"].as_str().unwrap();
        let callback = format!(
            "termius://app/continue-sso?email=a%40example.com&firebaseToken=fixture-token&requestId={id}"
        );
        assert_eq!(
            parse_callback(&pending, &callback).unwrap().0,
            "a@example.com"
        );
        assert!(
            parse_callback(
                &pending,
                "termius://app/continue-sso?firebaseToken=x&requestId=wrong"
            )
            .is_err()
        );
        assert!(parse_callback(&pending, &callback.replace("termius://", "https://")).is_err());
        assert!(parse_callback(&pending, &format!("{callback}&requestId={id}")).is_err());
        pending["created_at"] = json!(0);
        assert!(parse_callback(&pending, &callback).is_err());
    }
    #[test]
    fn error_messages_do_not_reflect_remote_content() {
        let error = login_error(&json!({"code":8,"message":"secret-device-token"}));
        assert!(!error.to_string().contains("secret-device-token"));
        assert!(
            login_error(&json!({"code":7}))
                .downcast_ref::<NotMigrated>()
                .is_some()
        );
    }
    #[test]
    fn unreadable_shared_rows_keep_route_identifiers() {
        let cryptor = VaultCryptor::new("test", &[0; 8], &[1; 8]).unwrap();
        let row =
            json!({"id":9,"ssh_config":3,"is_shared":true,"encrypted_with":17,"content":"missing"});
        let result = decrypt_row(&cryptor, &KeyRing::default(), "host_set", &row);
        assert_eq!(result["id"], 9);
        assert_eq!(result["ssh_config"], 3);
        assert_eq!(result["_undecryptable"], true);
    }
    #[test]
    fn authenticated_shared_content_preserves_envelope_identity() {
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/fixtures/crypto_vectors.json")).unwrap();
        let cryptor = VaultCryptor::new("test", &[0; 8], &[1; 8]).unwrap();
        let mut ring = KeyRing::default();
        ring.vaults.insert(
            "17".into(),
            Zeroizing::new(
                key_bytes(&decode_b64(vectors["entity"]["key"].as_str().unwrap()).unwrap())
                    .unwrap(),
            ),
        );
        let row = json!({"id":9,"is_shared":true,"encrypted_with":17,"content":vectors["entity"]["ciphertext"]});
        let result = decrypt_row(&cryptor, &ring, "host_set", &row);
        assert_eq!(result["id"], 9);
        assert_eq!(result["label"], "fixture shared host");
        assert_eq!(result["ssh_config"], 7);
        assert!(result.get("content").is_none());
        let mut row = row;
        row["content"] = json!("BAE=malformed");
        assert_eq!(
            decrypt_row(&cryptor, &ring, "host_set", &row)["_undecryptable"],
            true
        );
    }
    #[tokio::test]
    async fn socket_event_handles_engineio_heartbeats() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            ws.send(Message::Text("2heartbeat".into())).await.unwrap();
            assert_eq!(
                ws.next().await.unwrap().unwrap().into_text().unwrap(),
                "3heartbeat"
            );
            ws.send(Message::Text(
                "42/login_v2,[\"initialResponse\",{\"publicData\":\"DEADBEEF\"}]".into(),
            ))
            .await
            .unwrap();
        });
        let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
            .await
            .unwrap();
        let payload = event(&mut socket, "initialResponse").await.unwrap();
        assert_eq!(payload["public_data"], "DEADBEEF");
        server.await.unwrap();
    }
    #[tokio::test]
    async fn socket_error_only_not_migrated_allows_legacy_fallback() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
            ws.send(Message::Text(
                "42/login_v2,[\"grpc-error-response\",{\"code\":7,\"message\":\"secret\"}]".into(),
            ))
            .await
            .unwrap();
        });
        let (mut socket, _) = tokio_tungstenite::connect_async(format!("ws://{address}"))
            .await
            .unwrap();
        let error = event(&mut socket, "initialResponse").await.unwrap_err();
        assert!(error.downcast_ref::<NotMigrated>().is_some());
        assert!(!error.to_string().contains("secret"));
        server.await.unwrap();
    }
}
