pub mod cloud;
pub mod crypto;
pub mod inventory;
pub mod protocol;
pub mod ssh;
pub mod storage;
pub mod tools;

/// Credentials are deliberately not Debug/Serialize to prevent accidental disclosure.
#[derive(Clone)]
pub struct Endpoint {
    pub address: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    pub private_key: Option<String>,
    pub passphrase: Option<String>,
    pub strict_host_key_check: bool,
    /// OpenSSH public key strings (algorithm and base64 blob).
    pub known_host_keys: Vec<String>,
    pub connect_timeout: u64,
    pub keep_alive: u32,
}

#[derive(Clone)]
pub struct ConnectionSpec {
    pub host_id: serde_json::Value,
    pub label: String,
    pub target: Endpoint,
    pub jumps: Vec<Endpoint>,
}
