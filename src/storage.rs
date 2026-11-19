//! Versioned, authenticated local state with atomic writes and optimistic concurrency.
//!
//! This store intentionally does not read or change the Python application's ~/.termius.
//! A separate random master key is kept in the OS credential store where available.
//! Headless installations use a mode-0600 key file, or TERMIUS_SECRETS_KEY. Possession
//! of both the state file and the headless key file permits decryption.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use anyhow::{Context, Result, anyhow, bail};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use fs2::FileExt;
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zeroize::Zeroizing;

const FORMAT: &str = "termius-mcp-rs/state/1";
const MAX_STATE_BYTES: u64 = 128 * 1024 * 1024;
const STATE_FILE: &str = "state";
const KEY_FILE: &str = "state.key";

#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct StoredState {
    pub session: Option<Value>,
    pub vault_password: Option<String>,
    pub inventory: Value,
    pub last_synced: Option<String>,
    pub pending_sso: Option<Value>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    format: String,
    backend: String,
    salt: String,
    revision: u64,
    nonce: String,
    ciphertext: String,
}

/// Secrets are deliberately excluded from Debug, and derived keys zeroize on drop.
pub struct Store {
    pub state: StoredState,
    pub directory: PathBuf,
    key: Zeroizing<[u8; 32]>,
    backend: String,
    salt: String,
    revision: AtomicU64,
}

fn sensitive_open(path: &Path, write: bool, create_new: bool) -> Result<File> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        bail!("Local state files must not be symbolic links");
    }
    let mut options = OpenOptions::new();
    options.read(true).write(write).create_new(create_new);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).context("Cannot open local state file")?;
    let metadata = file.metadata().context("Cannot inspect local state file")?;
    if !metadata.is_file() {
        bail!("Local state path is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            bail!("Local state file belongs to another user");
        }
        if metadata.mode() & 0o077 != 0 {
            bail!("Local state files must be private (chmod 600)");
        }
        if metadata.nlink() != 1 {
            bail!("Local state files must not have hard links");
        }
    }
    Ok(file)
}

fn ensure_directory(directory: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(directory) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                bail!("Local state directory must be a real directory, not a symbolic link");
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder
                .create(directory)
                .context("Cannot create local state directory")?;
        }
        Err(_) => bail!("Cannot inspect local state directory"),
    }
    let metadata =
        fs::symlink_metadata(directory).context("Cannot inspect local state directory")?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("Invalid local state directory");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != rustix::process::geteuid().as_raw() {
            bail!("Local state directory belongs to another user");
        }
        if metadata.mode() & 0o077 != 0 {
            bail!("Local state directory must be private (chmod 700)");
        }
    }
    directory
        .canonicalize()
        .context("Cannot resolve local state directory")
}

fn lock(directory: &Path) -> Result<File> {
    let path = directory.join("state.lock");
    let file = match sensitive_open(&path, true, true) {
        Ok(file) => file,
        Err(_) => sensitive_open(&path, true, false)?,
    };
    // Avoid an unbounded startup/status wait if another process is stuck.
    file.try_lock_exclusive()
        .map_err(|_| anyhow!("Another Termius process is updating local state; retry shortly"))?;
    Ok(file)
}

fn read_bytes(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = sensitive_open(path, false, false)?;
    if file.metadata()?.len() > maximum {
        bail!("Local state file exceeds the size limit");
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1)
        .read_to_end(&mut bytes)
        .context("Cannot read local state file")?;
    if bytes.len() as u64 > maximum {
        bail!("Local state file exceeds the size limit");
    }
    Ok(bytes)
}

fn existing_envelope(directory: &Path) -> Result<Option<Envelope>> {
    let path = directory.join(STATE_FILE);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => bail!("Cannot inspect encrypted local state"),
        Ok(_) => {}
    }
    let envelope: Envelope =
        serde_json::from_slice(&read_bytes(&path, MAX_STATE_BYTES)?).map_err(|_| {
            anyhow!("Encrypted local state has an invalid format; the original file was preserved")
        })?;
    if envelope.format != FORMAT
        || !matches!(envelope.backend.as_str(), "passphrase" | "keyring" | "file")
    {
        bail!("Unsupported encrypted local state format; the original file was preserved");
    }
    if STANDARD.decode(&envelope.salt).ok().map(|v| v.len()) != Some(16) {
        bail!("Invalid local state salt; the original file was preserved");
    }
    Ok(Some(envelope))
}

fn derive_key(secret: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(65_536, 3, 1, Some(32))
        .map_err(|_| anyhow!("Invalid storage key derivation parameters"))?;
    let mut key = Zeroizing::new([0_u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(secret, salt, &mut *key)
        .map_err(|_| anyhow!("Could not derive local storage key"))?;
    Ok(key)
}

fn keyring_entry(directory: &Path) -> Result<keyring::Entry> {
    let service = format!("termius-mcp-rs:{}", directory.display());
    keyring::Entry::new(&service, "storage-key")
        .map_err(|_| anyhow!("OS credential store is unavailable"))
}

fn keyring_secret(directory: &Path, create: bool) -> Result<Zeroizing<Vec<u8>>> {
    let entry = keyring_entry(directory)?;
    match entry.get_password() {
        Ok(encoded) => {
            let encoded = Zeroizing::new(encoded);
            let bytes = Zeroizing::new(
                STANDARD
                    .decode(encoded.as_bytes())
                    .map_err(|_| anyhow!("OS credential store has an invalid storage key"))?,
            );
            if bytes.len() != 32 {
                bail!("OS credential store has an invalid storage key");
            }
            Ok(bytes)
        }
        Err(keyring::Error::NoEntry) if create => {
            let mut secret = Zeroizing::new(vec![0_u8; 32]);
            OsRng.fill_bytes(&mut secret);
            let encoded = Zeroizing::new(STANDARD.encode(&*secret));
            entry
                .set_password(&encoded)
                .map_err(|_| anyhow!("Cannot save the master key in the OS credential store"))?;
            Ok(secret)
        }
        Err(keyring::Error::NoEntry) => bail!(
            "The OS credential store no longer contains this vault's master key; local state was preserved"
        ),
        Err(_) => bail!("Cannot unlock the OS credential store; local state was preserved"),
    }
}

fn file_secret(directory: &Path, create: bool) -> Result<Zeroizing<Vec<u8>>> {
    let path = directory.join(KEY_FILE);
    if create
        && !path
            .try_exists()
            .context("Cannot inspect local storage key")?
    {
        let mut secret = Zeroizing::new(vec![0_u8; 32]);
        OsRng.fill_bytes(&mut secret);
        let mut file = sensitive_open(&path, true, true)?;
        file.write_all(&secret)
            .context("Cannot write local storage key")?;
        file.sync_all()
            .context("Cannot persist local storage key")?;
        sync_directory(directory)?;
        return Ok(secret);
    }
    let secret = Zeroizing::new(
        read_bytes(&path, 32)
            .context("The local master key is missing or unreadable; local state was preserved")?,
    );
    if secret.len() != 32 {
        bail!("Invalid local storage key; local state was preserved");
    }
    Ok(secret)
}

fn keyring_likely_available() -> bool {
    cfg!(target_os = "macos")
        || cfg!(target_os = "windows")
        || std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some()
}

fn select_secret(
    directory: &Path,
    stored_backend: Option<&str>,
    supplied: Option<&str>,
    keyring_override: Option<&str>,
) -> Result<(String, Zeroizing<Vec<u8>>)> {
    if supplied == Some("") {
        bail!("TERMIUS_SECRETS_KEY must not be empty");
    }
    if !matches!(keyring_override, None | Some("0" | "1")) {
        bail!("TERMIUS_KEYRING must be 0 or 1");
    }
    if let Some(backend) = stored_backend {
        if backend != "passphrase" && supplied.is_some() {
            bail!(
                "This state uses another key backend; do not change TERMIUS_SECRETS_KEY without migrating the state directory"
            );
        }
        if (backend == "keyring" && keyring_override == Some("0"))
            || (backend == "file" && keyring_override == Some("1"))
        {
            bail!(
                "TERMIUS_KEYRING conflicts with the saved key backend; the original state was preserved"
            );
        }
        let secret = match backend {
            "passphrase" => Zeroizing::new(
                supplied
                    .context("TERMIUS_SECRETS_KEY is required to open this encrypted state")?
                    .as_bytes()
                    .to_vec(),
            ),
            "keyring" => keyring_secret(directory, false)?,
            "file" => file_secret(directory, false)?,
            _ => bail!("Unsupported storage key backend"),
        };
        return Ok((backend.into(), secret));
    }
    if let Some(secret) = supplied {
        return Ok((
            "passphrase".into(),
            Zeroizing::new(secret.as_bytes().to_vec()),
        ));
    }
    if keyring_override == Some("1") {
        return Ok(("keyring".into(), keyring_secret(directory, true)?));
    }
    if keyring_override != Some("0")
        && keyring_likely_available()
        && let Ok(secret) = keyring_secret(directory, true)
    {
        return Ok(("keyring".into(), secret));
    }
    Ok(("file".into(), file_secret(directory, true)?))
}

fn aad(backend: &str, salt: &str, revision: u64) -> String {
    format!("{FORMAT}\0{backend}\0{salt}\0{revision}")
}

fn decrypt(envelope: &Envelope, key: &[u8; 32]) -> Result<StoredState> {
    let nonce = STANDARD
        .decode(&envelope.nonce)
        .map_err(|_| anyhow!("Invalid encrypted local state nonce"))?;
    if nonce.len() != 24 {
        bail!("Invalid encrypted local state nonce");
    }
    let ciphertext = STANDARD
        .decode(&envelope.ciphertext)
        .map_err(|_| anyhow!("Invalid encrypted local state ciphertext"))?;
    let aad = aad(&envelope.backend, &envelope.salt, envelope.revision);
    let plaintext = Zeroizing::new(XChaCha20Poly1305::new(key.into()).decrypt(XNonce::from_slice(&nonce), Payload { msg: &ciphertext, aad: aad.as_bytes() }).map_err(|_| anyhow!("Cannot decrypt local state: wrong key or damaged data; the original file was preserved"))?);
    serde_json::from_slice(&plaintext).map_err(|_| {
        anyhow!("Invalid decrypted local state format; the original file was preserved")
    })
}

fn sync_directory(directory: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(directory)
            .and_then(|file| file.sync_all())
            .context("Cannot persist local state directory")?;
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
    }
    Ok(())
}

impl Store {
    pub fn open(directory: PathBuf) -> Result<Self> {
        let passphrase = match std::env::var("TERMIUS_SECRETS_KEY") {
            Ok(value) => Some(Zeroizing::new(value)),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => bail!("TERMIUS_SECRETS_KEY must be valid UTF-8"),
        };
        let keyring_override = std::env::var("TERMIUS_KEYRING").ok();
        Self::open_with(
            directory,
            passphrase.as_deref().map(|v| v.as_str()),
            keyring_override.as_deref(),
        )
    }

    /// Open with explicit key settings instead of reading process environment.
    pub fn open_with(
        directory: PathBuf,
        passphrase: Option<&str>,
        keyring_override: Option<&str>,
    ) -> Result<Self> {
        let directory = ensure_directory(&directory)?;
        let _lock = lock(&directory)?;
        let envelope = existing_envelope(&directory)?;
        let (backend, secret) = select_secret(
            &directory,
            envelope.as_ref().map(|v| v.backend.as_str()),
            passphrase,
            keyring_override,
        )?;
        let salt = if let Some(envelope) = &envelope {
            envelope.salt.clone()
        } else {
            let mut salt = [0_u8; 16];
            OsRng.fill_bytes(&mut salt);
            STANDARD.encode(salt)
        };
        let key = derive_key(
            &secret,
            &STANDARD.decode(&salt).context("Invalid storage salt")?,
        )?;
        let (state, revision) = if let Some(envelope) = &envelope {
            (decrypt(envelope, &key)?, envelope.revision)
        } else {
            (StoredState::default(), 0)
        };
        let store = Self {
            state,
            directory,
            key,
            backend,
            salt,
            revision: AtomicU64::new(revision),
        };
        // Persist the backend and salt before releasing the first-open lock so
        // independently launched MCP/CLI processes derive the same storage key.
        if envelope.is_none() {
            store.save_locked()?;
        }
        Ok(store)
    }

    /// Refreshes other-process changes without repeating the expensive key derivation.
    pub fn reload(&mut self) -> Result<()> {
        let _lock = lock(&self.directory)?;
        let envelope = existing_envelope(&self.directory)?;
        match envelope {
            Some(envelope) => {
                if envelope.backend != self.backend || envelope.salt != self.salt {
                    bail!("Local state key parameters changed; restart this process");
                }
                let state = decrypt(&envelope, &self.key)?;
                self.state = state;
                self.revision.store(envelope.revision, Ordering::Relaxed);
            }
            None if self.revision.load(Ordering::Relaxed) != 0 => {
                bail!("Local state disappeared; restart this process before making changes")
            }
            None => {
                self.state = StoredState::default();
            }
        }
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        let _lock = lock(&self.directory)?;
        self.save_locked()
    }

    fn save_locked(&self) -> Result<()> {
        let revision = self.revision.load(Ordering::Relaxed);
        match existing_envelope(&self.directory)? {
            Some(envelope) => {
                if envelope.backend != self.backend || envelope.salt != self.salt {
                    bail!("Local state key parameters changed; restart this process");
                }
                // Authenticate the revision before using it as a concurrency token.
                decrypt(&envelope, &self.key)?;
                if envelope.revision != revision {
                    bail!("Local state changed in another process; reload and retry");
                }
            }
            None if revision != 0 => bail!("Local state disappeared; refusing to overwrite it"),
            None => {}
        }
        let next = revision
            .checked_add(1)
            .context("Local state revision is exhausted")?;
        let plain = Zeroizing::new(
            serde_json::to_vec(&self.state).context("Cannot serialize local state")?,
        );
        if plain.len() as u64 > MAX_STATE_BYTES / 2 {
            bail!("Local state exceeds the size limit");
        }
        let mut nonce = [0_u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let aad = aad(&self.backend, &self.salt, next);
        let ciphertext = XChaCha20Poly1305::new((&*self.key).into())
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: aad.as_bytes(),
                },
            )
            .map_err(|_| anyhow!("Cannot encrypt local state"))?;
        let envelope = Envelope {
            format: FORMAT.into(),
            backend: self.backend.clone(),
            salt: self.salt.clone(),
            revision: next,
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        };
        let bytes =
            serde_json::to_vec(&envelope).context("Cannot serialize encrypted local state")?;
        let mut random = [0_u8; 16];
        OsRng.fill_bytes(&mut random);
        let name = random
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let temp = self.directory.join(format!(".state-{name}.tmp"));
        let result = (|| -> Result<()> {
            let mut file = sensitive_open(&temp, true, true)?;
            file.write_all(&bytes)
                .context("Cannot write encrypted local state")?;
            file.sync_all()
                .context("Cannot persist encrypted local state")?;
            // A symlink appearing in place of state is never followed by rename;
            // the exclusive directory and lock prevent cooperating writer races.
            fs::rename(&temp, self.directory.join(STATE_FILE))
                .context("Cannot replace encrypted local state")?;
            sync_directory(&self.directory)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result?;
        self.revision.store(next, Ordering::Relaxed);
        Ok(())
    }

    pub fn clear(&mut self) -> Result<()> {
        let old = std::mem::take(&mut self.state);
        if let Err(error) = self.save() {
            self.state = old;
            return Err(error);
        }
        Ok(())
    }

    pub fn backend(&self) -> &str {
        &self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encrypted_roundtrip_wrong_password_and_corruption_preserve_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = Store::open_with(
            temp.path().join("vault"),
            Some("correct test passphrase"),
            Some("0"),
        )
        .unwrap();
        store.state.session =
            Some(json!({"username":"example@example.com","apikey":"fixture-device-token"}));
        store.state.vault_password = Some("fixture-vault-password".into());
        store.save().unwrap();
        let path = store.directory.join(STATE_FILE);
        let original = fs::read(&path).unwrap();
        let text = String::from_utf8(original.clone()).unwrap();
        assert!(!text.contains("fixture-device-token"));
        assert!(!text.contains("fixture-vault-password"));
        drop(store);
        let opened = Store::open_with(
            temp.path().join("vault"),
            Some("correct test passphrase"),
            Some("0"),
        )
        .unwrap();
        assert_eq!(
            opened.state.vault_password.as_deref(),
            Some("fixture-vault-password")
        );
        drop(opened);
        assert!(
            Store::open_with(
                temp.path().join("vault"),
                Some("wrong test passphrase"),
                Some("0")
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), original);
        let mut corrupted: Value = serde_json::from_slice(&original).unwrap();
        corrupted["revision"] = json!(9000);
        fs::write(&path, serde_json::to_vec(&corrupted).unwrap()).unwrap();
        let damaged = fs::read(&path).unwrap();
        assert!(
            Store::open_with(
                temp.path().join("vault"),
                Some("correct test passphrase"),
                Some("0")
            )
            .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), damaged);
    }

    #[test]
    fn concurrent_writers_cannot_lose_saved_changes() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("vault");
        let first = Store::open_with(dir.clone(), None, Some("0")).unwrap();
        first.save().unwrap();
        let mut second = Store::open_with(dir, None, Some("0")).unwrap();
        first.save().unwrap();
        second.state.vault_password = Some("new secret".into());
        assert!(second.save().is_err());
        second.reload().unwrap();
        assert!(second.state.vault_password.is_none());
        second.state.vault_password = Some("new secret".into());
        second.save().unwrap();
    }

    #[test]
    fn removing_key_never_reinitializes_existing_encrypted_state() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("vault");
        let store = Store::open_with(dir.clone(), None, Some("0")).unwrap();
        store.save().unwrap();
        drop(store);
        let original = fs::read(dir.join(STATE_FILE)).unwrap();
        fs::remove_file(dir.join(KEY_FILE)).unwrap();
        assert!(Store::open_with(dir.clone(), None, Some("0")).is_err());
        assert_eq!(fs::read(dir.join(STATE_FILE)).unwrap(), original);
        assert!(!dir.join(KEY_FILE).exists());
    }

    #[test]
    fn clear_persists_empty_state_and_keeps_encryption() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("vault");
        let mut store = Store::open_with(dir.clone(), None, Some("0")).unwrap();
        store.state.vault_password = Some("forgotten secret".into());
        store.save().unwrap();
        store.clear().unwrap();
        drop(store);
        let store = Store::open_with(dir, None, Some("0")).unwrap();
        assert!(store.state.vault_password.is_none());
        assert!(store.state.session.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn permissions_and_symlink_rejection() {
        use std::os::unix::fs::{MetadataExt, symlink};
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("vault");
        let store = Store::open_with(dir.clone(), None, Some("0")).unwrap();
        store.save().unwrap();
        drop(store);
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        for file in [STATE_FILE, KEY_FILE, "state.lock"] {
            assert_eq!(fs::metadata(dir.join(file)).unwrap().mode() & 0o777, 0o600);
        }
        let original = fs::read(dir.join(STATE_FILE)).unwrap();
        let outside = temp.path().join("outside");
        fs::rename(dir.join(STATE_FILE), &outside).unwrap();
        symlink(&outside, dir.join(STATE_FILE)).unwrap();
        assert!(Store::open_with(dir.clone(), None, Some("0")).is_err());
        assert_eq!(fs::read(&outside).unwrap(), original);
        let alias = temp.path().join("alias");
        symlink(&dir, &alias).unwrap();
        assert!(Store::open_with(alias, None, Some("0")).is_err());
    }
}
