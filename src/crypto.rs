//! Wire-compatible Termius cryptography. The Sodium envelope uses XSalsa20,
//! not XChaCha20; these names matter for interoperability with desktop 10.0.6.
use aes::Aes256;
use anyhow::{Context, Result, anyhow, bail, ensure};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine, engine::general_purpose::STANDARD};
use blake2::{Blake2b512, Digest};
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use crypto_box::{PublicKey, SalsaBox, SecretKey};
use crypto_secretbox::{
    Nonce, XSalsa20Poly1305,
    aead::{Aead, KeyInit},
};
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use rand::{RngCore, rngs::OsRng};
use serde_json::Value;
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub fn decode_b64(text: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(text)
        .map_err(|_| anyhow!("Invalid base64 encoding"))
}

/// Proto-JSON bytes may arrive as base64, a byte array, or a Node Buffer.
pub fn bytes_field(value: &Value) -> Result<Vec<u8>> {
    if let Some(text) = value.as_str() {
        return decode_b64(text);
    }
    let values = value
        .as_array()
        .or_else(|| {
            (value["type"] == "Buffer")
                .then(|| value["data"].as_array())
                .flatten()
        })
        .context("Missing or malformed byte field")?;
    values
        .iter()
        .map(|v| {
            v.as_u64()
                .filter(|n| *n <= 255)
                .map(|n| n as u8)
                .context("Invalid byte value")
        })
        .collect()
}

pub fn key_bytes(raw: &[u8]) -> Result<[u8; 32]> {
    if raw.len() == 32 {
        return Ok(raw.try_into().expect("checked length"));
    }
    let bytes = STANDARD
        .decode(raw)
        .map_err(|_| anyhow!("Invalid key encoding"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("Key must contain 32 bytes"))
}

/// libsodium crypto_pwhash Argon2id13 INTERACTIVE: t=2, m=64 MiB, p=1.
pub fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    ensure!(salt.len() == 16, "Argon2id salt must contain 16 bytes");
    let params =
        Params::new(65_536, 2, 1, Some(32)).map_err(|_| anyhow!("Invalid Argon2id parameters"))?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, &mut *key)
        .map_err(|_| anyhow!("Password key derivation failed"))?;
    Ok(key)
}

fn envelope(raw: &[u8], kind: u8) -> Result<(&[u8], &[u8])> {
    ensure!(raw.len() >= 42, "Incomplete Sodium ciphertext");
    ensure!(
        matches!(raw[0], 3 | 4),
        "Unsupported Sodium ciphertext version"
    );
    ensure!(raw[1] == kind, "Unexpected Sodium envelope type");
    Ok((&raw[2..26], &raw[26..]))
}

pub fn secret_open(key: &[u8], raw: &[u8]) -> Result<Vec<u8>> {
    let (nonce, body) = envelope(raw, 1)?;
    let cipher = XSalsa20Poly1305::new_from_slice(key)
        .map_err(|_| anyhow!("Secret key must contain 32 bytes"))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), body)
        .map_err(|_| anyhow!("Sodium ciphertext authentication failed"))
}

pub fn box_open(public: &[u8; 32], private: &[u8; 32], raw: &[u8]) -> Result<Vec<u8>> {
    let (nonce, body) = envelope(raw, 2)?;
    let cipher = SalsaBox::new(&PublicKey::from(*public), &SecretKey::from(*private));
    cipher
        .decrypt(Nonce::from_slice(nonce), body)
        .map_err(|_| anyhow!("Wrapped key authentication failed"))
}

pub struct VaultCryptor {
    encryption_salt: [u8; 8],
    hmac_salt: [u8; 8],
    encryption_key: Zeroizing<[u8; 32]>,
    hmac_key: Zeroizing<[u8; 32]>,
    password_key: Zeroizing<[u8; 32]>,
    personal_key: Option<Zeroizing<[u8; 32]>>,
}

impl VaultCryptor {
    pub fn new(password: &str, encryption_salt: &[u8], hmac_salt: &[u8]) -> Result<Self> {
        ensure!(
            encryption_salt.len() == 8 && hmac_salt.len() == 8,
            "Vault salts must each contain 8 bytes"
        );
        let mut enc = Zeroizing::new([0u8; 32]);
        let mut mac = Zeroizing::new([0u8; 32]);
        pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), encryption_salt, 10_000, &mut *enc);
        pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), hmac_salt, 10_000, &mut *mac);
        let salt = [encryption_salt, hmac_salt].concat();
        Ok(Self {
            encryption_salt: encryption_salt.try_into().expect("checked length"),
            hmac_salt: hmac_salt.try_into().expect("checked length"),
            encryption_key: enc,
            hmac_key: mac,
            password_key: derive_key(password.as_bytes(), &salt)?,
            personal_key: None,
        })
    }

    pub fn set_personal_key(&mut self, key: [u8; 32]) {
        self.personal_key = Some(Zeroizing::new(key));
    }

    pub fn decrypt_password_bytes(&self, text: &str) -> Result<Vec<u8>> {
        let raw = decode_b64(text)?;
        if raw.first() == Some(&4) {
            secret_open(&*self.password_key, &raw)
        } else {
            self.decrypt_rn(&raw)
        }
    }

    pub fn decrypt_bytes(&self, text: &str) -> Result<Vec<u8>> {
        let raw = decode_b64(text)?;
        match raw.first() {
            Some(4) => secret_open(
                &**self.personal_key.as_ref().unwrap_or(&self.password_key),
                &raw,
            ),
            Some(3) => self.decrypt_rn(&raw),
            _ => bail!("Unsupported vault ciphertext version"),
        }
    }

    /// Preserve genuine plaintext fields, but never fall back after a recognized
    /// encrypted envelope fails authentication.
    pub fn decrypt_field(&self, text: &str) -> Result<String> {
        if !looks_encrypted(text) {
            return Ok(text.to_owned());
        }
        let raw = self.decrypt_bytes(text)?;
        String::from_utf8(raw).map_err(|_| anyhow!("Vault text is not UTF-8"))
    }

    fn decrypt_rn(&self, raw: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            raw.len() >= 82 && raw[0] == 3 && raw[1] == 1,
            "Invalid RNCryptor v3 envelope"
        );
        ensure!(
            (raw.len() - 66).is_multiple_of(16),
            "Invalid RNCryptor ciphertext length"
        );
        ensure!(
            raw[2..10] == self.encryption_salt && raw[10..18] == self.hmac_salt,
            "RNCryptor vault salts do not match"
        );
        let split = raw.len() - 32;
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&*self.hmac_key)
            .expect("HMAC accepts a 32-byte key");
        mac.update(&raw[..split]);
        mac.verify_slice(&raw[split..])
            .map_err(|_| anyhow!("RNCryptor ciphertext authentication failed"))?;
        cbc::Decryptor::<Aes256>::new_from_slices(&*self.encryption_key, &raw[18..34])
            .expect("validated AES key and IV lengths")
            .decrypt_padded_vec_mut::<Pkcs7>(&raw[34..split])
            .map_err(|_| anyhow!("Invalid RNCryptor padding"))
    }
}

pub fn looks_encrypted(text: &str) -> bool {
    text.len() >= 56
        && matches!(text.as_bytes().first(), Some(b'A' | b'B'))
        && STANDARD
            .decode(text)
            .is_ok_and(|raw| raw.len() >= 42 && matches!(raw[0], 3 | 4))
}

fn hash(parts: &[&[u8]]) -> Vec<u8> {
    let mut digest = Blake2b512::new();
    for part in parts {
        digest.update(part);
    }
    digest.finalize().to_vec()
}
fn group() -> BigUint {
    BigUint::parse_bytes(include_str!("srp_group.hex").trim().as_bytes(), 16)
        .expect("fixed RFC 5054 group")
}
fn pad(n: &BigUint, size: usize) -> Result<Vec<u8>> {
    let bytes = n.to_bytes_be();
    ensure!(bytes.len() <= size, "SRP integer exceeds group size");
    let mut out = vec![0u8; size - bytes.len()];
    out.extend(bytes);
    Ok(out)
}
fn minimal(n: &BigUint) -> Vec<u8> {
    let bytes = n.to_bytes_be();
    if bytes.is_empty() { vec![0] } else { bytes }
}
fn parse_integer(value: &Value) -> Result<BigUint> {
    if let Some(number) = value.as_u64() {
        return Ok(BigUint::from(number));
    }
    if let Some(text) = value.as_str() {
        let text = text.trim();
        let stripped = text.strip_prefix("0x").or_else(|| text.strip_prefix("0X"));
        if stripped.is_some() || (text.len() >= 8 && text.bytes().all(|c| c.is_ascii_hexdigit())) {
            return BigUint::parse_bytes(stripped.unwrap_or(text).as_bytes(), 16)
                .context("Invalid SRP hexadecimal value");
        }
        let decoded = match decode_b64(text) {
            Ok(decoded) => decoded,
            // Match Botan's short hexadecimal fallback when a string cannot be
            // base64-decoded (e.g. "AB"). A successful base64 decode wins.
            Err(_) => {
                return BigUint::parse_bytes(text.as_bytes(), 16)
                    .context("Invalid SRP integer encoding");
            }
        };
        if let Some(hex) = decoded
            .strip_prefix(b"0x")
            .or_else(|| decoded.strip_prefix(b"0X"))
        {
            return BigUint::parse_bytes(hex, 16).context("Invalid SRP hexadecimal value");
        }
        // A base64 string containing bare ASCII hex is still raw binary in the
        // Python wire contract. Only Buffer/list values receive the sniff below.
        return Ok(BigUint::from_bytes_be(&decoded));
    }
    let decoded = bytes_field(value)?;
    let stripped = decoded.trim_ascii();
    let hex = stripped
        .strip_prefix(b"0x")
        .or_else(|| stripped.strip_prefix(b"0X"));
    if hex.is_some() || (stripped.len() >= 8 && stripped.iter().all(u8::is_ascii_hexdigit)) {
        return BigUint::parse_bytes(hex.unwrap_or(stripped), 16)
            .context("Invalid SRP hexadecimal value");
    }
    Ok(BigUint::from_bytes_be(&decoded))
}
fn wire(n: &BigUint) -> String {
    let mut s = n.to_str_radix(16).to_uppercase();
    if !s.len().is_multiple_of(2) {
        s.insert(0, '0');
    }
    s
}

/// Botan-compatible SRP-6a: RFC 5054 8192-bit group and Blake2b-512.
/// This is kept separate from transport for reproducible interoperability tests.
pub struct SrpSession {
    pub public_value: String,
    pub client_proof: String,
    session_key: Zeroizing<Vec<u8>>,
    expected_proof: Zeroizing<Vec<u8>>,
}
impl SrpSession {
    pub fn new(identifier: &str, password: &str, salt: &[u8], server: &Value) -> Result<Self> {
        let mut exponent = Zeroizing::new([0u8; 64]);
        OsRng.fill_bytes(&mut *exponent);
        Self::with_exponent(identifier, password, salt, server, &*exponent)
    }
    fn with_exponent(
        identifier: &str,
        password: &str,
        salt: &[u8],
        server: &Value,
        exponent: &[u8],
    ) -> Result<Self> {
        ensure!(!identifier.is_empty(), "Missing SRP identifier");
        let hashed = derive_key(password.trim_matches(['\r', '\n']).as_bytes(), salt)?;
        let password_b64 = Zeroizing::new(STANDARD.encode(*hashed));
        let n = group();
        let g = BigUint::from(19u8);
        let one = BigUint::from(1u8);
        let a = BigUint::from_bytes_be(exponent) % (&n - &one) + &one;
        let public = g.modpow(&a, &n);
        let b = parse_integer(server)?;
        ensure!(
            b > BigUint::from(0u8) && b < n,
            "Invalid SRP server public value"
        );
        let x = BigUint::from_bytes_be(&hash(&[
            salt,
            &hash(&[identifier.as_bytes(), b":", password_b64.as_bytes()]),
        ]));
        let u = BigUint::from_bytes_be(&hash(&[&pad(&public, 1024)?, &pad(&b, 1024)?]));
        ensure!(u != BigUint::from(0u8), "Invalid SRP scrambling parameter");
        let k = BigUint::from_bytes_be(&hash(&[&pad(&n, 1024)?, &pad(&g, 1024)?]));
        let kv = (k * g.modpow(&x, &n)) % &n;
        let base = (&b + &n - kv) % &n;
        ensure!(base != BigUint::from(0u8), "Invalid SRP shared secret base");
        let shared = base.modpow(&(a + u * x), &n);
        let session_key = Zeroizing::new(pad(&shared, 1024)?);
        let h_n = hash(&[&minimal(&n)]);
        let h_g = hash(&[&minimal(&g)]);
        let xor: Vec<u8> = h_n.iter().zip(h_g).map(|(a, b)| a ^ b).collect();
        let h_key = hash(&[&session_key]);
        let proof = hash(&[
            &xor,
            &hash(&[identifier.as_bytes()]),
            salt,
            &minimal(&public),
            &minimal(&b),
            &h_key,
        ]);
        let proof_n = BigUint::from_bytes_be(&proof);
        let expected = hash(&[&minimal(&public), &minimal(&proof_n), &h_key]);
        Ok(Self {
            public_value: wire(&public),
            client_proof: wire(&proof_n),
            session_key,
            expected_proof: Zeroizing::new(expected),
        })
    }
    pub fn validate_server_proof(&self, value: &Value) -> Result<()> {
        let actual = pad(&parse_integer(value)?, 64)?;
        ensure!(
            bool::from(actual.ct_eq(&self.expected_proof)),
            "SRP server proof validation failed"
        );
        Ok(())
    }
    pub fn unwrap_token(&self, salt: &[u8], ciphertext: &[u8]) -> Result<String> {
        let encoded = Zeroizing::new(STANDARD.encode(&*self.session_key));
        let key = derive_key(encoded.as_bytes(), salt)?;
        String::from_utf8(secret_open(&*key, ciphertext)?)
            .map_err(|_| anyhow!("DeviceToken is not UTF-8"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_short_and_wrong_kind_envelopes() {
        assert!(secret_open(&[0; 32], &[4; 20]).is_err());
        let mut blob = [0; 42];
        blob[0] = 4;
        blob[1] = 2;
        assert!(secret_open(&[0; 32], &blob).is_err());
        blob[1] = 1;
        assert!(box_open(&[0; 32], &[0; 32], &blob).is_err());
    }
    #[test]
    fn plaintext_sniffing_and_bytes() {
        for text in [
            "Main",
            "root",
            "example-label",
            "203.0.113.40",
            "ssh-rsa AAAAB3",
        ] {
            assert!(!looks_encrypted(text));
        }
        assert_eq!(
            bytes_field(&serde_json::json!({"type":"Buffer","data":[65,66]})).unwrap(),
            b"AB"
        );
        assert!(bytes_field(&serde_json::json!([256])).is_err());
    }
    #[test]
    fn real_modulus_padding_and_blake2() {
        assert_eq!(pad(&group(), 1024).unwrap(), minimal(&group()));
        assert_eq!(minimal(&BigUint::from(19u8)), [0x13]);
        assert_eq!(wire(&BigUint::from(10u8)), "0A");
        assert_eq!(hash(&[b"abc"])[..4], [0xba, 0x80, 0xa5, 0x3f]);
    }
    #[test]
    fn srp_integer_encodings_match_python_buffer_and_base64_rules() {
        let expected = BigUint::from(0xdeadbeefu64);
        for ascii in [b"DEADBEEF".as_slice(), b" 0xDEADBEEF\n", b"0XDEADBEEF"] {
            assert_eq!(
                parse_integer(&serde_json::json!({"type":"Buffer","data":ascii})).unwrap(),
                expected
            );
            assert_eq!(parse_integer(&serde_json::json!(ascii)).unwrap(), expected);
        }
        assert_eq!(
            parse_integer(&serde_json::json!([0xde, 0xad, 0xbe, 0xef])).unwrap(),
            expected
        );
        assert_eq!(
            parse_integer(&serde_json::json!(
                STANDARD.encode([0xde, 0xad, 0xbe, 0xef])
            ))
            .unwrap(),
            expected
        );
        assert_eq!(
            parse_integer(&serde_json::json!(STANDARD.encode(b"0xDEADBEEF"))).unwrap(),
            expected
        );
        // Base64-encoded bare ASCII hexadecimal is raw bytes, matching the
        // Python string branch; this differs deliberately from Node Buffer.
        assert_eq!(
            parse_integer(&serde_json::json!(STANDARD.encode(b"DEADBEEF"))).unwrap(),
            BigUint::from_bytes_be(b"DEADBEEF")
        );
        assert_eq!(
            parse_integer(&serde_json::json!(b"AB".as_slice())).unwrap(),
            BigUint::from_bytes_be(b"AB")
        );
        assert_eq!(
            parse_integer(&serde_json::json!("AB")).unwrap(),
            BigUint::from(0xabu8)
        );
        assert_eq!(
            parse_integer(&serde_json::json!(19)).unwrap(),
            BigUint::from(19u8)
        );
        assert!(parse_integer(&serde_json::json!({"type":"Buffer","data":[256]})).is_err());
    }
    #[test]
    fn reference_vectors() {
        let vectors: Value =
            serde_json::from_str(include_str!("../tests/fixtures/crypto_vectors.json")).unwrap();
        let derive = &vectors["argon2"];
        assert_eq!(
            &*derive_key(
                derive["password"].as_str().unwrap().as_bytes(),
                &decode_b64(derive["salt"].as_str().unwrap()).unwrap()
            )
            .unwrap(),
            decode_b64(derive["key"].as_str().unwrap())
                .unwrap()
                .as_slice()
        );
        let secret = &vectors["secretbox"];
        let key = decode_b64(secret["key"].as_str().unwrap()).unwrap();
        let raw = decode_b64(secret["ciphertext"].as_str().unwrap()).unwrap();
        assert_eq!(
            secret_open(&key, &raw).unwrap(),
            secret["plaintext"].as_str().unwrap().as_bytes()
        );
        let mut bad = raw;
        bad[40] ^= 1;
        assert!(secret_open(&key, &bad).is_err());
        let bx = &vectors["box"];
        assert_eq!(
            box_open(
                &key_bytes(&decode_b64(bx["public_key"].as_str().unwrap()).unwrap()).unwrap(),
                &key_bytes(&decode_b64(bx["private_key"].as_str().unwrap()).unwrap()).unwrap(),
                &decode_b64(bx["ciphertext"].as_str().unwrap()).unwrap()
            )
            .unwrap(),
            decode_b64(bx["plaintext"].as_str().unwrap()).unwrap()
        );
        let rn = &vectors["rncryptor"];
        let cryptor = VaultCryptor::new(
            rn["password"].as_str().unwrap(),
            &decode_b64(rn["salt"].as_str().unwrap()).unwrap(),
            &decode_b64(rn["hmac_salt"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            cryptor
                .decrypt_field(rn["ciphertext"].as_str().unwrap())
                .unwrap(),
            rn["plaintext"]
        );
        let srp = &vectors["srp"];
        let session = SrpSession::with_exponent(
            srp["identifier"].as_str().unwrap(),
            srp["password"].as_str().unwrap(),
            &decode_b64(srp["salt"].as_str().unwrap()).unwrap(),
            &srp["server_public"],
            &decode_b64(srp["exponent"].as_str().unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(session.public_value, srp["client_public"]);
        assert_eq!(session.client_proof, srp["client_proof"]);
        session.validate_server_proof(&srp["server_proof"]).unwrap();
        assert!(
            session
                .validate_server_proof(&Value::String("FF".repeat(64)))
                .is_err()
        );
        assert_eq!(
            session
                .unwrap_token(
                    &decode_b64(srp["session_salt"].as_str().unwrap()).unwrap(),
                    &decode_b64(srp["wrapped_token"].as_str().unwrap()).unwrap()
                )
                .unwrap(),
            "fixture-device-token"
        );
    }
}
