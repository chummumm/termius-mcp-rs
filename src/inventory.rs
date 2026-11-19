//! Read-only projections and fail-closed SSH route resolution for a full cloud snapshot.

use std::collections::{HashMap, HashSet};

use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};

use crate::{ConnectionSpec, Endpoint};

const MAX_GROUP_DEPTH: usize = 128;
const MAX_JUMP_HOSTS: usize = 32;

fn rows<'a>(snapshot: &'a Value, set: &str) -> &'a [Value] {
    snapshot
        .get(set)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

fn ref_id(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.get("id").and_then(Value::as_u64))
        .filter(|id| *id != 0)
}

fn id(row: &Value) -> Option<u64> {
    row.get("id").and_then(ref_id)
}

fn is_deleted(snapshot: &Value, set: &str, row_id: u64) -> bool {
    ["deleted_sets", "delete_sets"].iter().any(|key| {
        snapshot
            .get(key)
            .map(|deleted| {
                rows(deleted, set)
                    .iter()
                    .any(|value| ref_id(value) == Some(row_id))
            })
            .unwrap_or(false)
    })
}

fn is_active(snapshot: &Value, set: &str, row: &Value) -> bool {
    if row
        .get("_undecryptable")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        return false;
    }
    let Some(row_id) = id(row) else {
        return false;
    };
    if is_deleted(snapshot, set, row_id) {
        return false;
    }
    if let Some(active) = snapshot
        .get("ssh_route_members")
        .and_then(|v| v.get(set))
        .and_then(Value::as_array)
        && !active.iter().any(|v| ref_id(v) == Some(row_id))
    {
        return false;
    }
    !snapshot
        .get("ssh_route_unavailable")
        .map(|v| rows(v, set).iter().any(|v| ref_id(v) == Some(row_id)))
        .unwrap_or(false)
}

fn active_rows<'a>(snapshot: &'a Value, set: &'a str) -> impl Iterator<Item = &'a Value> + 'a {
    rows(snapshot, set)
        .iter()
        .filter(move |row| is_active(snapshot, set, row))
}

fn by_id<'a>(snapshot: &'a Value, set: &str, row_id: u64) -> Result<&'a Value> {
    let mut found = rows(snapshot, set)
        .iter()
        .filter(|row| id(row) == Some(row_id));
    let row = found
        .next()
        .ok_or_else(|| anyhow!("Unresolved {set} reference {row_id}; sync the vault"))?;
    if found.next().is_some() {
        bail!("Duplicate {set} reference {row_id}");
    }
    if !is_active(snapshot, set, row) {
        bail!("Unavailable {set} reference {row_id}; sync the vault");
    }
    Ok(row)
}

fn relation<'a>(
    snapshot: &'a Value,
    owner: &Value,
    field: &str,
    set: &str,
) -> Result<Option<&'a Value>> {
    if owner
        .get("_unresolved_relations")
        .and_then(Value::as_array)
        .map(|v| v.iter().any(|v| v.as_str() == Some(field)))
        .unwrap_or(false)
    {
        bail!("Unresolved SSH relation: {field}; sync the vault");
    }
    match owner.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let row_id = ref_id(value).ok_or_else(|| anyhow!("Invalid SSH relation: {field}"))?;
            by_id(snapshot, set, row_id).map(Some)
        }
    }
}

fn text<'a>(row: &'a Value, name: &str) -> Option<&'a str> {
    row.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn boolean(value: &Value) -> Option<bool> {
    value.as_bool().or_else(|| match value.as_str() {
        Some("yes" | "true") => Some(true),
        Some("no" | "false") => Some(false),
        _ => None,
    })
}

fn number(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}

fn has_secret(row: &Value, name: &str) -> bool {
    text(row, name).is_some()
}

fn find_host<'a>(snapshot: &'a Value, name: &str) -> Result<&'a Value> {
    if name.trim().is_empty() {
        bail!("Host id or label is required");
    }
    let numeric = name.parse::<u64>().ok();
    let mut found = active_rows(snapshot, "host_set")
        .filter(|row| id(row) == numeric || text(row, "label") == Some(name));
    let row = found.next().ok_or_else(|| anyhow!("Host not found"))?;
    if found.next().is_some() {
        bail!("Multiple hosts match; use the numeric id from hosts");
    }
    Ok(row)
}

fn owner_stack<'a>(snapshot: &'a Value, host: &'a Value) -> Result<Vec<&'a Value>> {
    let mut stack = vec![host];
    let mut seen = HashSet::new();
    let mut group = relation(snapshot, host, "group", "group_set")?;
    while let Some(current) = group {
        let current_id = id(current).context("Group has no id")?;
        if !seen.insert(current_id) {
            bail!("Cycle in SSH group inheritance");
        }
        if stack.len() >= MAX_GROUP_DEPTH {
            bail!("SSH group nesting exceeds {MAX_GROUP_DEPTH}");
        }
        stack.push(current);
        group = relation(snapshot, current, "parent_group", "group_set")?;
    }
    Ok(stack)
}

fn config_identity<'a>(snapshot: &'a Value, config: &Value) -> Result<Option<&'a Value>> {
    let config_id = id(config).context("SSH config has no id")?;
    let mut linked: Option<Option<u64>> = config.get("_identity_link").map(ref_id);
    for set in ["sshconfigidentity_set", "sharedsshconfigidentity_set"] {
        for link in rows(snapshot, set) {
            let owner = link.get("ssh_config").and_then(ref_id);
            if link.get("_undecryptable").and_then(Value::as_bool) == Some(true)
                && (owner.is_none() || owner == Some(config_id))
            {
                bail!("Unreadable explicit SSH identity link; sync the vault");
            }
            if owner != Some(config_id) {
                continue;
            }
            if id(link)
                .map(|n| is_deleted(snapshot, set, n))
                .unwrap_or(false)
            {
                continue;
            }
            let identity_id = link.get("identity").and_then(ref_id);
            if let Some(previous) = linked
                && previous != identity_id
            {
                bail!("Conflicting explicit SSH identity links");
            }
            linked = Some(identity_id);
        }
    }
    if let Some(linked) = linked {
        let identity_id = linked.context("Unresolved explicit SSH identity; sync the vault")?;
        return by_id(snapshot, "identity_set", identity_id).map(Some);
    }
    relation(snapshot, config, "identity", "identity_set")
}

struct Merged<'a> {
    owners: Vec<&'a Value>,
    config: Map<String, Value>,
    identity: Value,
    key: Option<&'a Value>,
}

fn merge<'a>(snapshot: &'a Value, host: &'a Value) -> Result<Merged<'a>> {
    let owners = owner_stack(snapshot, host)?;
    let mut configs = Vec::new();
    for owner in &owners {
        if let Some(config) = relation(snapshot, owner, "ssh_config", "sshconfig_set")? {
            configs.push(config);
        }
    }
    let mut config = Map::new();
    for item in &configs {
        for field in [
            "port",
            "strict_host_key_check",
            "use_ssh_key",
            "timeout",
            "keep_alive_packages",
            "agent_forwarding",
            "startup_snippet",
            "use_mosh",
        ] {
            if config.contains_key(field) {
                continue;
            }
            if let Some(value) = item.get(field).filter(|value| !value.is_null()) {
                config.insert(field.into(), value.clone());
            }
        }
    }
    let mut invisible = Vec::new();
    let mut visible = None;
    for config in &configs {
        if let Some(identity) = config_identity(snapshot, config)? {
            // Validate every explicit relation up to the first visible identity.
            relation(snapshot, identity, "ssh_key", "sshkeycrypt_set")?;
            if identity.get("is_visible").and_then(boolean) == Some(true) {
                visible = Some(identity);
                break;
            }
            invisible.push(identity);
        }
    }
    let identity = if let Some(identity) = visible {
        identity.clone()
    } else {
        let mut merged = Map::new();
        for identity in invisible {
            for field in ["username", "password", "ssh_key", "label"] {
                if merged.contains_key(field) {
                    continue;
                }
                if let Some(value) = identity
                    .get(field)
                    .filter(|value| !value.is_null() && value.as_str() != Some(""))
                {
                    merged.insert(field.into(), value.clone());
                }
            }
        }
        Value::Object(merged)
    };
    let key = relation(snapshot, &identity, "ssh_key", "sshkeycrypt_set")?;
    Ok(Merged {
        owners,
        config,
        identity,
        key,
    })
}

fn jump_hosts<'a>(
    snapshot: &'a Value,
    host: &'a Value,
    merged: &Merged<'a>,
) -> Result<Vec<&'a Value>> {
    if snapshot.get("ssh_route_members") == Some(&Value::Null) {
        bail!("The current Termius host snapshot is incomplete");
    }
    if rows(&snapshot["ssh_route_unavailable"], "hostchain_set")
        .iter()
        .any(Value::is_null)
    {
        bail!("The owner of an unreadable SSH chain is unknown");
    }
    for chain in rows(snapshot, "hostchain_set") {
        if id(chain).is_some_and(|n| is_deleted(snapshot, "hostchain_set", n)) {
            continue;
        }
        // An invalid owner may belong to this host or an inherited group.
        // Ignoring it would silently turn a required bastion route into direct SSH.
        if chain.get("ssh_config").and_then(ref_id).is_none() {
            bail!("The owner of an SSH chain is unknown; sync the vault");
        }
    }
    for owner in &merged.owners {
        let Some(config) = relation(snapshot, owner, "ssh_config", "sshconfig_set")? else {
            continue;
        };
        let config_id = id(config).context("SSH config has no id")?;
        if rows(&snapshot["ssh_route_unavailable"], "hostchain_set")
            .iter()
            .any(|v| ref_id(v) == Some(config_id))
        {
            bail!("Unreadable SSH host chain; sync the vault");
        }
        let matches: Vec<_> = rows(snapshot, "hostchain_set")
            .iter()
            .filter(|row| {
                row.get("ssh_config").and_then(ref_id) == Some(config_id)
                    && !id(row)
                        .map(|n| is_deleted(snapshot, "hostchain_set", n))
                        .unwrap_or(false)
            })
            .collect();
        if matches.len() > 1 {
            bail!("Multiple SSH host chains for one config");
        }
        let Some(chain) = matches.first() else {
            continue;
        };
        if chain.get("_undecryptable").and_then(Value::as_bool) == Some(true) {
            bail!("Unreadable SSH host chain; sync the vault");
        }
        let refs = chain
            .get("hosts_chain")
            .and_then(Value::as_array)
            .context("Invalid SSH host chain")?;
        if refs.len() > MAX_JUMP_HOSTS {
            bail!("SSH chain exceeds {MAX_JUMP_HOSTS} hops");
        }
        let mut seen = HashSet::new();
        if let Some(host_id) = id(host) {
            seen.insert(host_id);
        }
        let mut hops = Vec::new();
        for value in refs {
            let host_id = value
                .as_u64()
                .filter(|n| *n > 0)
                .context("Invalid SSH host chain member")?;
            if !seen.insert(host_id) {
                bail!("Repeated host in SSH chain");
            }
            let hop = by_id(snapshot, "host_set", host_id)?;
            // Fail on inaccessible ancestors or credentials before any socket opens.
            merge(snapshot, hop)?;
            hops.push(hop);
        }
        return Ok(hops);
    }
    Ok(Vec::new())
}

fn trusted_keys(snapshot: &Value, address: &str, port: u16) -> Result<Vec<String>> {
    let endpoint = format!("[{address}]:{port}");
    let mut algorithms: HashMap<String, String> = HashMap::new();
    for known in active_rows(snapshot, "knownhost_set") {
        let Some(hostnames) = text(known, "hostnames") else {
            continue;
        };
        if !hostnames
            .split(',')
            .any(|name| name == endpoint || (port == 22 && name == address))
        {
            continue;
        }
        let Some(key) = text(known, "key") else {
            continue;
        };
        let mut fields = key.split_whitespace();
        let (Some(algorithm), Some(blob)) = (fields.next(), fields.next()) else {
            continue;
        };
        if !algorithm.starts_with("ssh-")
            && !algorithm.starts_with("ecdsa-")
            && !algorithm.starts_with("sk-")
        {
            continue;
        }
        if blob.len() > 1024 * 1024 {
            bail!("SSH host key exceeds size limit");
        }
        let Ok(decoded) = STANDARD.decode(blob) else {
            continue;
        };
        if decoded.len() < 4 {
            continue;
        }
        let length = u32::from_be_bytes(decoded[..4].try_into().expect("fixed length")) as usize;
        if length > decoded.len() - 4 || &decoded[4..4 + length] != algorithm.as_bytes() {
            continue;
        }
        let canonical = format!("{algorithm} {blob}");
        if let Some(existing) = algorithms.insert(algorithm.into(), canonical.clone())
            && existing != canonical
        {
            bail!("Conflicting trusted SSH host keys");
        }
    }
    let mut keys: Vec<_> = algorithms.into_values().collect();
    keys.sort();
    Ok(keys)
}

fn strict_host_key_check(config: &Map<String, Value>) -> Result<bool> {
    match config.get("strict_host_key_check") {
        None => Ok(false),
        Some(value) => boolean(value).context("Invalid SSH host key policy"),
    }
}

fn endpoint(snapshot: &Value, host: &Value, merged: &Merged<'_>) -> Result<Endpoint> {
    let address = text(host, "address").context("Host has no address")?;
    if address
        .chars()
        .any(|ch| ch.is_control() || ch.is_whitespace())
        || address.starts_with('-')
    {
        bail!("Invalid SSH host address");
    }
    let port = match merged.config.get("port") {
        None => 22,
        Some(value) => number(value)
            .filter(|p| *p > 0 && *p <= u16::MAX.into())
            .context("Invalid SSH port")? as u16,
    };
    let username = text(&merged.identity, "username")
        .context("Host has no username; sync the vault and check its SSH identity")?;
    if username.chars().any(char::is_control) {
        bail!("Invalid SSH username");
    }
    if merged
        .key
        .is_some_and(|key| text(key, "private_key").is_none())
    {
        bail!(
            "The selected SSH key has no private key material; sync the vault and check key synchronization"
        );
    }
    let strict_host_key_check = strict_host_key_check(&merged.config)?;
    Ok(Endpoint {
        address: address.into(),
        port,
        username: Some(username.into()),
        password: text(&merged.identity, "password").map(str::to_owned),
        private_key: merged
            .key
            .and_then(|key| text(key, "private_key"))
            .map(str::to_owned),
        passphrase: merged
            .key
            .and_then(|key| text(key, "passphrase"))
            .map(str::to_owned),
        strict_host_key_check,
        // Compatibility mode must not reject a rotated or conflicting saved pin
        // before the transport has a chance to honor the selected policy.
        known_host_keys: if strict_host_key_check {
            trusted_keys(snapshot, address, port)?
        } else {
            Vec::new()
        },
        connect_timeout: merged
            .config
            .get("timeout")
            .and_then(number)
            .unwrap_or(60)
            .max(1),
        keep_alive: merged
            .config
            .get("keep_alive_packages")
            .and_then(number)
            .unwrap_or(0)
            .min(u32::MAX.into()) as u32,
    })
}

/// Resolve credentials and all hops without allowing partial or stale routes.
pub fn resolve(snapshot: &Value, name: &str) -> Result<ConnectionSpec> {
    let host = find_host(snapshot, name)?;
    let merged = merge(snapshot, host)?;
    let hops = jump_hosts(snapshot, host, &merged)?;
    let target = endpoint(snapshot, host, &merged)?;
    let jumps = hops
        .iter()
        .map(|hop| endpoint(snapshot, hop, &merge(snapshot, hop)?))
        .collect::<Result<Vec<_>>>()?;
    Ok(ConnectionSpec {
        host_id: host["id"].clone(),
        label: text(host, "label").unwrap_or(&target.address).into(),
        target,
        jumps,
    })
}

pub fn counts(snapshot: &Value) -> Value {
    let mut out = Map::new();
    for (name, set) in [
        ("hosts", "host_set"),
        ("groups", "group_set"),
        ("identities", "identity_set"),
        ("keys", "sshkeycrypt_set"),
        ("snippets", "snippet_set"),
    ] {
        out.insert(name.into(), json!(active_rows(snapshot, set).count()));
    }
    Value::Object(out)
}

fn host_row(snapshot: &Value, host: &Value) -> Value {
    let group = relation(snapshot, host, "group", "group_set")
        .ok()
        .flatten()
        .and_then(|group| text(group, "label"));
    let merged = merge(snapshot, host);
    let mut row = json!({ "id": host["id"], "label": host["label"], "address": host["address"], "group": group, "username": null, "has_password": false });
    match merged {
        Ok(merged) => {
            row["username"] = json!(text(&merged.identity, "username"));
            row["has_password"] = json!(has_secret(&merged.identity, "password"));
        }
        Err(_) => {
            row["connection_unavailable"] = json!(true);
        }
    }
    row
}

pub fn hosts(snapshot: &Value, query: Option<&str>) -> Result<Value> {
    let query = query.unwrap_or_default().to_lowercase();
    Ok(Value::Array(
        active_rows(snapshot, "host_set")
            .map(|host| host_row(snapshot, host))
            .filter(|row| {
                query.is_empty()
                    || ["label", "address", "group", "username"]
                        .iter()
                        .any(|field| {
                            row.get(field)
                                .and_then(Value::as_str)
                                .map(|value| value.to_lowercase().contains(&query))
                                .unwrap_or(false)
                        })
            })
            .collect(),
    ))
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

pub fn host_details(snapshot: &Value, name: &str) -> Result<Value> {
    let host = find_host(snapshot, name)?;
    let mut out = host_row(snapshot, host);
    let merged = match merge(snapshot, host) {
        Ok(merged) => merged,
        Err(error) => {
            out["ssh_command"] = Value::Null;
            out["ssh_command_reason"] = json!(error.to_string());
            return Ok(out);
        }
    };
    for field in ["port", "use_ssh_key", "timeout", "keep_alive_packages"] {
        out[field] = merged.config.get(field).cloned().unwrap_or(Value::Null);
    }
    out["strict_host_key_check"] = json!(strict_host_key_check(&merged.config).ok());
    out["agent_forwarding"] = json!(false);
    out["ssh_key"] = json!(merged.key.and_then(|key| text(key, "label")));
    out["startup_snippet"] = merged
        .config
        .get("startup_snippet")
        .and_then(ref_id)
        .and_then(|row_id| by_id(snapshot, "snippet_set", row_id).ok())
        .and_then(|row| row.get("label"))
        .cloned()
        .unwrap_or(Value::Null);
    let command = (|| -> Result<String> {
        if !jump_hosts(snapshot, host, &merged)?.is_empty() {
            bail!("Use exec or files for this Termius host chain");
        }
        let peer = endpoint(snapshot, host, &merged)?;
        let destination = format!(
            "{}@{}",
            peer.username.as_deref().unwrap_or_default(),
            peer.address
        );
        Ok(format!(
            "ssh -p {} -o StrictHostKeyChecking={} -o ForwardAgent=no -- {}",
            peer.port,
            if peer.strict_host_key_check {
                "yes"
            } else {
                "no"
            },
            shell_quote(&destination)
        ))
    })();
    match command {
        Ok(command) => {
            out["ssh_command"] = json!(command);
        }
        Err(error) => {
            out["ssh_command"] = Value::Null;
            out["ssh_command_reason"] = json!(error.to_string());
        }
    }
    Ok(out)
}

pub fn list(snapshot: &Value, kind: &str, include_script: bool) -> Result<Value> {
    let set = match kind {
        "groups" => "group_set",
        "identities" => "identity_set",
        "keys" => "sshkeycrypt_set",
        "snippets" => "snippet_set",
        _ => bail!("kind must be groups, identities, keys, or snippets"),
    };
    let mut items = Vec::new();
    for item in active_rows(snapshot, set) {
        if kind == "identities" && item.get("is_visible").and_then(boolean) == Some(false) {
            continue;
        }
        let mut row = json!({ "id": item["id"], "label": item["label"] });
        match kind {
            "identities" => {
                row["username"] = json!(text(item, "username"));
                row["has_password"] = json!(has_secret(item, "password"));
                row["ssh_key"] = relation(snapshot, item, "ssh_key", "sshkeycrypt_set")
                    .ok()
                    .flatten()
                    .and_then(|key| key.get("label"))
                    .cloned()
                    .unwrap_or(Value::Null);
            }
            "keys" => {
                row["has_private_key"] = json!(has_secret(item, "private_key"));
            }
            "snippets" if include_script => {
                row["script"] = item["script"].clone();
            }
            _ => {}
        }
        items.push(row);
    }
    Ok(json!({ "kind": kind, "count": items.len(), "items": items }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot() -> Value {
        json!({
            "host_set": [{"id": 1, "label": "test", "address": "server.example.com", "group": 2, "ssh_config": 10}],
            "group_set": [{"id": 2, "label": "production", "parent_group": null, "ssh_config": 20}],
            "sshconfig_set": [{"id": 10, "identity": 100, "port": 2222, "strict_host_key_check": false}, {"id": 20, "identity": 200, "port": 22, "strict_host_key_check": true}],
            "identity_set": [{"id": 100, "username": "host-user", "password": "secret-a", "is_visible": false}, {"id": 200, "username": "group-user", "password": "secret-b", "ssh_key": 300, "is_visible": false}],
            "sshkeycrypt_set": [{"id": 300, "label": "key", "private_key": "private-fixture", "passphrase": "passphrase-fixture"}],
            "snippet_set": [{"id": 90, "label": "script", "script": "echo hello"}]
        })
    }

    #[test]
    fn nearest_fields_and_false_policy_are_preserved() {
        let s = snapshot();
        let result = resolve(&s, "test").unwrap();
        assert_eq!(result.target.port, 2222);
        assert_eq!(result.target.username.as_deref(), Some("host-user"));
        assert_eq!(result.target.password.as_deref(), Some("secret-a"));
        assert_eq!(
            result.target.private_key.as_deref(),
            Some("private-fixture")
        );
        assert!(!result.target.strict_host_key_check);
    }

    #[test]
    fn visible_identity_replaces_entire_hidden_credential() {
        let mut s = snapshot();
        s["identity_set"][1]["is_visible"] = json!(true);
        let result = resolve(&s, "1").unwrap();
        assert_eq!(result.target.username.as_deref(), Some("group-user"));
        assert_eq!(result.target.password.as_deref(), Some("secret-b"));
    }

    #[test]
    fn deleted_or_unreadable_key_never_falls_back() {
        for update in [
            json!({"deleted_sets":{"sshkeycrypt_set":[300]}}),
            json!({"ssh_route_members":{"sshkeycrypt_set":[]}}),
        ] {
            let mut s = snapshot();
            s.as_object_mut()
                .unwrap()
                .extend(update.as_object().unwrap().clone());
            assert!(resolve(&s, "1").is_err());
        }
        let mut s = snapshot();
        s["sshkeycrypt_set"][0]["_undecryptable"] = json!(true);
        assert!(resolve(&s, "1").is_err());
        let mut s = snapshot();
        s["sshkeycrypt_set"][0]["private_key"] = json!("");
        assert!(resolve(&s, "1").is_err());
    }

    #[test]
    fn explicit_identity_link_has_priority_and_missing_is_fatal() {
        let mut s = snapshot();
        s["sharedsshconfigidentity_set"] = json!([{"ssh_config":{"id":10},"identity":{"id":200}}]);
        assert_eq!(
            resolve(&s, "1").unwrap().target.username.as_deref(),
            Some("group-user")
        );
        s["sharedsshconfigidentity_set"][0]["identity"] = json!(999);
        assert!(resolve(&s, "1").is_err());
    }

    #[test]
    fn group_cycles_and_missing_ancestors_fail_closed() {
        let mut s = snapshot();
        s["group_set"][0]["parent_group"] = json!(2);
        assert!(resolve(&s, "1").is_err());
        s["group_set"][0]["parent_group"] = json!(987);
        assert!(resolve(&s, "1").is_err());
    }

    #[test]
    fn ambiguous_numeric_label_and_duplicate_ids_are_rejected() {
        let mut s = snapshot();
        let mut extra = s["host_set"][0].clone();
        extra["id"] = json!(2);
        extra["label"] = json!("1");
        s["host_set"].as_array_mut().unwrap().push(extra);
        assert!(resolve(&s, "1").is_err());
    }

    #[test]
    fn public_projections_never_return_passwords_or_private_keys() {
        let s = snapshot();
        let mut outputs = vec![
            hosts(&s, None).unwrap(),
            host_details(&s, "1").unwrap(),
            counts(&s),
        ];
        for kind in ["identities", "keys", "groups", "snippets"] {
            outputs.push(list(&s, kind, false).unwrap());
        }
        let rendered = serde_json::to_string(&outputs).unwrap();
        for secret in [
            "secret-a",
            "secret-b",
            "private-fixture",
            "passphrase-fixture",
        ] {
            assert!(!rendered.contains(secret));
        }
        assert!(!rendered.contains("echo hello"));
        assert!(
            list(&s, "snippets", true)
                .unwrap()
                .to_string()
                .contains("echo hello")
        );
    }

    #[test]
    fn unknown_unreadable_chain_owner_disables_connection() {
        let mut s = snapshot();
        s["hostchain_set"] = json!([{"id":1,"_undecryptable":true}]);
        assert!(resolve(&s, "1").is_err());
    }

    #[test]
    fn jump_chain_keeps_order_and_individual_trust_policy() {
        let mut s = snapshot();
        s["host_set"].as_array_mut().unwrap().extend([
            json!({"id":2,"label":"hop-one","address":"hop1.example.com","ssh_config":20}),
            json!({"id":3,"label":"hop-two","address":"hop2.example.com","ssh_config":20}),
        ]);
        s["hostchain_set"] = json!([{"id":1,"ssh_config":10,"hosts_chain":[2,3]}]);
        let unpinned = resolve(&s, "1").unwrap();
        assert!(!unpinned.target.strict_host_key_check);
        assert!(unpinned.jumps.iter().all(|hop| hop.strict_host_key_check));
        assert!(
            unpinned
                .jumps
                .iter()
                .all(|hop| hop.known_host_keys.is_empty())
        );
        let blob = STANDARD.encode(
            [
                0, 0, 0, 11, b's', b's', b'h', b'-', b'e', b'd', b'2', b'5', b'5', b'1', b'9', 0,
                0, 0, 32,
            ]
            .into_iter()
            .chain([1_u8; 32])
            .collect::<Vec<_>>(),
        );
        s["knownhost_set"] = json!([{"id":1,"hostnames":"[server.example.com]:2222","key":format!("ssh-ed25519 {blob}")},{"id":2,"hostnames":"hop1.example.com,hop2.example.com","key":format!("ssh-ed25519 {blob}")}]);
        let result = resolve(&s, "1").unwrap();
        assert!(result.target.known_host_keys.is_empty());
        assert!(
            result
                .jumps
                .iter()
                .all(|hop| !hop.known_host_keys.is_empty())
        );
        assert_eq!(
            result
                .jumps
                .iter()
                .map(|p| p.address.as_str())
                .collect::<Vec<_>>(),
            ["hop1.example.com", "hop2.example.com"]
        );
        s["hostchain_set"][0]["hosts_chain"] = json!([2, 1]);
        assert!(resolve(&s, "1").is_err());
    }
}
