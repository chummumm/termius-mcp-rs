//! Independent construction checks for effective host trust and route invariants.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use termius_mcp::inventory;

fn snapshot() -> Value {
    json!({
        "host_set":[{"id":1,"label":"destination","address":"server.example.invalid","ssh_config":10,"group":2}],
        "group_set":[{"id":2,"label":"parent","ssh_config":11}],
        "sshconfig_set":[{"id":10,"identity":20},{"id":11}],
        "identity_set":[{"id":20,"username":"fixture-user","password":"synthetic-test-password","is_visible":true}],
        "hostchain_set":[],
        "knownhost_set":[]
    })
}

fn synthetic_public_key(byte: u8) -> String {
    let mut blob = vec![0, 0, 0, 11];
    blob.extend_from_slice(b"ssh-ed25519");
    blob.extend_from_slice(&[0, 0, 0, 32]);
    blob.extend_from_slice(&[byte; 32]);
    format!("ssh-ed25519 {}", STANDARD.encode(blob))
}

#[test]
fn effective_host_trust_preserves_inherited_true_and_nearest_false() {
    let mut value = snapshot();
    let resolved = inventory::resolve(&value, "destination").unwrap();
    assert!(!resolved.target.strict_host_key_check);
    assert_eq!(
        inventory::host_details(&value, "destination", false).unwrap()["strict_host_key_check"],
        false
    );

    value["sshconfig_set"][1]["strict_host_key_check"] = json!(true);
    assert!(
        inventory::resolve(&value, "destination")
            .unwrap()
            .target
            .strict_host_key_check
    );
    assert_eq!(
        inventory::host_details(&value, "destination", false).unwrap()["strict_host_key_check"],
        true
    );

    value["sshconfig_set"][0]["strict_host_key_check"] = json!(false);
    assert!(
        !inventory::resolve(&value, "destination")
            .unwrap()
            .target
            .strict_host_key_check
    );
    for invalid in [json!(0), json!(1), json!("unsupported"), json!({})] {
        value["sshconfig_set"][0]["strict_host_key_check"] = invalid;
        assert!(inventory::resolve(&value, "destination").is_err());
        let details = inventory::host_details(&value, "destination", false).unwrap();
        assert!(details["strict_host_key_check"].is_null());
        assert!(details["ssh_command"].is_null());
    }
}

#[test]
fn disabled_host_verification_does_not_parse_conflicting_rotation_records() {
    let mut value = snapshot();
    value["knownhost_set"] = json!([
        {"id":1,"hostnames":"server.example.invalid","key":synthetic_public_key(1)},
        {"id":2,"hostnames":"server.example.invalid","key":synthetic_public_key(2)}
    ]);
    for policy in [None, Some(false)] {
        match policy {
            None => {
                value["sshconfig_set"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("strict_host_key_check");
            }
            Some(policy) => {
                value["sshconfig_set"][0]["strict_host_key_check"] = json!(policy);
            }
        }
        let resolved = inventory::resolve(&value, "destination").expect(
            "Disabled verification must not reject a connection while parsing old/new trust records",
        );
        assert!(!resolved.target.strict_host_key_check);
        assert!(resolved.target.known_host_keys.is_empty());
    }

    value["sshconfig_set"][0]["strict_host_key_check"] = json!(true);
    assert!(inventory::resolve(&value, "destination").is_err());
}

#[test]
fn mixed_trust_modes_preserve_the_saved_jump_route() {
    let mut value = snapshot();
    value["host_set"].as_array_mut().unwrap().push(json!({
        "id":3,"label":"bastion","address":"jump.example.invalid","ssh_config":12
    }));
    value["sshconfig_set"].as_array_mut().unwrap().push(json!({
        "id":12,"identity":20,"strict_host_key_check":true
    }));
    value["hostchain_set"] = json!([{"id":30,"ssh_config":10,"hosts_chain":[3]}]);
    value["knownhost_set"] = json!([{
        "id":1,"hostnames":"jump.example.invalid","key":synthetic_public_key(1)
    }]);
    let resolved = inventory::resolve(&value, "destination").unwrap();
    assert!(!resolved.target.strict_host_key_check);
    assert_eq!(resolved.jumps.len(), 1);
    assert_eq!(resolved.jumps[0].address, "jump.example.invalid");
    assert!(resolved.jumps[0].strict_host_key_check);
    assert_eq!(resolved.jumps[0].known_host_keys.len(), 1);
}
