//! Independent reviewer regressions; no live cloud account is required.
use serde_json::json;
use termius_mcp::inventory;

fn base_snapshot() -> serde_json::Value {
    json!({
        "host_set":[{"id":1,"label":"destination","address":"server.example.com","ssh_config":10}],
        "sshconfig_set":[{"id":10,"identity":20}],
        "identity_set":[{"id":20,"username":"alice","password":"synthetic-test-password","is_visible":true}],
        "hostchain_set":[],
        "knownhost_set":[]
    })
}

#[test]
fn malformed_chain_owner_cannot_silently_turn_into_direct_connection() {
    for owner in [json!(null), json!(0), json!("unparseable"), json!({})] {
        let mut snapshot = base_snapshot();
        snapshot["hostchain_set"] = json!([{"id":99,"ssh_config":owner,"hosts_chain":[2]}]);
        assert!(
            inventory::resolve(&snapshot, "destination").is_err(),
            "An unknown chain owner must fail closed; the Python snapshot marks this globally unavailable"
        );
    }
}

#[test]
fn empty_chain_set_can_intentionally_use_a_direct_connection() {
    assert!(
        inventory::resolve(&base_snapshot(), "destination")
            .unwrap()
            .jumps
            .is_empty()
    );
}

#[test]
fn explicitly_deleted_malformed_chain_does_not_block_direct_connection() {
    let mut snapshot = base_snapshot();
    snapshot["hostchain_set"] = json!([{"id":99,"ssh_config":null,"hosts_chain":[2]}]);
    snapshot["deleted_sets"] = json!({"hostchain_set":[99]});
    assert!(
        inventory::resolve(&snapshot, "destination")
            .unwrap()
            .jumps
            .is_empty()
    );
}

#[tokio::test]
async fn legacy_header_names_are_case_insensitive_and_order_independent() {
    for input in [
        "CONTENT-LENGTH: 2\r\n\r\n{}",
        "Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    ] {
        let mut reader = tokio::io::BufReader::new(input.as_bytes());
        assert_eq!(
            termius_mcp::protocol::read_message(&mut reader)
                .await
                .unwrap(),
            Some(json!({}))
        );
    }
}
