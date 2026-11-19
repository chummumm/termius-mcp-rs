//! Independent regression cases against Python 3.2.0's supported wire encodings.
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use termius_mcp::crypto::SrpSession;

#[test]
fn srp_accepts_ascii_hex_in_proto_buffer_as_python_does() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/crypto_vectors.json")).unwrap();
    let vector = &fixture["srp"];
    let public = vector["server_public"].as_str().unwrap();
    let identifier = vector["identifier"].as_str().unwrap();
    let password = vector["password"].as_str().unwrap();
    let salt = STANDARD.decode(vector["salt"].as_str().unwrap()).unwrap();
    // The same valid Botan hex may be returned as a protobuf Buffer or byte array.
    // Python botan_bigint_from_str explicitly recognizes this form before decoding
    // raw bytes as an integer. The library's text path is the positive control.
    assert!(SrpSession::new(identifier, password, &salt, &json!(public)).is_ok());
    let buffer = json!({"type":"Buffer", "data":public.as_bytes()});
    assert!(
        SrpSession::new(identifier, password, &salt, &buffer).is_ok(),
        "ASCII hexadecimal Buffer must have the same interpretation as hex text"
    );
}

#[test]
fn naive_cloud_timestamps_are_utc_as_in_python() {
    let now = time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap();
    let naive = now.trim_end_matches('Z');
    for timestamp in [naive.to_string(), naive.replacen('T', " ", 1)] {
        assert!(
            !termius_mcp::tools::is_stale(Some(&timestamp), 60),
            "Python treats timezone-free ISO timestamps as UTC"
        );
    }
    assert!(termius_mcp::tools::is_stale(
        Some("2000-01-01T00:00:00"),
        60
    ));
}
