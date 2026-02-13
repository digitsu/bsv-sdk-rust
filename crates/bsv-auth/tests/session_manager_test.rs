//! Tests for the session manager.

use bsv_auth::session_manager::{DefaultSessionManager, SessionManager};
use bsv_auth::types::PeerSession;
use bsv_primitives::ec::private_key::PrivateKey;

#[test]
fn test_session_manager_add_get_remove() {
    let manager = DefaultSessionManager::new();
    let pk = PrivateKey::new();
    let pub_key = pk.pub_key();

    let session = PeerSession {
        is_authenticated: true,
        session_nonce: "test-nonce".to_string(),
        peer_nonce: "peer-nonce".to_string(),
        peer_identity_key: Some(pub_key.clone()),
        last_update: 1000,
    };

    // Add session
    manager.add_session(session.clone()).unwrap();

    // Get session by nonce
    let retrieved = manager.get_session("test-nonce").unwrap();
    assert_eq!(retrieved.session_nonce, "test-nonce");
    assert_eq!(retrieved.peer_nonce, "peer-nonce");
    assert!(retrieved.is_authenticated);

    // Get by identity key
    let retrieved2 = manager.get_session(&pub_key.to_hex()).unwrap();
    assert_eq!(retrieved2.session_nonce, "test-nonce");

    // Has session
    assert!(manager.has_session("test-nonce"));
    assert!(manager.has_session(&pub_key.to_hex()));
    assert!(!manager.has_session("nonexistent"));

    // Update session
    let mut updated = retrieved;
    updated.is_authenticated = false;
    manager.update_session(updated);

    let retrieved3 = manager.get_session("test-nonce").unwrap();
    assert!(!retrieved3.is_authenticated);

    // Remove session
    manager.remove_session(&retrieved3);
    assert!(manager.get_session("test-nonce").is_err());
    assert!(!manager.has_session("test-nonce"));
}

#[test]
fn test_session_manager_rejects_empty_nonce() {
    let manager = DefaultSessionManager::new();
    let session = PeerSession {
        is_authenticated: true,
        session_nonce: String::new(),
        peer_nonce: String::new(),
        peer_identity_key: None,
        last_update: 0,
    };

    assert!(manager.add_session(session).is_err());
}

#[test]
fn test_session_manager_multiple_sessions_same_identity() {
    let manager = DefaultSessionManager::new();
    let pk = PrivateKey::new();
    let pub_key = pk.pub_key();

    let session1 = PeerSession {
        is_authenticated: false,
        session_nonce: "nonce-1".to_string(),
        peer_nonce: "peer-1".to_string(),
        peer_identity_key: Some(pub_key.clone()),
        last_update: 1000,
    };

    let session2 = PeerSession {
        is_authenticated: true,
        session_nonce: "nonce-2".to_string(),
        peer_nonce: "peer-2".to_string(),
        peer_identity_key: Some(pub_key.clone()),
        last_update: 2000,
    };

    manager.add_session(session1).unwrap();
    manager.add_session(session2).unwrap();

    // Should pick the best session (authenticated + newer)
    let best = manager.get_session(&pub_key.to_hex()).unwrap();
    assert_eq!(best.session_nonce, "nonce-2");
    assert!(best.is_authenticated);

    // Individual nonces still work
    let s1 = manager.get_session("nonce-1").unwrap();
    assert_eq!(s1.session_nonce, "nonce-1");
}
