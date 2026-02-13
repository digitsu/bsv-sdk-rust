//! Session manager — manages peer sessions, allowing multiple concurrent sessions per identity key.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::AuthError;
use crate::types::PeerSession;

/// Trait for managing peer sessions.
pub trait SessionManager: Send + Sync {
    fn add_session(&self, session: PeerSession) -> Result<(), AuthError>;
    fn update_session(&self, session: PeerSession);
    fn get_session(&self, identifier: &str) -> Result<PeerSession, AuthError>;
    fn remove_session(&self, session: &PeerSession);
    fn has_session(&self, identifier: &str) -> bool;
}

/// Default in-memory session manager.
pub struct DefaultSessionManager {
    /// Maps session_nonce -> PeerSession
    nonce_to_session: RwLock<HashMap<String, PeerSession>>,
    /// Maps identity_key_hex -> set of session_nonces
    key_to_nonces: RwLock<HashMap<String, Vec<String>>>,
}

impl DefaultSessionManager {
    pub fn new() -> Self {
        Self {
            nonce_to_session: RwLock::new(HashMap::new()),
            key_to_nonces: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for DefaultSessionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionManager for DefaultSessionManager {
    fn add_session(&self, session: PeerSession) -> Result<(), AuthError> {
        if session.session_nonce.is_empty() {
            return Err(AuthError::General(
                "invalid session: session_nonce is required".into(),
            ));
        }

        let nonce = session.session_nonce.clone();

        // Store by nonce
        {
            let mut map = self.nonce_to_session.write().unwrap();
            map.insert(nonce.clone(), session.clone());
        }

        // Track by identity key
        if let Some(ref peer_key) = session.peer_identity_key {
            let key_hex = peer_key.to_hex();
            let mut map = self.key_to_nonces.write().unwrap();
            let nonces = map.entry(key_hex).or_insert_with(Vec::new);
            if !nonces.contains(&nonce) {
                nonces.push(nonce);
            }
        }

        Ok(())
    }

    fn update_session(&self, session: PeerSession) {
        self.remove_session(&session);
        let _ = self.add_session(session);
    }

    fn get_session(&self, identifier: &str) -> Result<PeerSession, AuthError> {
        // Check direct nonce lookup
        {
            let map = self.nonce_to_session.read().unwrap();
            if let Some(session) = map.get(identifier) {
                return Ok(session.clone());
            }
        }

        // Try as identity key
        let nonces = {
            let map = self.key_to_nonces.read().unwrap();
            map.get(identifier).cloned()
        };

        if let Some(nonces) = nonces {
            if nonces.is_empty() {
                return Err(AuthError::SessionNotFound);
            }

            let map = self.nonce_to_session.read().unwrap();
            let mut best: Option<PeerSession> = None;

            for nonce in &nonces {
                if let Some(s) = map.get(nonce) {
                    match &best {
                        None => best = Some(s.clone()),
                        Some(current_best) => {
                            if s.last_update > current_best.last_update {
                                if s.is_authenticated || !current_best.is_authenticated {
                                    best = Some(s.clone());
                                }
                            } else if s.is_authenticated && !current_best.is_authenticated {
                                best = Some(s.clone());
                            }
                        }
                    }
                }
            }

            if let Some(session) = best {
                return Ok(session);
            }
        }

        Err(AuthError::SessionNotFound)
    }

    fn remove_session(&self, session: &PeerSession) {
        if !session.session_nonce.is_empty() {
            let mut map = self.nonce_to_session.write().unwrap();
            map.remove(&session.session_nonce);
        }

        if let Some(ref peer_key) = session.peer_identity_key {
            let key_hex = peer_key.to_hex();
            let mut map = self.key_to_nonces.write().unwrap();
            if let Some(nonces) = map.get_mut(&key_hex) {
                nonces.retain(|n| n != &session.session_nonce);
                if nonces.is_empty() {
                    map.remove(&key_hex);
                }
            }
        }
    }

    fn has_session(&self, identifier: &str) -> bool {
        {
            let map = self.nonce_to_session.read().unwrap();
            if map.contains_key(identifier) {
                return true;
            }
        }

        let map = self.key_to_nonces.read().unwrap();
        if let Some(nonces) = map.get(identifier) {
            return !nonces.is_empty();
        }

        false
    }
}
