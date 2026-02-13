//! Session manager — manages peer sessions, allowing multiple concurrent sessions per identity key.

use std::collections::HashMap;
use std::sync::RwLock;

use crate::error::AuthError;
use crate::types::PeerSession;

/// Trait for managing peer sessions.
pub trait SessionManager: Send + Sync {
    /// Add a new peer session.
    fn add_session(&self, session: PeerSession) -> Result<(), AuthError>;
    /// Update an existing peer session.
    fn update_session(&self, session: PeerSession);
    /// Get a peer session by nonce or identity key.
    fn get_session(&self, identifier: &str) -> Result<PeerSession, AuthError>;
    /// Remove a peer session.
    fn remove_session(&self, session: &PeerSession);
    /// Check if a session exists for the given identifier.
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
    /// Create a new empty session manager.
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

/// Helper to convert a poisoned lock error into an AuthError.
fn lock_err<T>(_: std::sync::PoisonError<T>) -> AuthError {
    AuthError::LockError("lock poisoned".into())
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
            let mut map = self.nonce_to_session.write().map_err(lock_err)?;
            map.insert(nonce.clone(), session.clone());
        }

        // Track by identity key
        if let Some(ref peer_key) = session.peer_identity_key {
            let key_hex = peer_key.to_hex();
            let mut map = self.key_to_nonces.write().map_err(lock_err)?;
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
            let map = self.nonce_to_session.read().map_err(lock_err)?;
            if let Some(session) = map.get(identifier) {
                return Ok(session.clone());
            }
        }

        // Try as identity key
        let nonces = {
            let map = self.key_to_nonces.read().map_err(lock_err)?;
            map.get(identifier).cloned()
        };

        if let Some(nonces) = nonces {
            if nonces.is_empty() {
                return Err(AuthError::SessionNotFound);
            }

            let map = self.nonce_to_session.read().map_err(lock_err)?;
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
            if let Ok(mut map) = self.nonce_to_session.write() {
                map.remove(&session.session_nonce);
            }
        }

        if let Some(ref peer_key) = session.peer_identity_key {
            let key_hex = peer_key.to_hex();
            if let Ok(mut map) = self.key_to_nonces.write() {
                if let Some(nonces) = map.get_mut(&key_hex) {
                    nonces.retain(|n| n != &session.session_nonce);
                    if nonces.is_empty() {
                        map.remove(&key_hex);
                    }
                }
            }
        }
    }

    fn has_session(&self, identifier: &str) -> bool {
        if let Ok(map) = self.nonce_to_session.read() {
            if map.contains_key(identifier) {
                return true;
            }
        }

        if let Ok(map) = self.key_to_nonces.read() {
            if let Some(nonces) = map.get(identifier) {
                return !nonces.is_empty();
            }
        }

        false
    }
}
