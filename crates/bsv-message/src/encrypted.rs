//! BRC-78 message encryption and decryption.
//!
//! <https://github.com/bitcoin-sv/BRCs/blob/master/peer-to-peer/0078.md>

use base64::Engine;
use rand::RngCore;

use bsv_primitives::ec::{PrivateKey, PublicKey, SymmetricKey};

use crate::MessageError;

/// BRC-78 encrypted message version tag.
const VERSION: &str = "42421033";

/// Encrypt a message using the sender's private key and the recipient's public key (BRC-78).
///
/// The output format is:
/// `version (4 bytes) || sender_pubkey (33 bytes) || recipient_pubkey (33 bytes) || key_id (32 bytes) || ciphertext`
pub fn encrypt(
    message: &[u8],
    sender: &PrivateKey,
    recipient: &PublicKey,
) -> Result<Vec<u8>, MessageError> {
    let mut key_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key_id);

    let key_id_base64 = base64::engine::general_purpose::STANDARD.encode(key_id);
    let invoice_number = format!("2-message encryption-{}", key_id_base64);

    let signing_priv = sender.derive_child(recipient, &invoice_number)?;
    let recipient_derived = recipient.derive_child(sender, &invoice_number)?;
    let shared_secret = signing_priv.derive_shared_secret(&recipient_derived)?;

    let shared_compressed = shared_secret.to_compressed();
    let skey = SymmetricKey::new(&shared_compressed[1..]);
    let ciphertext = skey.encrypt(message)?;

    let version = hex::decode(VERSION).unwrap();
    let sender_pub = sender.pub_key().to_compressed();
    let recipient_der = recipient.to_compressed();

    let mut result = Vec::with_capacity(4 + 33 + 33 + 32 + ciphertext.len());
    result.extend_from_slice(&version);
    result.extend_from_slice(&sender_pub);
    result.extend_from_slice(&recipient_der);
    result.extend_from_slice(&key_id);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Decrypt a BRC-78 encrypted message using the recipient's private key.
pub fn decrypt(message: &[u8], recipient: &PrivateKey) -> Result<Vec<u8>, MessageError> {
    let min_length = 4 + 33 + 33 + 32 + 1;
    if message.len() < min_length {
        return Err(MessageError::MessageTooShort {
            expected: min_length,
            actual: message.len(),
        });
    }

    let mut offset = 0;

    // Version (4 bytes)
    let version_hex = hex::encode(&message[offset..offset + 4]);
    offset += 4;
    if version_hex != VERSION {
        return Err(MessageError::VersionMismatch {
            expected: VERSION.to_string(),
            received: version_hex,
        });
    }

    // Sender public key (33 bytes)
    let sender = PublicKey::from_bytes(&message[offset..offset + 33])?;
    offset += 33;

    // Recipient public key (33 bytes)
    let expected_recipient = &message[offset..offset + 33];
    offset += 33;
    let actual_recipient = recipient.pub_key().to_compressed();
    if expected_recipient != actual_recipient.as_slice() {
        return Err(MessageError::RecipientMismatch {
            expected: hex::encode(expected_recipient),
            actual: hex::encode(actual_recipient),
        });
    }

    // Key ID (32 bytes)
    let key_id = &message[offset..offset + 32];
    offset += 32;

    // Ciphertext (rest)
    let encrypted = &message[offset..];

    let key_id_base64 = base64::engine::general_purpose::STANDARD.encode(key_id);
    let invoice_number = format!("2-message encryption-{}", key_id_base64);

    let signing_pub = sender.derive_child(recipient, &invoice_number)?;
    let recipient_derived = recipient.derive_child(&sender, &invoice_number)?;
    let shared_secret = signing_pub.derive_shared_secret(&recipient_derived)?;

    let shared_compressed = shared_secret.to_compressed();
    let skey = SymmetricKey::new(&shared_compressed[1..]);
    Ok(skey.decrypt(encrypted)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a private key from a short byte slice (left-padded to 32 bytes).
    fn priv_key_from_short(b: &[u8]) -> PrivateKey {
        let mut padded = [0u8; 32];
        padded[32 - b.len()..].copy_from_slice(b);
        PrivateKey::from_bytes(&padded).unwrap()
    }

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let sender = priv_key_from_short(&[15]);
        let recipient = priv_key_from_short(&[21]);
        let recipient_pub = recipient.pub_key();

        let msg = vec![1, 2, 4, 8, 16, 32];
        let encrypted = encrypt(&msg, &sender, &recipient_pub).unwrap();
        let decrypted = decrypt(&encrypted, &recipient).unwrap();
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn test_decrypt_wrong_version() {
        let sender = priv_key_from_short(&[15]);
        let recipient = priv_key_from_short(&[21]);
        let recipient_pub = recipient.pub_key();

        let msg = vec![1, 2, 4, 8, 16, 32];
        let mut encrypted = encrypt(&msg, &sender, &recipient_pub).unwrap();
        encrypted[0] = 1;

        let err = decrypt(&encrypted, &recipient).unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("message version mismatch"),
            "got: {}",
            err_str
        );
        assert!(err_str.contains("42421033"), "got: {}", err_str);
        assert!(err_str.contains("01421033"), "got: {}", err_str);
    }

    #[test]
    fn test_decrypt_wrong_recipient() {
        let sender = priv_key_from_short(&[15]);
        let recipient = priv_key_from_short(&[21]);
        let recipient_pub = recipient.pub_key();
        let wrong_recipient = priv_key_from_short(&[22]);

        let msg = vec![1, 2, 4, 8, 16, 32];
        let encrypted = encrypt(&msg, &sender, &recipient_pub).unwrap();

        let err = decrypt(&encrypted, &wrong_recipient).unwrap_err();
        let err_str = err.to_string();
        assert!(
            err_str.contains("expects a recipient public key"),
            "got: {}",
            err_str
        );
        // Verify both hex keys appear in the error
        let expected_hex = hex::encode(recipient_pub.to_compressed());
        let actual_hex = hex::encode(wrong_recipient.pub_key().to_compressed());
        assert!(err_str.contains(&expected_hex), "got: {}", err_str);
        assert!(err_str.contains(&actual_hex), "got: {}", err_str);
    }

    #[test]
    fn test_decrypt_too_short() {
        let recipient = priv_key_from_short(&[21]);
        let short_msg = vec![0u8; 10];
        assert!(decrypt(&short_msg, &recipient).is_err());
    }
}
