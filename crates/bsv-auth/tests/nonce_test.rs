//! Tests for nonce creation and verification.

use bsv_auth::utils::{create_nonce, verify_nonce};
use bsv_primitives::ec::private_key::PrivateKey;
use bsv_wallet::types::{Counterparty, CounterpartyType};
use bsv_wallet::{ProtoWallet, ProtoWalletArgs};

#[test]
fn test_create_nonce() {
    let pk = PrivateKey::new();
    let wallet = ProtoWallet::new(ProtoWalletArgs::PrivateKey(pk)).unwrap();
    let counterparty = Counterparty {
        r#type: CounterpartyType::Self_,
        counterparty: None,
    };

    let nonce1 = create_nonce(&wallet, counterparty.clone()).unwrap();
    assert!(!nonce1.is_empty());

    let nonce2 = create_nonce(&wallet, counterparty).unwrap();
    assert!(!nonce2.is_empty());
    assert_ne!(nonce1, nonce2, "Two nonces should be different");
}

#[test]
fn test_verify_nonce() {
    let pk = PrivateKey::new();
    let wallet = ProtoWallet::new(ProtoWalletArgs::PrivateKey(pk)).unwrap();
    let counterparty = Counterparty {
        r#type: CounterpartyType::Self_,
        counterparty: None,
    };

    let nonce = create_nonce(&wallet, counterparty.clone()).unwrap();

    // Valid nonce should verify
    let valid = verify_nonce(&nonce, &wallet, counterparty.clone()).unwrap();
    assert!(valid);

    // Wrong counterparty should fail
    let invalid = verify_nonce(
        &nonce,
        &wallet,
        Counterparty {
            r#type: CounterpartyType::Anyone,
            counterparty: None,
        },
    )
    .unwrap();
    assert!(!invalid);
}

#[test]
fn test_verify_nonce_invalid_format() {
    let pk = PrivateKey::new();
    let wallet = ProtoWallet::new(ProtoWalletArgs::PrivateKey(pk)).unwrap();
    let counterparty = Counterparty {
        r#type: CounterpartyType::Self_,
        counterparty: None,
    };

    // Invalid base64 should error
    let result = verify_nonce("not-valid-base64!!!", &wallet, counterparty);
    assert!(result.is_err());
}
