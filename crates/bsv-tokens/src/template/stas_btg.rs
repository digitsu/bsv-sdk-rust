//! STAS-BTG unlocking script templates.
//!
//! Provides two unlocking templates for the dual-path STAS-BTG locking script:
//!
//! ## Path A — BTG Proof ([`StasBtgUnlockingTemplate`])
//!
//! ```text
//! <sig> <pubkey> <prefix> <output> <suffix> OP_TRUE
//! ```
//!
//! The `OP_TRUE` selects the `OP_IF` branch. The BTG preamble verifies the
//! prev-TX proof and drops the three proof segments.
//!
//! ## Path B — Checkpoint Attestation ([`StasBtgCheckpointUnlockingTemplate`])
//!
//! ```text
//! <sig_owner> <pubkey_owner> <sig_issuer> <pubkey_issuer> OP_FALSE
//! ```
//!
//! The `OP_FALSE` selects the `OP_ELSE` branch. The checkpoint gate verifies
//! the issuer's signature against the embedded redemption PKH, then the STAS
//! v2 body verifies the owner's signature normally.

use bsv_primitives::ec::PrivateKey;
use bsv_script::Script;
use bsv_transaction::sighash::SIGHASH_ALL_FORKID;
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;
use bsv_transaction::TransactionError;

use crate::proof::split_tx_around_output;

/// STAS-BTG unlocking script template (Path A — BTG proof).
///
/// Produces unlocking scripts of the form:
/// `<DER_sig + sighash_byte> <compressed_pubkey> <prefix> <output> <suffix> OP_TRUE`
///
/// The `prefix`, `output`, and `suffix` are the three segments of the previous
/// raw transaction split around the output being spent (at `prev_vout`).
/// `OP_TRUE` selects the `OP_IF` branch of the dual-path locking script.
pub struct StasBtgUnlockingTemplate {
    /// Private key used to sign the input.
    private_key: PrivateKey,
    /// Sighash flag (defaults to `SIGHASH_ALL | SIGHASH_FORKID`).
    sighash_flag: u32,
    /// Raw bytes of the previous transaction being spent.
    prev_raw_tx: Vec<u8>,
    /// Output index in the previous transaction that is being spent.
    prev_vout: u32,
}

/// Create a STAS-BTG unlocker for signing token inputs with prev-TX proof (Path A).
///
/// The resulting unlocking script selects the `OP_IF` branch via `OP_TRUE`.
///
/// # Arguments
/// * `private_key` - The private key used to sign.
/// * `sighash_flag` - Optional sighash flag. Defaults to `SIGHASH_ALL_FORKID`.
/// * `prev_raw_tx` - The complete raw bytes of the previous transaction.
/// * `prev_vout` - The output index within the previous transaction being spent.
///
/// # Returns
/// A [`StasBtgUnlockingTemplate`] implementing [`UnlockingScriptTemplate`].
pub fn unlock_btg(
    private_key: PrivateKey,
    sighash_flag: Option<u32>,
    prev_raw_tx: Vec<u8>,
    prev_vout: u32,
) -> StasBtgUnlockingTemplate {
    StasBtgUnlockingTemplate {
        private_key,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
        prev_raw_tx,
        prev_vout,
    }
}

impl UnlockingScriptTemplate for StasBtgUnlockingTemplate {
    /// Sign the specified input and produce the BTG proof unlocking script.
    ///
    /// Builds: `<sig> <pubkey> <prefix> <output> <suffix> OP_TRUE` where the
    /// three proof segments are derived by splitting `prev_raw_tx` around
    /// `prev_vout`. `OP_TRUE` selects the OP_IF (proof) branch.
    fn sign(&self, tx: &Transaction, input_index: u32) -> Result<Script, TransactionError> {
        let idx = input_index as usize;

        if idx >= tx.inputs.len() {
            return Err(TransactionError::SigningError(format!(
                "input index {} out of range (tx has {} inputs)",
                idx,
                tx.inputs.len()
            )));
        }

        let input = &tx.inputs[idx];
        if input.source_tx_output().is_none() {
            return Err(TransactionError::SigningError(
                "missing source output on input (no previous tx info)".to_string(),
            ));
        }

        // Compute signature (identical to standard STAS/P2PKH)
        let sig_hash = tx.calc_input_signature_hash(idx, self.sighash_flag)?;
        let signature = self.private_key.sign(&sig_hash)?;
        let pub_key_bytes = self.private_key.pub_key().to_compressed();

        let der_sig = signature.to_der();
        let mut sig_buf = Vec::with_capacity(der_sig.len() + 1);
        sig_buf.extend_from_slice(&der_sig);
        sig_buf.push(self.sighash_flag as u8);

        // Split the previous TX into three proof segments
        let (prefix, output, suffix) = split_tx_around_output(&self.prev_raw_tx, self.prev_vout)
            .map_err(|e| TransactionError::SigningError(format!("prev-TX split failed: {e}")))?;

        // Build unlocking script: <sig> <pubkey> <prefix> <output> <suffix> OP_TRUE
        let mut script = Script::new();
        script.append_push_data(&sig_buf)?;
        script.append_push_data(&pub_key_bytes)?;
        script.append_push_data(&prefix)?;
        script.append_push_data(&output)?;
        script.append_push_data(&suffix)?;
        script.append_opcodes(&[0x51])?; // OP_TRUE — selects OP_IF branch

        Ok(script)
    }

    /// Estimate the byte length of a STAS-BTG proof unlocking script.
    ///
    /// The base P2PKH portion is ~106 bytes (sig + pubkey).
    /// The proof segments add the full size of the previous raw TX plus
    /// push opcode overhead (~10 bytes for three PUSHDATA operations).
    /// Plus 1 byte for `OP_TRUE`.
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        // Base sig+pubkey: ~106 bytes
        // Proof data: prev_raw_tx.len() bytes split across three pushes
        // Push opcode overhead: ~10 bytes (3 push ops with length prefixes)
        // OP_TRUE: 1 byte
        107 + self.prev_raw_tx.len() as u32 + 10
    }
}

/// STAS-BTG checkpoint unlocking script template (Path B — Checkpoint attestation).
///
/// Produces unlocking scripts of the form:
/// `<sig_owner> <pubkey_owner> <sig_issuer> <pubkey_issuer> OP_FALSE`
///
/// Both the owner and the issuer sign the same sighash for this input.
/// `OP_FALSE` selects the `OP_ELSE` branch of the dual-path locking script,
/// where the checkpoint gate verifies the issuer's identity and signature,
/// then the STAS v2 body verifies the owner's signature.
pub struct StasBtgCheckpointUnlockingTemplate {
    /// Private key of the current token owner (signs the token input).
    owner_private_key: PrivateKey,
    /// Private key of the issuer / redemption key holder (co-signs for attestation).
    issuer_private_key: PrivateKey,
    /// Sighash flag (defaults to `SIGHASH_ALL | SIGHASH_FORKID`).
    sighash_flag: u32,
}

/// Create a STAS-BTG checkpoint unlocker for co-signed attestation (Path B).
///
/// The resulting unlocking script selects the `OP_ELSE` branch via `OP_FALSE`.
/// Both the owner and the issuer must provide their private keys; the issuer
/// co-signs without ever taking custody of the token.
///
/// # Arguments
/// * `owner_private_key` - The current token owner's private key.
/// * `issuer_private_key` - The issuer's (redemption key holder's) private key.
/// * `sighash_flag` - Optional sighash flag. Defaults to `SIGHASH_ALL_FORKID`.
///
/// # Returns
/// A [`StasBtgCheckpointUnlockingTemplate`] implementing [`UnlockingScriptTemplate`].
pub fn unlock_btg_checkpoint(
    owner_private_key: PrivateKey,
    issuer_private_key: PrivateKey,
    sighash_flag: Option<u32>,
) -> StasBtgCheckpointUnlockingTemplate {
    StasBtgCheckpointUnlockingTemplate {
        owner_private_key,
        issuer_private_key,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
    }
}

impl UnlockingScriptTemplate for StasBtgCheckpointUnlockingTemplate {
    /// Sign the specified input and produce the checkpoint unlocking script.
    ///
    /// Builds: `<sig_owner> <pubkey_owner> <sig_issuer> <pubkey_issuer> OP_FALSE`
    ///
    /// Both keys sign the same BIP143 sighash for this input. `OP_FALSE`
    /// selects the OP_ELSE (checkpoint) branch.
    fn sign(&self, tx: &Transaction, input_index: u32) -> Result<Script, TransactionError> {
        let idx = input_index as usize;

        if idx >= tx.inputs.len() {
            return Err(TransactionError::SigningError(format!(
                "input index {} out of range (tx has {} inputs)",
                idx,
                tx.inputs.len()
            )));
        }

        let input = &tx.inputs[idx];
        if input.source_tx_output().is_none() {
            return Err(TransactionError::SigningError(
                "missing source output on input (no previous tx info)".to_string(),
            ));
        }

        // Compute sighash (same for both owner and issuer)
        let sig_hash = tx.calc_input_signature_hash(idx, self.sighash_flag)?;

        // Owner signature
        let owner_signature = self.owner_private_key.sign(&sig_hash)?;
        let owner_pubkey_bytes = self.owner_private_key.pub_key().to_compressed();
        let owner_der = owner_signature.to_der();
        let mut owner_sig_buf = Vec::with_capacity(owner_der.len() + 1);
        owner_sig_buf.extend_from_slice(&owner_der);
        owner_sig_buf.push(self.sighash_flag as u8);

        // Issuer signature
        let issuer_signature = self.issuer_private_key.sign(&sig_hash)?;
        let issuer_pubkey_bytes = self.issuer_private_key.pub_key().to_compressed();
        let issuer_der = issuer_signature.to_der();
        let mut issuer_sig_buf = Vec::with_capacity(issuer_der.len() + 1);
        issuer_sig_buf.extend_from_slice(&issuer_der);
        issuer_sig_buf.push(self.sighash_flag as u8);

        // Build: <sig_owner> <pubkey_owner> <sig_issuer> <pubkey_issuer> OP_FALSE
        let mut script = Script::new();
        script.append_push_data(&owner_sig_buf)?;
        script.append_push_data(&owner_pubkey_bytes)?;
        script.append_push_data(&issuer_sig_buf)?;
        script.append_push_data(&issuer_pubkey_bytes)?;
        script.append_opcodes(&[0x00])?; // OP_FALSE — selects OP_ELSE branch

        Ok(script)
    }

    /// Estimate the byte length of a STAS-BTG checkpoint unlocking script.
    ///
    /// Two signatures (~74 bytes each with sighash byte) + two compressed
    /// pubkeys (34 bytes each with push opcode) + 1 byte OP_FALSE = ~217 bytes.
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        // sig_owner(~74) + pubkey_owner(34) + sig_issuer(~74) + pubkey_issuer(34) + OP_FALSE(1)
        217
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_primitives::ec::PrivateKey;
    use bsv_primitives::hash::hash160;
    use bsv_script::Address;
    use bsv_transaction::input::TransactionInput;
    use bsv_transaction::output::TransactionOutput;
    use bsv_transaction::template::p2pkh;

    /// Build a dummy previous transaction with a P2PKH output.
    fn build_prev_tx() -> (Transaction, Vec<u8>) {
        let mut prev_tx = Transaction::new();

        let mut input = TransactionInput::new();
        input.source_txid = [0xcc; 32];
        input.source_tx_out_index = 0;
        input.unlocking_script = Some(Script::new());
        input.sequence_number = 0xffffffff;
        prev_tx.add_input(input);

        let key = PrivateKey::new();
        let pubkey = key.pub_key().to_compressed();
        let pkh = hash160(&pubkey);
        let addr = Address::from_public_key_hash(&pkh, bsv_script::Network::Mainnet);
        let locking = p2pkh::lock(&addr).unwrap();

        prev_tx.add_output(TransactionOutput {
            satoshis: 10000,
            locking_script: locking,
            change: false,
        });

        let raw = prev_tx.to_bytes();
        (prev_tx, raw)
    }

    /// Helper to build a spending TX with the given unlocking template.
    fn build_spending_tx(prev_tx: &Transaction, prev_raw: &[u8]) -> Transaction {
        let prev_txid_bytes = bsv_primitives::hash::sha256d(prev_raw);
        let key = PrivateKey::new();
        let pubkey = key.pub_key().to_compressed();
        let pkh = hash160(&pubkey);
        let addr = Address::from_public_key_hash(&pkh, bsv_script::Network::Mainnet);
        let locking = p2pkh::lock(&addr).unwrap();

        let mut tx = Transaction::new();
        let mut input = TransactionInput::new();
        let mut txid_le = prev_txid_bytes;
        txid_le.reverse();
        input.source_txid = txid_le;
        input.source_tx_out_index = 0;
        input.set_source_output(Some(TransactionOutput {
            satoshis: 10000,
            locking_script: prev_tx.outputs[0].locking_script.clone(),
            change: false,
        }));
        input.sequence_number = 0xffffffff;
        tx.add_input(input);

        tx.add_output(TransactionOutput {
            satoshis: 10000,
            locking_script: locking,
            change: false,
        });

        tx
    }

    #[test]
    fn btg_unlocking_script_ends_with_op_true() {
        let (prev_tx, prev_raw) = build_prev_tx();
        let key = PrivateKey::new();
        let tx = build_spending_tx(&prev_tx, &prev_raw);

        let template = unlock_btg(key, None, prev_raw, 0);
        let unlocking_script = template.sign(&tx, 0).unwrap();
        let script_bytes = unlocking_script.to_bytes();

        assert!(
            !script_bytes.is_empty(),
            "unlocking script should not be empty"
        );

        // Last byte should be OP_TRUE (0x51) for path selection
        assert_eq!(
            *script_bytes.last().unwrap(),
            0x51,
            "BTG proof unlocking script should end with OP_TRUE (0x51)"
        );

        // Should be longer than standard P2PKH (~106 bytes)
        assert!(
            script_bytes.len() > 106,
            "BTG unlocking script ({} bytes) should be longer than P2PKH (106 bytes)",
            script_bytes.len()
        );
    }

    #[test]
    fn checkpoint_unlocking_script_ends_with_op_false() {
        let (prev_tx, prev_raw) = build_prev_tx();
        let owner_key = PrivateKey::new();
        let issuer_key = PrivateKey::new();
        let tx = build_spending_tx(&prev_tx, &prev_raw);

        let template = unlock_btg_checkpoint(owner_key, issuer_key, None);
        let unlocking_script = template.sign(&tx, 0).unwrap();
        let script_bytes = unlocking_script.to_bytes();

        assert!(
            !script_bytes.is_empty(),
            "checkpoint unlocking script should not be empty"
        );

        // Last byte should be OP_FALSE (0x00) for checkpoint path selection
        assert_eq!(
            *script_bytes.last().unwrap(),
            0x00,
            "checkpoint unlocking script should end with OP_FALSE (0x00)"
        );

        // Should be approximately 217 bytes (2 sigs + 2 pubkeys + OP_FALSE)
        assert!(
            script_bytes.len() > 200 && script_bytes.len() < 250,
            "checkpoint unlocking script ({} bytes) should be ~217 bytes",
            script_bytes.len()
        );
    }

    #[test]
    fn estimate_length_accounts_for_prev_tx() {
        let (_prev_tx, prev_raw) = build_prev_tx();
        let prev_raw_len = prev_raw.len() as u32;
        let key = PrivateKey::new();

        let template = unlock_btg(key, None, prev_raw, 0);

        let dummy_tx = Transaction::new();
        let estimated = template.estimate_length(&dummy_tx, 0);

        // Should be at least 106 (base) + prev_raw_len
        assert!(
            estimated >= 106 + prev_raw_len,
            "estimated length ({estimated}) should be >= 106 + {prev_raw_len}"
        );
    }

    #[test]
    fn sign_fails_for_out_of_range_input() {
        let (_prev_tx, prev_raw) = build_prev_tx();
        let key = PrivateKey::new();

        let template = unlock_btg(key, None, prev_raw, 0);
        let tx = Transaction::new(); // empty tx, no inputs

        let result = template.sign(&tx, 0);
        assert!(result.is_err());
    }
}
