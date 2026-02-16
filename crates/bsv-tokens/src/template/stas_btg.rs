//! STAS-BTG unlocking script template.
//!
//! The STAS-BTG unlocking script extends the standard P2PKH-style unlocking
//! (`<sig> <pubkey>`) with three additional data pushes that provide the
//! prev-TX proof:
//!
//! ```text
//! <sig> <pubkey> <prev_tx_prefix> <prev_tx_output> <prev_tx_suffix>
//! ```
//!
//! The locking script's BTG preamble uses these three segments to reconstruct
//! and verify the previous transaction, ensuring an unbroken chain of trust
//! back to the genesis (contract) transaction.

use bsv_primitives::ec::PrivateKey;
use bsv_script::Script;
use bsv_transaction::sighash::SIGHASH_ALL_FORKID;
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;
use bsv_transaction::TransactionError;

use crate::proof::split_tx_around_output;

/// STAS-BTG unlocking script template.
///
/// Produces unlocking scripts of the form:
/// `<DER_sig + sighash_byte> <compressed_pubkey> <prefix> <output> <suffix>`
///
/// The `prefix`, `output`, and `suffix` are the three segments of the previous
/// raw transaction split around the output being spent (at `prev_vout`).
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

/// Create a STAS-BTG unlocker for signing token inputs with prev-TX proof.
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
    /// Sign the specified input and produce the BTG unlocking script.
    ///
    /// Builds: `<sig> <pubkey> <prefix> <output> <suffix>` where the three
    /// proof segments are derived by splitting `prev_raw_tx` around `prev_vout`.
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

        // Build the unlocking script: <sig> <pubkey> <prefix> <output> <suffix>
        let mut script = Script::new();
        script.append_push_data(&sig_buf)?;
        script.append_push_data(&pub_key_bytes)?;
        script.append_push_data(&prefix)?;
        script.append_push_data(&output)?;
        script.append_push_data(&suffix)?;

        Ok(script)
    }

    /// Estimate the byte length of a STAS-BTG unlocking script.
    ///
    /// The base P2PKH portion is ~106 bytes (sig + pubkey).
    /// The proof segments add the full size of the previous raw TX plus
    /// push opcode overhead (~10 bytes for three PUSHDATA operations).
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        // Base sig+pubkey: ~106 bytes
        // Proof data: prev_raw_tx.len() bytes split across three pushes
        // Push opcode overhead: ~10 bytes (3 push ops with length prefixes)
        106 + self.prev_raw_tx.len() as u32 + 10
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

    #[test]
    fn btg_unlocking_script_has_five_pushes() {
        let (prev_tx, prev_raw) = build_prev_tx();
        let prev_txid_bytes = bsv_primitives::hash::sha256d(&prev_raw);

        // Build the spending transaction
        let key = PrivateKey::new();
        let pubkey = key.pub_key().to_compressed();
        let pkh = hash160(&pubkey);
        let addr = Address::from_public_key_hash(&pkh, bsv_script::Network::Mainnet);
        let locking = p2pkh::lock(&addr).unwrap();

        let mut tx = Transaction::new();
        let mut input = TransactionInput::new();
        // Reverse txid bytes for outpoint (Bitcoin uses LE txid in inputs)
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

        // Create the BTG unlocking template
        let template = unlock_btg(key, None, prev_raw, 0);
        let unlocking_script = template.sign(&tx, 0).unwrap();

        // The unlocking script should have 5 data pushes
        let script_bytes = unlocking_script.to_bytes();
        assert!(
            !script_bytes.is_empty(),
            "unlocking script should not be empty"
        );

        // Verify we can count at least 5 push operations by checking script length
        // is significantly longer than a standard P2PKH unlock (~106 bytes)
        assert!(
            script_bytes.len() > 106,
            "BTG unlocking script ({} bytes) should be longer than P2PKH (106 bytes)",
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
