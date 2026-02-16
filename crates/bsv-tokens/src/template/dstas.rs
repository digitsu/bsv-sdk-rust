//! DSTAS unlocking script template.
//!
//! Structurally identical to the STAS unlocking script (`<sig> <pubkey>`),
//! but stores the [`DstasSpendType`] for future use when preimage-based
//! validation is added.

use bsv_primitives::ec::PrivateKey;
use bsv_script::Script;
use bsv_transaction::sighash::SIGHASH_ALL_FORKID;
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;
use bsv_transaction::TransactionError;

use crate::types::DstasSpendType;

/// DSTAS unlocking script template.
///
/// Produces `<DER_signature + sighash_byte> <compressed_pubkey>`, identical
/// to P2PKH / STAS.  The `spend_type` is stored for future preimage encoding.
pub struct DstasUnlockingTemplate {
    private_key: PrivateKey,
    sighash_flag: u32,
    /// The spend type for this unlock (stored, not yet encoded in script).
    #[allow(dead_code)]
    spend_type: DstasSpendType,
}

/// Create a DSTAS unlocker.
///
/// # Arguments
/// * `private_key` – Signing key.
/// * `spend_type` – The DSTAS spend type.
/// * `sighash_flag` – Optional sighash flag (defaults to `SIGHASH_ALL_FORKID`).
pub fn unlock(
    private_key: PrivateKey,
    spend_type: DstasSpendType,
    sighash_flag: Option<u32>,
) -> DstasUnlockingTemplate {
    DstasUnlockingTemplate {
        private_key,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
        spend_type,
    }
}

impl UnlockingScriptTemplate for DstasUnlockingTemplate {
    /// Sign the specified input and produce the unlocking script.
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

        let sig_hash = tx.calc_input_signature_hash(idx, self.sighash_flag)?;
        let signature = self.private_key.sign(&sig_hash)?;
        let pub_key_bytes = self.private_key.pub_key().to_compressed();

        let der_sig = signature.to_der();
        let mut sig_buf = Vec::with_capacity(der_sig.len() + 1);
        sig_buf.extend_from_slice(&der_sig);
        sig_buf.push(self.sighash_flag as u8);

        let mut script = Script::new();
        script.append_push_data(&sig_buf)?;
        script.append_push_data(&pub_key_bytes)?;

        Ok(script)
    }

    /// Estimate the byte length of a DSTAS unlocking script (same as P2PKH).
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        106
    }
}
