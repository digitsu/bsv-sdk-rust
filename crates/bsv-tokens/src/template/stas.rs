//! STAS unlocking script template.
//!
//! The STAS unlocking script is identical to P2PKH: `<sig> <pubkey>`.
//! The on-chain STAS script validates transaction structure; our template
//! only needs to produce a valid signature.

use bsv_primitives::ec::PrivateKey;
use bsv_script::Script;
use bsv_transaction::sighash::SIGHASH_ALL_FORKID;
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;
use bsv_transaction::TransactionError;

/// STAS unlocking script template holding a private key and sighash flag.
///
/// Produces unlocking scripts of the form `<DER_signature + sighash_byte> <compressed_pubkey>`,
/// identical to P2PKH.
pub struct StasUnlockingTemplate {
    private_key: PrivateKey,
    sighash_flag: u32,
}

/// Create a STAS unlocker for signing token inputs.
///
/// # Arguments
/// * `private_key` - The private key used to sign.
/// * `sighash_flag` - Optional sighash flag. Defaults to `SIGHASH_ALL_FORKID`.
///
/// # Returns
/// A `StasUnlockingTemplate` implementing `UnlockingScriptTemplate`.
pub fn unlock(private_key: PrivateKey, sighash_flag: Option<u32>) -> StasUnlockingTemplate {
    StasUnlockingTemplate {
        private_key,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
    }
}

impl UnlockingScriptTemplate for StasUnlockingTemplate {
    /// Sign the specified input and produce the unlocking script.
    ///
    /// Identical to P2PKH: computes BIP-143 sighash, signs with ECDSA,
    /// builds `<sig> <pubkey>`.
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

    /// Estimate the byte length of a STAS unlocking script (same as P2PKH).
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        106
    }
}
