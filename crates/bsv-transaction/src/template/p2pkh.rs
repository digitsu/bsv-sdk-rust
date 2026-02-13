//! Pay-to-Public-Key-Hash (P2PKH) script template.
//!
//! Creates standard P2PKH locking scripts (`OP_DUP OP_HASH160 <hash>
//! OP_EQUALVERIFY OP_CHECKSIG`) and unlocking scripts (`<sig> <pubkey>`).
//! Ported from the Go BSV SDK (`transaction/template/p2pkh`).

use bsv_primitives::ec::PrivateKey;
use bsv_script::opcodes::*;
use bsv_script::{Address, Script};

use crate::sighash::SIGHASH_ALL_FORKID;
use crate::template::UnlockingScriptTemplate;
use crate::transaction::Transaction;
use crate::TransactionError;

/// Create a P2PKH locking script from a Bitcoin address.
///
/// Produces: `OP_DUP OP_HASH160 <20-byte pubkey hash> OP_EQUALVERIFY OP_CHECKSIG`
///
/// # Arguments
/// * `address` - The Bitcoin address whose public key hash to lock to.
///
/// # Returns
/// `Ok(Script)` containing the 25-byte P2PKH locking script, or an error
/// if the address has an invalid public key hash.
pub fn lock(address: &Address) -> Result<Script, TransactionError> {
    let pkh = &address.public_key_hash;

    let mut bytes = Vec::with_capacity(25);
    bytes.push(OP_DUP);
    bytes.push(OP_HASH160);
    bytes.push(OP_DATA_20);
    bytes.extend_from_slice(pkh);
    bytes.push(OP_EQUALVERIFY);
    bytes.push(OP_CHECKSIG);

    Ok(Script::from_bytes(&bytes))
}

/// Create a P2PKH unlocker for signing transaction inputs.
///
/// # Arguments
/// * `private_key` - The private key used to sign.
/// * `sighash_flag` - Optional sighash flag. Defaults to `SIGHASH_ALL_FORKID` (0x41).
///
/// # Returns
/// A `P2PKH` instance implementing `UnlockingScriptTemplate`.
pub fn unlock(private_key: PrivateKey, sighash_flag: Option<u32>) -> P2PKH {
    P2PKH {
        private_key,
        sighash_flag: sighash_flag.unwrap_or(SIGHASH_ALL_FORKID),
    }
}

/// P2PKH signing template holding a private key and sighash flag.
///
/// Implements `UnlockingScriptTemplate` to produce unlocking scripts
/// of the form `<DER_signature + sighash_byte> <compressed_pubkey>`.
pub struct P2PKH {
    /// The private key used for ECDSA signing.
    private_key: PrivateKey,

    /// The sighash flag to use (e.g. `SIGHASH_ALL_FORKID`).
    sighash_flag: u32,
}

impl UnlockingScriptTemplate for P2PKH {
    /// Sign the specified input and produce the unlocking script.
    ///
    /// Computes the BIP-143-style signature hash for the input, signs it
    /// with the private key using RFC6979 deterministic ECDSA, and constructs
    /// the unlocking script: `<DER_sig || sighash_byte> <compressed_pubkey>`.
    ///
    /// # Arguments
    /// * `tx` - The transaction being signed.
    /// * `input_index` - The index of the input to sign.
    ///
    /// # Returns
    /// `Ok(Script)` containing the P2PKH unlocking script.
    fn sign(&self, tx: &Transaction, input_index: u32) -> Result<Script, TransactionError> {
        let idx = input_index as usize;

        if idx >= tx.inputs.len() {
            return Err(TransactionError::SigningError(format!(
                "input index {} out of range (tx has {} inputs)",
                idx,
                tx.inputs.len()
            )));
        }

        // Verify source output info is available.
        let input = &tx.inputs[idx];
        if input.source_tx_output().is_none() {
            return Err(TransactionError::SigningError(
                "missing source output on input (no previous tx info)".to_string(),
            ));
        }

        // Compute the signature hash.
        let sig_hash = tx.calc_input_signature_hash(idx, self.sighash_flag)?;

        // Sign the hash with the private key (RFC6979 deterministic ECDSA).
        let signature = self.private_key.sign(&sig_hash)?;

        // Get the compressed public key (33 bytes).
        let pub_key_bytes = self.private_key.pub_key().to_compressed();

        // Build the DER signature with sighash flag byte appended.
        let der_sig = signature.to_der();
        let mut sig_buf = Vec::with_capacity(der_sig.len() + 1);
        sig_buf.extend_from_slice(&der_sig);
        sig_buf.push(self.sighash_flag as u8);

        // Build the unlocking script: PUSHDATA(sig) PUSHDATA(pubkey).
        let mut script = Script::new();
        script.append_push_data(&sig_buf)?;
        script.append_push_data(&pub_key_bytes)?;

        Ok(script)
    }

    /// Estimate the byte length of a P2PKH unlocking script.
    ///
    /// A typical P2PKH scriptSig is approximately 106 bytes:
    /// 1 (push len) + 72 (DER sig + sighash) + 1 (push len) + 33 (compressed pubkey) = ~107
    ///
    /// # Returns
    /// 106 (standard estimate matching the Go SDK).
    fn estimate_length(&self, _tx: &Transaction, _input_index: u32) -> u32 {
        106
    }
}
