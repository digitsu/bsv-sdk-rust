//! DSTAS transaction factories.
//!
//! Pure functions that build complete, signed transactions for dSTAS token
//! operations: two-tx issuance, base spend, freeze, unfreeze, and swap.

use bsv_primitives::chainhash::Hash;
use bsv_primitives::ec::PrivateKey;
use bsv_script::opcodes::{OP_FALSE, OP_RETURN};
use bsv_script::Script;
use bsv_transaction::input::TransactionInput;
use bsv_transaction::output::TransactionOutput;
use bsv_transaction::template::p2pkh;
use bsv_transaction::template::UnlockingScriptTemplate;
use bsv_transaction::transaction::Transaction;

use crate::error::TokenError;
use crate::scheme::TokenScheme;
use crate::script::dstas_builder::build_dstas_locking_script;
use crate::template::dstas as dstas_template;
use crate::types::DstasSpendType;

// -----------------------------------------------------------------------
// Config structs
// -----------------------------------------------------------------------

/// A single output in a DSTAS issuance.
pub struct DstasIssueOutput {
    /// Satoshi value for this token output.
    pub satoshis: u64,
    /// Owner public key hash (20 bytes).
    pub owner_pkh: [u8; 20],
    /// Whether this token is freezable.
    pub freezable: bool,
}

/// Configuration for DSTAS issuance (two-transaction flow).
pub struct DstasIssueConfig {
    /// The token scheme to embed.
    pub scheme: TokenScheme,
    /// Funding UTXO txid.
    pub funding_txid: Hash,
    /// Funding UTXO vout.
    pub funding_vout: u32,
    /// Funding UTXO satoshis.
    pub funding_satoshis: u64,
    /// Funding UTXO locking script.
    pub funding_locking_script: Script,
    /// Private key to sign funding input.
    pub funding_private_key: PrivateKey,
    /// Token outputs to create.
    pub outputs: Vec<DstasIssueOutput>,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

/// Result of the two-transaction DSTAS issuance flow.
pub struct DstasIssueTxs {
    /// The contract transaction.
    pub contract_tx: Transaction,
    /// The issue transaction that spends the contract output.
    pub issue_tx: Transaction,
}

/// A token input for DSTAS spend operations.
pub struct TokenInput {
    /// UTXO txid.
    pub txid: Hash,
    /// UTXO vout.
    pub vout: u32,
    /// UTXO satoshis.
    pub satoshis: u64,
    /// UTXO locking script.
    pub locking_script: Script,
    /// Private key to sign.
    pub private_key: PrivateKey,
}

/// Parameters for a DSTAS output in spend operations.
#[derive(Clone)]
pub struct DstasOutputParams {
    /// Satoshi value.
    pub satoshis: u64,
    /// Owner public key hash.
    pub owner_pkh: [u8; 20],
    /// Redemption public key hash.
    pub redemption_pkh: [u8; 20],
    /// Whether the token is frozen.
    pub frozen: bool,
    /// Whether the token is freezable.
    pub freezable: bool,
    /// Additional service field data.
    pub service_fields: Vec<Vec<u8>>,
    /// Additional optional data.
    pub optional_data: Vec<Vec<u8>>,
}

/// Configuration for a generic DSTAS spend transaction.
pub struct DstasBaseConfig {
    /// Token inputs (1 or 2).
    pub token_inputs: Vec<TokenInput>,
    /// Fee UTXO txid.
    pub fee_txid: Hash,
    /// Fee UTXO vout.
    pub fee_vout: u32,
    /// Fee UTXO satoshis.
    pub fee_satoshis: u64,
    /// Fee UTXO locking script.
    pub fee_locking_script: Script,
    /// Fee UTXO private key.
    pub fee_private_key: PrivateKey,
    /// Output destinations.
    pub destinations: Vec<DstasOutputParams>,
    /// Spend type for this transaction.
    pub spend_type: DstasSpendType,
    /// Fee rate in satoshis per kilobyte.
    pub fee_rate: u64,
}

// -----------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------

/// Estimate transaction size.
fn estimate_size(num_inputs: usize, outputs: &[TransactionOutput]) -> usize {
    let mut size = 4 + 1 + 1 + 4;
    size += num_inputs * (32 + 4 + 1 + 106 + 4);
    for output in outputs {
        size += 8 + 1 + output.locking_script.len();
    }
    size
}

/// Add a change output for the fee payer. Returns error if insufficient funds.
fn add_fee_change(
    tx: &mut Transaction,
    fee_satoshis: u64,
    fee_private_key: &PrivateKey,
    fee_rate: u64,
) -> Result<(), TokenError> {
    let est_size = estimate_size(tx.inputs.len(), &tx.outputs) + 34;
    let fee = (est_size as u64 * fee_rate).div_ceil(1000);

    if fee_satoshis < fee {
        return Err(TokenError::InsufficientFunds {
            needed: fee,
            available: fee_satoshis,
        });
    }

    let change = fee_satoshis - fee;
    if change > 0 {
        let change_address = bsv_script::Address::from_public_key_hash(
            &bsv_primitives::hash::hash160(&fee_private_key.pub_key().to_compressed()),
            bsv_script::Network::Mainnet,
        );
        let change_script = p2pkh::lock(&change_address)?;
        tx.add_output(TransactionOutput {
            satoshis: change,
            locking_script: change_script,
            change: true,
        });
    }

    Ok(())
}

// -----------------------------------------------------------------------
// Factory functions
// -----------------------------------------------------------------------

/// Build the two-transaction DSTAS issuance flow.
///
/// # Transaction 1 (Contract TX)
/// - Input 0: Funding UTXO (P2PKH)
/// - Output 0: P2PKH contract output (total token satoshis)
/// - Output 1: OP_RETURN with scheme JSON
/// - Output 2: Change
///
/// # Transaction 2 (Issue TX)
/// - Input 0: Contract output from TX 1
/// - Input 1: Change output from TX 1 (for fees)
/// - Outputs 0..N-1: DSTAS token outputs
/// - Output N: Change
pub fn build_dstas_issue_txs(config: &DstasIssueConfig) -> Result<DstasIssueTxs, TokenError> {
    if config.outputs.is_empty() {
        return Err(TokenError::InvalidDestination(
            "at least one output required for DSTAS issuance".into(),
        ));
    }

    let total_tokens: u64 = config.outputs.iter().map(|o| o.satoshis).sum();
    if total_tokens == 0 {
        return Err(TokenError::InvalidDestination(
            "total token satoshis must be > 0".into(),
        ));
    }

    // Derive issuer address from funding key
    let issuer_pkh =
        bsv_primitives::hash::hash160(&config.funding_private_key.pub_key().to_compressed());
    let issuer_address =
        bsv_script::Address::from_public_key_hash(&issuer_pkh, bsv_script::Network::Mainnet);

    // --- Contract TX ---
    let mut contract_tx = Transaction::new();

    // Funding input
    let mut fund_input = TransactionInput::new();
    fund_input.source_txid = *config.funding_txid.as_bytes();
    fund_input.source_tx_out_index = config.funding_vout;
    fund_input.set_source_output(Some(TransactionOutput {
        satoshis: config.funding_satoshis,
        locking_script: config.funding_locking_script.clone(),
        change: false,
    }));
    contract_tx.add_input(fund_input);

    // Output 0: contract P2PKH
    let contract_script = p2pkh::lock(&issuer_address)?;
    contract_tx.add_output(TransactionOutput {
        satoshis: total_tokens,
        locking_script: contract_script,
        change: false,
    });

    // Output 1: OP_RETURN scheme
    let scheme_bytes = config.scheme.to_bytes()?;
    let mut op_return_script = Script::new();
    op_return_script.append_opcodes(&[OP_FALSE, OP_RETURN])?;
    op_return_script.append_push_data(&scheme_bytes)?;
    contract_tx.add_output(TransactionOutput {
        satoshis: 0,
        locking_script: op_return_script,
        change: false,
    });

    // Estimate fee for contract TX
    let est_size = estimate_size(1, &contract_tx.outputs) + 34;
    let contract_fee = (est_size as u64 * config.fee_rate).div_ceil(1000);

    let needed = total_tokens + contract_fee;
    if config.funding_satoshis < needed {
        return Err(TokenError::InsufficientFunds {
            needed,
            available: config.funding_satoshis,
        });
    }

    let contract_change = config.funding_satoshis - total_tokens - contract_fee;
    if contract_change > 0 {
        let change_script = p2pkh::lock(&issuer_address)?;
        contract_tx.add_output(TransactionOutput {
            satoshis: contract_change,
            locking_script: change_script,
            change: true,
        });
    }

    // Sign contract TX
    let contract_unlocker = p2pkh::unlock(config.funding_private_key.clone(), None);
    let contract_sig = contract_unlocker.sign(&contract_tx, 0)?;
    contract_tx.inputs[0].unlocking_script = Some(contract_sig);

    // --- Issue TX ---
    let contract_txid = Hash::from_bytes(&contract_tx.tx_id())
        .map_err(|e| TokenError::InvalidScript(format!("txid error: {e}")))?;

    let mut issue_tx = Transaction::new();

    // Input 0: contract output
    let contract_output_script = p2pkh::lock(&issuer_address)?;
    let mut contract_input = TransactionInput::new();
    contract_input.source_txid = *contract_txid.as_bytes();
    contract_input.source_tx_out_index = 0;
    contract_input.set_source_output(Some(TransactionOutput {
        satoshis: total_tokens,
        locking_script: contract_output_script,
        change: false,
    }));
    issue_tx.add_input(contract_input);

    // Input 1: change from contract TX (for fees) — only if there was change
    let fee_available = if contract_change > 0 {
        let change_script = p2pkh::lock(&issuer_address)?;
        let mut change_input = TransactionInput::new();
        change_input.source_txid = *contract_txid.as_bytes();
        change_input.source_tx_out_index = 2; // change is output index 2
        change_input.set_source_output(Some(TransactionOutput {
            satoshis: contract_change,
            locking_script: change_script,
            change: false,
        }));
        issue_tx.add_input(change_input);
        contract_change
    } else {
        0
    };

    // Derive redemption PKH from scheme.token_id
    let redemption_pkh = issuer_pkh;

    // DSTAS token outputs
    for out in &config.outputs {
        let locking = build_dstas_locking_script(
            &out.owner_pkh,
            &redemption_pkh,
            None,
            false,
            out.freezable,
            &[],
            &[],
        )?;
        issue_tx.add_output(TransactionOutput {
            satoshis: out.satoshis,
            locking_script: locking,
            change: false,
        });
    }

    // Issue TX fee change
    if fee_available > 0 {
        add_fee_change(
            &mut issue_tx,
            fee_available,
            &config.funding_private_key,
            config.fee_rate,
        )?;
    }

    // Sign issue TX — all inputs are P2PKH (issuer key)
    for i in 0..issue_tx.inputs.len() {
        let unlocker = p2pkh::unlock(config.funding_private_key.clone(), None);
        let sig = unlocker.sign(&issue_tx, i as u32)?;
        issue_tx.inputs[i].unlocking_script = Some(sig);
    }

    Ok(DstasIssueTxs {
        contract_tx,
        issue_tx,
    })
}

/// Build a generic DSTAS spend transaction.
///
/// # Transaction structure
/// - Inputs 0..N-1: Token inputs (DSTAS, signed with DSTAS template)
/// - Input N: Fee input (P2PKH)
/// - Outputs 0..M-1: DSTAS token outputs
/// - Output M: Fee change
pub fn build_dstas_base_tx(config: &DstasBaseConfig) -> Result<Transaction, TokenError> {
    if config.destinations.is_empty() {
        return Err(TokenError::InvalidDestination(
            "at least one destination required".into(),
        ));
    }

    if config.token_inputs.is_empty() || config.token_inputs.len() > 2 {
        return Err(TokenError::InvalidDestination(
            "DSTAS base tx requires 1 or 2 token inputs".into(),
        ));
    }

    let total_token_in: u64 = config.token_inputs.iter().map(|i| i.satoshis).sum();
    let total_token_out: u64 = config.destinations.iter().map(|d| d.satoshis).sum();
    if total_token_in != total_token_out {
        return Err(TokenError::AmountMismatch {
            expected: total_token_in,
            actual: total_token_out,
        });
    }

    let mut tx = Transaction::new();

    // Token inputs
    for ti in &config.token_inputs {
        let mut input = TransactionInput::new();
        input.source_txid = *ti.txid.as_bytes();
        input.source_tx_out_index = ti.vout;
        input.set_source_output(Some(TransactionOutput {
            satoshis: ti.satoshis,
            locking_script: ti.locking_script.clone(),
            change: false,
        }));
        tx.add_input(input);
    }

    // Fee input
    let mut fee_input = TransactionInput::new();
    fee_input.source_txid = *config.fee_txid.as_bytes();
    fee_input.source_tx_out_index = config.fee_vout;
    fee_input.set_source_output(Some(TransactionOutput {
        satoshis: config.fee_satoshis,
        locking_script: config.fee_locking_script.clone(),
        change: false,
    }));
    tx.add_input(fee_input);

    // DSTAS outputs
    for dest in &config.destinations {
        let locking = build_dstas_locking_script(
            &dest.owner_pkh,
            &dest.redemption_pkh,
            None,
            dest.frozen,
            dest.freezable,
            &dest.service_fields,
            &dest.optional_data,
        )?;
        tx.add_output(TransactionOutput {
            satoshis: dest.satoshis,
            locking_script: locking,
            change: false,
        });
    }

    // Fee change
    add_fee_change(
        &mut tx,
        config.fee_satoshis,
        &config.fee_private_key,
        config.fee_rate,
    )?;

    // Sign token inputs with DSTAS template
    for (i, ti) in config.token_inputs.iter().enumerate() {
        let unlocker = dstas_template::unlock(ti.private_key.clone(), config.spend_type, None);
        let sig = unlocker.sign(&tx, i as u32)?;
        tx.inputs[i].unlocking_script = Some(sig);
    }

    // Sign fee input with P2PKH
    let fee_idx = config.token_inputs.len();
    let p2pkh_unlocker = p2pkh::unlock(config.fee_private_key.clone(), None);
    let fee_sig = p2pkh_unlocker.sign(&tx, fee_idx as u32)?;
    tx.inputs[fee_idx].unlocking_script = Some(fee_sig);

    Ok(tx)
}

/// Build a DSTAS freeze transaction.
///
/// Wrapper around [`build_dstas_base_tx`] that sets `frozen = true` on all outputs
/// and uses `DstasSpendType::FreezeUnfreeze`.
pub fn build_dstas_freeze_tx(config: &mut DstasBaseConfig) -> Result<Transaction, TokenError> {
    config.spend_type = DstasSpendType::FreezeUnfreeze;
    for dest in &mut config.destinations {
        dest.frozen = true;
    }
    build_dstas_base_tx(config)
}

/// Build a DSTAS unfreeze transaction.
///
/// Wrapper around [`build_dstas_base_tx`] that sets `frozen = false` on all outputs
/// and uses `DstasSpendType::FreezeUnfreeze`.
pub fn build_dstas_unfreeze_tx(config: &mut DstasBaseConfig) -> Result<Transaction, TokenError> {
    config.spend_type = DstasSpendType::FreezeUnfreeze;
    for dest in &mut config.destinations {
        dest.frozen = false;
    }
    build_dstas_base_tx(config)
}

/// Build a DSTAS swap flow transaction.
///
/// Requires exactly 2 token inputs. Uses `DstasSpendType::Transfer`.
pub fn build_dstas_swap_flow_tx(config: &mut DstasBaseConfig) -> Result<Transaction, TokenError> {
    if config.token_inputs.len() != 2 {
        return Err(TokenError::InvalidDestination(
            "swap flow requires exactly 2 token inputs".into(),
        ));
    }
    config.spend_type = DstasSpendType::Transfer;
    build_dstas_base_tx(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bsv_primitives::chainhash::Hash;
    use bsv_primitives::ec::PrivateKey;
    use crate::scheme::{Authority, TokenScheme};
    use crate::token_id::TokenId;
    use crate::script::reader::read_locking_script;
    use crate::ScriptType;

    fn test_key() -> PrivateKey {
        PrivateKey::new()
    }

    fn test_p2pkh_script(key: &PrivateKey) -> Script {
        let pkh = bsv_primitives::hash::hash160(&key.pub_key().to_compressed());
        let addr = bsv_script::Address::from_public_key_hash(&pkh, bsv_script::Network::Mainnet);
        p2pkh::lock(&addr).unwrap()
    }

    fn dummy_hash() -> Hash {
        Hash::from_bytes(&[0xaa; 32]).unwrap()
    }

    fn test_scheme() -> TokenScheme {
        TokenScheme {
            name: "TestDSTAS".into(),
            token_id: TokenId::from_pkh([0xaa; 20]),
            symbol: "TDSTAS".into(),
            satoshis_per_token: 1,
            freeze: true,
            confiscation: false,
            is_divisible: true,
            authority: Authority {
                m: 1,
                public_keys: vec!["02abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890ab".into()],
            },
        }
    }

    fn make_dstas_locking(owner_pkh: &[u8; 20], redemption_pkh: &[u8; 20]) -> Script {
        build_dstas_locking_script(owner_pkh, redemption_pkh, None, false, true, &[], &[]).unwrap()
    }

    // ---------------------------------------------------------------
    // Issue flow tests
    // ---------------------------------------------------------------

    #[test]
    fn issue_txs_structure() {
        let key = test_key();
        let config = DstasIssueConfig {
            scheme: test_scheme(),
            funding_txid: dummy_hash(),
            funding_vout: 0,
            funding_satoshis: 100_000,
            funding_locking_script: test_p2pkh_script(&key),
            funding_private_key: key,
            outputs: vec![
                DstasIssueOutput {
                    satoshis: 5000,
                    owner_pkh: [0x11; 20],
                    freezable: true,
                },
                DstasIssueOutput {
                    satoshis: 5000,
                    owner_pkh: [0x22; 20],
                    freezable: false,
                },
            ],
            fee_rate: 500,
        };

        let result = build_dstas_issue_txs(&config).unwrap();

        // Contract TX: 1 input, 2-3 outputs (contract + OP_RETURN + optional change)
        assert_eq!(result.contract_tx.input_count(), 1);
        assert!(result.contract_tx.output_count() >= 2);
        assert_eq!(result.contract_tx.outputs[0].satoshis, 10000);
        assert_eq!(result.contract_tx.outputs[1].satoshis, 0); // OP_RETURN

        // Issue TX: 1-2 inputs, 2-3 outputs (tokens + optional change)
        assert!(result.issue_tx.input_count() >= 1);
        assert!(result.issue_tx.output_count() >= 2);
        assert_eq!(result.issue_tx.outputs[0].satoshis, 5000);
        assert_eq!(result.issue_tx.outputs[1].satoshis, 5000);

        // All inputs should be signed
        for input in &result.contract_tx.inputs {
            assert!(input.unlocking_script.is_some());
        }
        for input in &result.issue_tx.inputs {
            assert!(input.unlocking_script.is_some());
        }
    }

    #[test]
    fn issue_txid_chaining() {
        let key = test_key();
        let config = DstasIssueConfig {
            scheme: test_scheme(),
            funding_txid: dummy_hash(),
            funding_vout: 0,
            funding_satoshis: 100_000,
            funding_locking_script: test_p2pkh_script(&key),
            funding_private_key: key,
            outputs: vec![DstasIssueOutput {
                satoshis: 10000,
                owner_pkh: [0x11; 20],
                freezable: true,
            }],
            fee_rate: 500,
        };

        let result = build_dstas_issue_txs(&config).unwrap();

        // Issue TX input 0 should reference contract TX's txid
        let contract_txid = result.contract_tx.tx_id();
        assert_eq!(result.issue_tx.inputs[0].source_txid, contract_txid);
    }

    #[test]
    fn issue_empty_outputs_rejected() {
        let key = test_key();
        let config = DstasIssueConfig {
            scheme: test_scheme(),
            funding_txid: dummy_hash(),
            funding_vout: 0,
            funding_satoshis: 100_000,
            funding_locking_script: test_p2pkh_script(&key),
            funding_private_key: key,
            outputs: vec![],
            fee_rate: 500,
        };

        assert!(build_dstas_issue_txs(&config).is_err());
    }

    #[test]
    fn issue_insufficient_funds() {
        let key = test_key();
        let config = DstasIssueConfig {
            scheme: test_scheme(),
            funding_txid: dummy_hash(),
            funding_vout: 0,
            funding_satoshis: 100, // too low
            funding_locking_script: test_p2pkh_script(&key),
            funding_private_key: key,
            outputs: vec![DstasIssueOutput {
                satoshis: 10000,
                owner_pkh: [0x11; 20],
                freezable: true,
            }],
            fee_rate: 500,
        };

        assert!(build_dstas_issue_txs(&config).is_err());
    }

    // ---------------------------------------------------------------
    // Base TX tests
    // ---------------------------------------------------------------

    #[test]
    fn base_tx_structure() {
        let token_key = test_key();
        let fee_key = test_key();
        let owner_pkh = [0x11; 20];
        let redemption_pkh = [0x22; 20];

        let config = DstasBaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: make_dstas_locking(&owner_pkh, &redemption_pkh),
                private_key: token_key,
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![DstasOutputParams {
                satoshis: 5000,
                owner_pkh: [0x33; 20],
                redemption_pkh,
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
            }],
            spend_type: DstasSpendType::Transfer,
            fee_rate: 500,
        };

        let tx = build_dstas_base_tx(&config).unwrap();
        assert_eq!(tx.input_count(), 2); // 1 token + 1 fee
        assert!(tx.output_count() >= 1); // 1 token + optional change
        assert_eq!(tx.outputs[0].satoshis, 5000);

        // All signed
        for input in &tx.inputs {
            assert!(input.unlocking_script.is_some());
        }
    }

    #[test]
    fn base_tx_amount_conservation() {
        let token_key = test_key();
        let fee_key = test_key();

        let config = DstasBaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 10000,
                locking_script: make_dstas_locking(&[0x11; 20], &[0x22; 20]),
                private_key: token_key,
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                DstasOutputParams {
                    satoshis: 4000,
                    owner_pkh: [0x33; 20],
                    redemption_pkh: [0x22; 20],
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                },
                DstasOutputParams {
                    satoshis: 6000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: [0x22; 20],
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                },
            ],
            spend_type: DstasSpendType::Transfer,
            fee_rate: 500,
        };

        let tx = build_dstas_base_tx(&config).unwrap();
        // Token outputs should sum to input
        let token_out: u64 = tx.outputs.iter().filter(|o| !o.change).map(|o| o.satoshis).sum();
        assert_eq!(token_out, 10000);
    }

    #[test]
    fn base_tx_amount_mismatch() {
        let token_key = test_key();
        let fee_key = test_key();

        let config = DstasBaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 10000,
                locking_script: make_dstas_locking(&[0x11; 20], &[0x22; 20]),
                private_key: token_key,
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![DstasOutputParams {
                satoshis: 9000, // != 10000
                owner_pkh: [0x33; 20],
                redemption_pkh: [0x22; 20],
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
            }],
            spend_type: DstasSpendType::Transfer,
            fee_rate: 500,
        };

        assert!(build_dstas_base_tx(&config).is_err());
    }

    #[test]
    fn base_tx_empty_destinations() {
        let token_key = test_key();
        let fee_key = test_key();

        let config = DstasBaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: make_dstas_locking(&[0x11; 20], &[0x22; 20]),
                private_key: token_key,
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![],
            spend_type: DstasSpendType::Transfer,
            fee_rate: 500,
        };

        assert!(build_dstas_base_tx(&config).is_err());
    }

    #[test]
    fn base_tx_too_many_inputs() {
        let fee_key = test_key();

        let config = DstasBaseConfig {
            token_inputs: vec![
                TokenInput { txid: dummy_hash(), vout: 0, satoshis: 1000, locking_script: make_dstas_locking(&[0x11; 20], &[0x22; 20]), private_key: test_key() },
                TokenInput { txid: dummy_hash(), vout: 1, satoshis: 1000, locking_script: make_dstas_locking(&[0x11; 20], &[0x22; 20]), private_key: test_key() },
                TokenInput { txid: dummy_hash(), vout: 2, satoshis: 1000, locking_script: make_dstas_locking(&[0x11; 20], &[0x22; 20]), private_key: test_key() },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 3,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![DstasOutputParams {
                satoshis: 3000,
                owner_pkh: [0x33; 20],
                redemption_pkh: [0x22; 20],
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
            }],
            spend_type: DstasSpendType::Transfer,
            fee_rate: 500,
        };

        assert!(build_dstas_base_tx(&config).is_err());
    }

    // ---------------------------------------------------------------
    // Freeze / Unfreeze tests
    // ---------------------------------------------------------------

    #[test]
    fn freeze_tx_output_is_frozen() {
        let token_key = test_key();
        let fee_key = test_key();

        let mut config = DstasBaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: make_dstas_locking(&[0x11; 20], &[0x22; 20]),
                private_key: token_key,
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![DstasOutputParams {
                satoshis: 5000,
                owner_pkh: [0x33; 20],
                redemption_pkh: [0x22; 20],
                frozen: false, // will be overridden
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
            }],
            spend_type: DstasSpendType::Transfer, // will be overridden
            fee_rate: 500,
        };

        let tx = build_dstas_freeze_tx(&mut config).unwrap();

        // Parse the first output script to verify frozen
        let parsed = read_locking_script(tx.outputs[0].locking_script.to_bytes());
        assert_eq!(parsed.script_type, ScriptType::Dstas);
        let dstas = parsed.dstas.unwrap();
        assert!(dstas.frozen);
    }

    #[test]
    fn unfreeze_tx_output_is_not_frozen() {
        let token_key = test_key();
        let fee_key = test_key();

        let mut config = DstasBaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: make_dstas_locking(&[0x11; 20], &[0x22; 20]),
                private_key: token_key,
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![DstasOutputParams {
                satoshis: 5000,
                owner_pkh: [0x33; 20],
                redemption_pkh: [0x22; 20],
                frozen: true, // will be overridden to false
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
            }],
            spend_type: DstasSpendType::Transfer,
            fee_rate: 500,
        };

        let tx = build_dstas_unfreeze_tx(&mut config).unwrap();

        let parsed = read_locking_script(tx.outputs[0].locking_script.to_bytes());
        assert_eq!(parsed.script_type, ScriptType::Dstas);
        let dstas = parsed.dstas.unwrap();
        assert!(!dstas.frozen);
    }

    // ---------------------------------------------------------------
    // Swap flow tests
    // ---------------------------------------------------------------

    #[test]
    fn swap_flow_requires_two_inputs() {
        let fee_key = test_key();

        let mut config = DstasBaseConfig {
            token_inputs: vec![TokenInput {
                txid: dummy_hash(),
                vout: 0,
                satoshis: 5000,
                locking_script: make_dstas_locking(&[0x11; 20], &[0x22; 20]),
                private_key: test_key(),
            }],
            fee_txid: dummy_hash(),
            fee_vout: 1,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![DstasOutputParams {
                satoshis: 5000,
                owner_pkh: [0x33; 20],
                redemption_pkh: [0x22; 20],
                frozen: false,
                freezable: true,
                service_fields: vec![],
                optional_data: vec![],
            }],
            spend_type: DstasSpendType::Transfer,
            fee_rate: 500,
        };

        assert!(build_dstas_swap_flow_tx(&mut config).is_err());
    }

    #[test]
    fn swap_flow_with_two_inputs() {
        let fee_key = test_key();

        let mut config = DstasBaseConfig {
            token_inputs: vec![
                TokenInput {
                    txid: dummy_hash(),
                    vout: 0,
                    satoshis: 3000,
                    locking_script: make_dstas_locking(&[0x11; 20], &[0x22; 20]),
                    private_key: test_key(),
                },
                TokenInput {
                    txid: dummy_hash(),
                    vout: 1,
                    satoshis: 7000,
                    locking_script: make_dstas_locking(&[0x33; 20], &[0x22; 20]),
                    private_key: test_key(),
                },
            ],
            fee_txid: dummy_hash(),
            fee_vout: 2,
            fee_satoshis: 50_000,
            fee_locking_script: test_p2pkh_script(&fee_key),
            fee_private_key: fee_key,
            destinations: vec![
                DstasOutputParams {
                    satoshis: 3000,
                    owner_pkh: [0x44; 20],
                    redemption_pkh: [0x22; 20],
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                },
                DstasOutputParams {
                    satoshis: 7000,
                    owner_pkh: [0x55; 20],
                    redemption_pkh: [0x22; 20],
                    frozen: false,
                    freezable: true,
                    service_fields: vec![],
                    optional_data: vec![],
                },
            ],
            spend_type: DstasSpendType::SwapCancellation, // will be overridden
            fee_rate: 500,
        };

        let tx = build_dstas_swap_flow_tx(&mut config).unwrap();
        assert_eq!(tx.input_count(), 3); // 2 token + 1 fee
        assert!(tx.output_count() >= 2);
    }
}
