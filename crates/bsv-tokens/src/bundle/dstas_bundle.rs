//! DSTAS multi-transaction bundle factory.

use crate::error::TokenError;
use crate::factory::dstas::{
    build_dstas_base_tx, DstasBaseConfig, DstasOutputParams, TokenInput,
};
use crate::types::DstasSpendType;
use super::planner::{plan_operations, PlannedOp};
use super::stas_bundle::{FundingUtxo, PayoutBundle, TokenUtxo};

/// Configuration for a DSTAS bundle transfer.
pub struct DstasBundleConfig {
    /// Available DSTAS token UTXOs.
    pub token_utxos: Vec<TokenUtxo>,
    /// Target output parameters.
    pub destinations: Vec<DstasOutputParams>,
    /// Fee rate in satoshis per KB.
    pub fee_rate: u64,
    /// Callback to get a funding UTXO for fees.
    pub funding_provider: Box<dyn Fn() -> Result<FundingUtxo, TokenError>>,
}

fn token_to_input(t: &TokenUtxo) -> TokenInput {
    TokenInput {
        txid: t.txid,
        vout: t.vout,
        satoshis: t.satoshis,
        locking_script: t.locking_script.clone(),
        private_key: t.private_key.clone(),
    }
}

/// Build a multi-transaction DSTAS bundle.
pub fn build_dstas_bundle(config: DstasBundleConfig) -> Result<PayoutBundle, TokenError> {
    if config.destinations.is_empty() {
        return Err(TokenError::BundleError("no destinations provided".into()));
    }

    let available: Vec<(usize, u64)> = config.token_utxos.iter().enumerate()
        .map(|(i, u)| (i, u.satoshis))
        .collect();
    let targets: Vec<u64> = config.destinations.iter().map(|d| d.satoshis).collect();

    let ops = plan_operations(&available, &targets)?;

    let mut transactions = Vec::new();

    for op in &ops {
        match op {
            PlannedOp::Transfer { source, dest_index } => {
                let funding = (config.funding_provider)()?;
                let dest = config.destinations[*dest_index].clone();
                let tx_config = DstasBaseConfig {
                    token_inputs: vec![token_to_input(&config.token_utxos[*source])],
                    fee_txid: funding.txid,
                    fee_vout: funding.vout,
                    fee_satoshis: funding.satoshis,
                    fee_locking_script: funding.locking_script,
                    fee_private_key: funding.private_key,
                    destinations: vec![dest],
                    spend_type: DstasSpendType::Transfer,
                    fee_rate: config.fee_rate,
                };
                let tx = build_dstas_base_tx(&tx_config)?;
                transactions.push(tx);
            }
            PlannedOp::Split { source, amounts } => {
                let funding = (config.funding_provider)()?;
                let dests: Vec<DstasOutputParams> = amounts.iter().enumerate().map(|(i, &amt)| {
                    if i < config.destinations.len() {
                        let mut d = config.destinations[i].clone();
                        d.satoshis = amt;
                        d
                    } else {
                        let mut d = config.destinations[0].clone();
                        d.satoshis = amt;
                        d
                    }
                }).collect();
                let tx_config = DstasBaseConfig {
                    token_inputs: vec![token_to_input(&config.token_utxos[*source])],
                    fee_txid: funding.txid,
                    fee_vout: funding.vout,
                    fee_satoshis: funding.satoshis,
                    fee_locking_script: funding.locking_script,
                    fee_private_key: funding.private_key,
                    destinations: dests,
                    spend_type: DstasSpendType::Transfer,
                    fee_rate: config.fee_rate,
                };
                let tx = build_dstas_base_tx(&tx_config)?;
                transactions.push(tx);
            }
            PlannedOp::Merge { input_a, input_b } => {
                let funding = (config.funding_provider)()?;
                let merged_sats = config.token_utxos[*input_a].satoshis
                    + config.token_utxos[*input_b].satoshis;
                let mut dest = config.destinations[0].clone();
                dest.satoshis = merged_sats;
                let tx_config = DstasBaseConfig {
                    token_inputs: vec![
                        token_to_input(&config.token_utxos[*input_a]),
                        token_to_input(&config.token_utxos[*input_b]),
                    ],
                    fee_txid: funding.txid,
                    fee_vout: funding.vout,
                    fee_satoshis: funding.satoshis,
                    fee_locking_script: funding.locking_script,
                    fee_private_key: funding.private_key,
                    destinations: vec![dest],
                    spend_type: DstasSpendType::Transfer,
                    fee_rate: config.fee_rate,
                };
                let tx = build_dstas_base_tx(&tx_config)?;
                transactions.push(tx);
            }
        }
    }

    Ok(PayoutBundle {
        transactions,
        fee_satoshis: 0,
    })
}
