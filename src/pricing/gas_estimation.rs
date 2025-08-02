//! Gas estimation utilities and intrinsic cost calculations.

use crate::{
    config::QuoteConfig,
    types::GasEstimate,
};
use alloy::{
    eips::eip7702::constants::PER_EMPTY_ACCOUNT_COST,
    primitives::U256,
};

/// Gas estimator for intent and transaction gas calculations.
#[derive(Debug)]
pub struct GasEstimator;

impl GasEstimator {
    /// Estimates combined gas for intent and transaction.
    ///
    /// The recommended transaction gas is calculated according to the contracts recommendation:
    /// https://github.com/ithacaxyz/account/blob/feffa280d5de487223e43a69126f5b6b3d99a10a/test/SimulateExecute.t.sol#L205-L206
    pub fn estimate_combined_gas(
        simulation_gas: U256,
        intrinsic_gas: u64,
        config: &QuoteConfig,
    ) -> GasEstimate {
        GasEstimate::from_combined_gas(
            simulation_gas.to::<u64>(),
            intrinsic_gas,
            config,
        )
    }

    /// Calculates the intrinsic cost of a transaction.
    ///
    /// This function assumes Prague rules and includes:
    /// - Base transaction cost (21000 gas)
    /// - Data cost (4 gas per non-zero byte, 16 gas per zero byte)
    /// - Optional EIP-7702 authorization cost
    pub fn calculate_intrinsic_cost(call_data: &[u8], has_authorization: bool) -> u64 {
        let zero_data_len = call_data.iter().filter(|v| **v == 0).count() as u64;
        let non_zero_data_len = call_data.len() as u64 - zero_data_len;
        
        // Gas costs per Istanbul rules
        const NON_ZERO_DATA_COST: u64 = 16;
        const ZERO_DATA_COST: u64 = 4;
        const BASE_TX_COST: u64 = 21000;
        
        let data_gas = zero_data_len * ZERO_DATA_COST + non_zero_data_len * NON_ZERO_DATA_COST;
        let auth_gas = if has_authorization { PER_EMPTY_ACCOUNT_COST } else { 0 };
        
        BASE_TX_COST + data_gas + auth_gas
    }

    /// Calculates the intrinsic cost for an encoded call.
    ///
    /// Convenience method that takes encoded call data directly.
    pub fn calculate_intrinsic_for_encoded(encoded_call: &[u8], has_authorization: bool) -> u64 {
        Self::calculate_intrinsic_cost(encoded_call, has_authorization)
    }

    /// Extracts the intent gas limit from a gas estimate.
    pub fn get_intent_gas_limit(estimate: &GasEstimate) -> U256 {
        U256::from(estimate.intent)
    }

    /// Extracts the transaction gas limit from a gas estimate.
    pub fn get_tx_gas_limit(estimate: &GasEstimate) -> U256 {
        U256::from(estimate.tx)
    }
}