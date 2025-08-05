use super::PricingError;

pub struct GasEstimator;

impl GasEstimator {
    pub fn calculate_intrinsic_cost(call_data: &[u8], has_authorization: bool) -> u64 {
        const NON_ZERO_DATA_COST: u64 = 16;  // Correct gas cost per non-zero byte (Istanbul)
        const ZERO_DATA_COST: u64 = 4;       // Gas cost per zero byte
        const BASE_TX_COST: u64 = 21000;     // Base transaction cost
        const PER_EMPTY_ACCOUNT_COST: u64 = 25000; // Cost for EIP-7702 authorization

        let zero_data_len = call_data.iter().filter(|&&byte| byte == 0).count() as u64;
        let non_zero_data_len = call_data.len() as u64 - zero_data_len;

        let data_cost = zero_data_len * ZERO_DATA_COST + non_zero_data_len * NON_ZERO_DATA_COST;
        let auth_cost = if has_authorization { PER_EMPTY_ACCOUNT_COST } else { 0 };

        BASE_TX_COST + auth_cost + data_cost
    }

    pub fn estimate_execution_gas(execution_data: &[u8]) -> Result<u64, PricingError> {
        // Base gas estimation for execution
        let base_gas = 21000_u64;
        let data_gas = Self::calculate_intrinsic_cost(execution_data, false);
        
        // Add additional gas for complex execution
        let execution_gas = 100_000_u64; // Estimated execution overhead
        
        Ok(base_gas + data_gas + execution_gas)
    }
}