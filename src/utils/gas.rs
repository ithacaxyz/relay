//! Gas calculation utilities.

use alloy::eips::eip7702::constants::PER_EMPTY_ACCOUNT_COST;

/// Calculate approximate intrinsic cost for a transaction.
///
/// This function assumes Prague rules.
pub fn approx_intrinsic_cost(input: &[u8], has_auth: bool) -> u64 {
    let zero_data_len = input.iter().filter(|v| **v == 0).count() as u64;
    let non_zero_data_len = input.len() as u64 - zero_data_len;
    let non_zero_data_multiplier = 4; // as defined in istanbul
    let standard_token_cost = 4;
    let tokens = zero_data_len + non_zero_data_len * non_zero_data_multiplier;
    
    // For 7702 designations there is an additional gas charge
    //
    // Note: this is not entirely accurate, as there is also a gas refund in 7702, but at this
    // point it is not possible to compute the gas refund, so it is an overestimate, as we also
    // need to charge for the account being presumed empty.
    let auth_cost = if has_auth { PER_EMPTY_ACCOUNT_COST } else { 0 };
    
    21000 + auth_cost + tokens * standard_token_cost
}