mod balance;
use alloy::primitives::{U256, utils::format_units};
pub use balance::*;

mod liquidity;
pub use liquidity::*;

/// Formats a U256 value into a f64 with the specified number of decimals.
pub fn format_units_f64(value: U256, decimals: u8) -> eyre::Result<f64> {
    Ok(format_units(value, decimals)?.parse::<f64>()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_format_units_f64() {
        let value = U256::from_str("12345678901234567890").unwrap();
        let decimals = 18;
        assert_eq!(format_units_f64(value, decimals).unwrap(), 12.345678901234567);
    }
}
