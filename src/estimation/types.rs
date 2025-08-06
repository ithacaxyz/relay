//! Types used in the estimation module.

use crate::types::{AssetDiffs, SimulationResult};
use alloy::primitives::U256;

/// Response from intent simulation containing all necessary data for fee calculation.
#[derive(Clone)]
pub struct SimulationResponse {
    /// Asset differences calculated during simulation.
    pub asset_diffs: AssetDiffs,
    /// Combined gas estimate for the intent.
    pub gas_combined: U256,
    /// Detailed simulation result.
    pub simulation_result: SimulationResult,
}

impl SimulationResponse {
    /// Creates a new simulation response.
    pub fn new(asset_diffs: AssetDiffs, gas_combined: U256, simulation_result: SimulationResult) -> Self {
        Self {
            asset_diffs,
            gas_combined,
            simulation_result,
        }
    }
}