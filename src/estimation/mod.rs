//! Estimation module for intent simulation and fee calculation.
//!
//! This module provides a clean separation of concerns for:
//! - **Simulation**: Executing intents to determine gas usage and effects
//! - **Fee Calculation**: Computing costs based on gas, prices, and network conditions
//! - **Quote Generation**: Building complete quotes with all pricing information

pub mod fees;
pub mod simulator;

pub use simulator::{build_delegation_override, build_simulation_overrides};

pub mod arb;
pub mod op;
