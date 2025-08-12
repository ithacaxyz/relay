//! Estimation module for intent simulation and fee calculation.
//!
//! This module provides a clean separation of concerns for:
//! - **Simulation**: Executing intents to determine gas usage and effects
//! - **Fee Calculation**: Computing costs based on gas, prices, and network conditions
//! - **Quote Generation**: Building complete quotes with all pricing information
//!
//! ## Architecture
//!
//! The estimation module is organized into focused submodules:
//! - `simulator`: Handles intent simulation and gas estimation
//! - `fees`: Manages fee calculation and token pricing
//! - `types`: Common types used across the estimation module
//! - `builder`: Utilities for building quotes and responses
//!
//! ## Future Improvements
//!
//! This structure enables future enhancements such as:
//! - Multiple fee calculation strategies
//! - Caching of simulation results
//! - Historical gas price analysis
//! - Advanced quote optimization

// Declare submodules (initially empty)
pub mod builder;
pub mod fees;
pub mod simulator;
pub mod types;

// Future: Public API will be re-exported here
// pub use simulator::Simulator;
// pub use fees::FeeEngine;
// pub use types::{SimulationResult, PricingContext, Quote};
