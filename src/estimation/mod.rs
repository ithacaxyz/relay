//! Estimation module for intent simulation and fee calculation.
//!
//! This module combines simulation and pricing functionality to provide
//! comprehensive gas estimation and fee calculation for intents.

pub mod fees;
pub mod simulator;

// Re-export main types and functions
pub use fees::{FeeEngine, PricingContext};
pub use simulator::{simulate_init, simulate_intent};