//! Multicall3 batching implementation for optimizing RPC calls.

use alloy::{
    dyn_abi::{DynSolValue, FunctionExt, JsonAbiExt},
    json_abi::JsonAbi,
    primitives::{Address, Bytes, U256},
    providers::Provider,
    rpc::types::TransactionRequest,
};
use serde::{Deserialize, Serialize};

/// Multicall3 contract address (same on all chains)
pub const MULTICALL3_ADDRESS: Address = address!("cA11bde05977b3631167028862bE2a173976CA11");

/// Multicall3 ABI - minimal interface we need
const MULTICALL3_ABI: &str = r#"[
    {
        "inputs": [
            {
                "components": [
                    {"name": "target", "type": "address"},
                    {"name": "callData", "type": "bytes"}
                ],
                "name": "calls",
                "type": "tuple[]"
            }
        ],
        "name": "aggregate",
        "outputs": [
            {"name": "blockNumber", "type": "uint256"},
            {"name": "returnData", "type": "bytes[]"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {
                "components": [
                    {"name": "target", "type": "address"},
                    {"name": "allowFailure", "type": "bool"},
                    {"name": "callData", "type": "bytes"}
                ],
                "name": "calls",
                "type": "tuple[]"
            }
        ],
        "name": "tryAggregate",
        "outputs": [
            {
                "components": [
                    {"name": "success", "type": "bool"},
                    {"name": "returnData", "type": "bytes"}
                ],
                "name": "returnData",
                "type": "tuple[]"
            }
        ],
        "stateMutability": "view",
        "type": "function"
    }
]"#;

/// Represents a single call in a multicall batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Call {
    /// Target contract address
    pub target: Address,
    /// Encoded call data
    pub call_data: Bytes,
    /// Whether to allow this call to fail
    #[serde(default)]
    pub allow_failure: bool,
}

/// Result of a multicall execution
#[derive(Debug, Clone)]
pub struct MulticallResult {
    /// Block number at which the calls were executed
    pub block_number: Option<U256>,
    /// Results for each call
    pub results: Vec<CallResult>,
}

/// Result of a single call in a multicall
#[derive(Debug, Clone)]
pub struct CallResult {
    /// Whether the call succeeded
    pub success: bool,
    /// Return data from the call
    pub return_data: Bytes,
}

/// Error types for multicall operations
#[derive(Debug, thiserror::Error)]
pub enum MulticallError {
    /// Failed to parse ABI
    #[error("Failed to parse Multicall3 ABI: {0}")]
    AbiError(String),
    
    /// Failed to encode call data
    #[error("Failed to encode call data: {0}")]
    EncodeError(String),
    
    /// Failed to decode return data
    #[error("Failed to decode return data: {0}")]
    DecodeError(String),
    
    /// RPC call failed
    #[error("RPC call failed: {0}")]
    RpcError(String),
    
    /// No calls provided
    #[error("No calls provided for batching")]
    NoCalls,
}

/// Multicall batcher for optimizing multiple contract calls
pub struct MulticallBatcher<P> {
    provider: P,
    multicall_address: Address,
    abi: JsonAbi,
}

impl<P> MulticallBatcher<P> {
    /// Create a new multicall batcher
    pub fn new(provider: P) -> Result<Self, MulticallError> {
        Self::with_address(provider, MULTICALL3_ADDRESS)
    }
    
    /// Create a new multicall batcher with a custom address
    pub fn with_address(provider: P, multicall_address: Address) -> Result<Self, MulticallError> {
        let abi: JsonAbi = serde_json::from_str(MULTICALL3_ABI)
            .map_err(|e| MulticallError::AbiError(e.to_string()))?;
        
        Ok(Self {
            provider,
            multicall_address,
            abi,
        })
    }
}

impl<P> MulticallBatcher<P>
where
    P: Provider,
{
    /// Execute multiple calls in a single batch
    pub async fn batch_calls(&self, calls: Vec<Call>) -> Result<MulticallResult, MulticallError> {
        if calls.is_empty() {
            return Err(MulticallError::NoCalls);
        }
        
        // Check if all calls allow failure or not
        let all_allow_failure = calls.iter().all(|c| c.allow_failure);
        let none_allow_failure = calls.iter().all(|c| !c.allow_failure);
        
        if none_allow_failure {
            // Use aggregate for better gas efficiency when no failures allowed
            self.aggregate(calls).await
        } else {
            // Use tryAggregate when some calls may fail
            self.try_aggregate(calls, all_allow_failure).await
        }
    }
    
    /// Execute calls using aggregate (all must succeed)
    async fn aggregate(&self, calls: Vec<Call>) -> Result<MulticallResult, MulticallError> {
        let call_tuples: Vec<DynSolValue> = calls
            .iter()
            .map(|call| {
                DynSolValue::Tuple(vec![
                    DynSolValue::Address(call.target),
                    DynSolValue::Bytes(call.call_data.to_vec()),
                ])
            })
            .collect();
        
        let function = self.abi
            .functions()
            .find(|f| f.name == "aggregate")
            .ok_or_else(|| MulticallError::AbiError("aggregate function not found".to_string()))?;
        
        let call_data = function
            .abi_encode_input(&[DynSolValue::Array(call_tuples)])
            .map_err(|e| MulticallError::EncodeError(e.to_string()))?;
        
        let tx = TransactionRequest::default()
            .to(self.multicall_address)
            .input(call_data.into());
        
        let result = self.provider
            .call(tx)
            .await
            .map_err(|e| MulticallError::RpcError(e.to_string()))?;
        
        let decoded = function
            .abi_decode_output(&result)
            .map_err(|e| MulticallError::DecodeError(e.to_string()))?;
        
        // Extract block number and return data
        let (block_number, return_data) = match &decoded[..] {
            [DynSolValue::Uint(bn, _), DynSolValue::Array(data)] => {
                let results = data
                    .iter()
                    .map(|d| {
                        if let DynSolValue::Bytes(bytes) = d {
                            CallResult {
                                success: true,
                                return_data: bytes.clone().into(),
                            }
                        } else {
                            CallResult {
                                success: false,
                                return_data: Bytes::default(),
                            }
                        }
                    })
                    .collect();
                
                (Some(bn.clone()), results)
            }
            _ => return Err(MulticallError::DecodeError("Unexpected output format".to_string())),
        };
        
        Ok(MulticallResult {
            block_number,
            results: return_data,
        })
    }
    
    /// Execute calls using tryAggregate (allows failures)
    async fn try_aggregate(&self, calls: Vec<Call>, require_success: bool) -> Result<MulticallResult, MulticallError> {
        let call_tuples: Vec<DynSolValue> = calls
            .iter()
            .map(|call| {
                DynSolValue::Tuple(vec![
                    DynSolValue::Address(call.target),
                    DynSolValue::Bool(!require_success || call.allow_failure),
                    DynSolValue::Bytes(call.call_data.to_vec()),
                ])
            })
            .collect();
        
        let function = self.abi
            .functions()
            .find(|f| f.name == "tryAggregate")
            .ok_or_else(|| MulticallError::AbiError("tryAggregate function not found".to_string()))?;
        
        let call_data = function
            .abi_encode_input(&[DynSolValue::Array(call_tuples)])
            .map_err(|e| MulticallError::EncodeError(e.to_string()))?;
        
        let tx = TransactionRequest::default()
            .to(self.multicall_address)
            .input(call_data.into());
        
        let result = self.provider
            .call(tx)
            .await
            .map_err(|e| MulticallError::RpcError(e.to_string()))?;
        
        let decoded = function
            .abi_decode_output(&result)
            .map_err(|e| MulticallError::DecodeError(e.to_string()))?;
        
        // Extract results
        let results = match &decoded[..] {
            [DynSolValue::Array(data)] => {
                data.iter()
                    .map(|d| {
                        if let DynSolValue::Tuple(fields) = d {
                            if fields.len() == 2 {
                                let success = matches!(&fields[0], DynSolValue::Bool(true));
                                let return_data = if let DynSolValue::Bytes(bytes) = &fields[1] {
                                    bytes.clone().into()
                                } else {
                                    Bytes::default()
                                };
                                
                                CallResult { success, return_data }
                            } else {
                                CallResult {
                                    success: false,
                                    return_data: Bytes::default(),
                                }
                            }
                        } else {
                            CallResult {
                                success: false,
                                return_data: Bytes::default(),
                            }
                        }
                    })
                    .collect()
            }
            _ => return Err(MulticallError::DecodeError("Unexpected output format".to_string())),
        };
        
        Ok(MulticallResult {
            block_number: None,
            results,
        })
    }
}

/// Helper macro to create multicall batches
#[macro_export]
macro_rules! multicall {
    ($($target:expr => $call_data:expr),* $(,)?) => {
        vec![
            $(
                $crate::rpc::multicall::Call {
                    target: $target,
                    call_data: $call_data,
                    allow_failure: false,
                }
            ),*
        ]
    };
    
    ($($target:expr => $call_data:expr => $allow_failure:expr),* $(,)?) => {
        vec![
            $(
                $crate::rpc::multicall::Call {
                    target: $target,
                    call_data: $call_data,
                    allow_failure: $allow_failure,
                }
            ),*
        ]
    };
}

// Re-export for convenience
pub use multicall;

/// Extension trait for providers to add multicall support
pub trait MulticallExt: Provider {
    /// Create a multicall batcher for this provider
    fn multicall(&self) -> MulticallBatcher<&Self> {
        MulticallBatcher::new(self).expect("Failed to create multicall batcher")
    }
    
    /// Create a multicall batcher with a custom address
    fn multicall_at(&self, address: Address) -> MulticallBatcher<&Self> {
        MulticallBatcher::with_address(self, address).expect("Failed to create multicall batcher")
    }
}

// Implement for all providers
impl<P: Provider> MulticallExt for P {}

// Helper to convert Address to the correct type
use alloy::primitives::address;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_call_creation() {
        let call = Call {
            target: Address::ZERO,
            call_data: Bytes::from(vec![0x01, 0x02, 0x03]),
            allow_failure: false,
        };
        
        assert_eq!(call.target, Address::ZERO);
        assert_eq!(call.call_data.len(), 3);
        assert!(!call.allow_failure);
    }
    
    #[test]
    fn test_multicall_macro() {
        let calls = multicall![
            Address::ZERO => Bytes::from(vec![0x01]),
            Address::ZERO => Bytes::from(vec![0x02]),
        ];
        
        assert_eq!(calls.len(), 2);
        assert!(!calls[0].allow_failure);
        assert!(!calls[1].allow_failure);
    }
}