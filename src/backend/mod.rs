mod event;
use std::collections::{HashMap, VecDeque};

use alloy::{primitives::map::AddressMap, rpc::types::TransactionRequest};
pub use event::*;
use futures_util::future::BoxFuture;

use crate::{chains::Chains, nonce::MultiChainNonceManager, signers::DynSigner};

// todo this name sucks

#[derive(Clone, Debug)]
pub struct BackendHandle {}

/// A service that receives unsigned transactions, signs them using the provided signers, and
/// broadcasts them to the network.
///
/// This service is responsible for handling incoming transactions, signing them with the provided
/// signers, and broadcasting them to the network. Events are emitted to notify the caller of the
/// status of each transaction.
///
/// The transactions go through the following states:
///
/// [`TxEvent::Queued`] --> [`TxEvent::Pending`] --> [`TxEvent::Included`]
///
/// It is possible for the transaction to get stuck in the [`TxEvent::Pending`] state if the network
/// is congested or if the transaction is rejected by the network. In such cases, the transaction
/// will be resubmitted or replaced with a higher gas price.
///
/// To interact with the [`Backend`], you can use the [`BackendHandle`] struct.
#[derive(Debug)]
pub struct Backend {
    providers: Chains,
    signers: Vec<DynSigner>,
    nonce_manager: MultiChainNonceManager,
    queue: VecDeque<TransactionRequest>,
    pending: AddressMap<HashMap<u64, B256>>,
}

impl Backend {
    /// Create a new backend instance.
    pub fn new(providers: Chains, signers: Vec<DynSigner>) -> Self {
        Backend {
            providers,
            signers,
            nonce_manager: MultiChainNonceManager::default(),
            queue: VecDeque::default(),
            pending: AddressMap::default(),
        }
    }
}

impl IntoFuture for Backend {
    type Output = ();
    type IntoFuture = BoxFuture<'static, Self::Output>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            // pop off queue
            // process pending txs
        })
    }
}
