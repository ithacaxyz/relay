use super::RelayTransaction;
use alloy::primitives::{Address, U256, aliases::U192};
use std::collections::{BTreeMap, HashMap, VecDeque};

/// Splits the nonce into sequence key and nonce.
fn split_nonce(nonce: U256) -> (U192, u64) {
    (U192::from(nonce >> 64), nonce.as_limbs().first().copied().unwrap_or_default())
}

pub struct TxPool {
    /// Transactions ready to be sent, ordered by priority (FIFO).
    ready: VecDeque<RelayTransaction>,

    /// Transactions that are blocked by other transactions that are either `ready` or are not in
    /// the pool yet. sender -> seqKey -> nonce -> tx
    blocked: HashMap<Address, HashMap<U192, BTreeMap<u64, RelayTransaction>>>,
}

impl TxPool {
    /// Invoked when new transaction is added to the pool.
    pub fn on_new_transaction(&mut self, tx: RelayTransaction, on_chain_nonce: u64) {
        let (seq_key, tx_nonce) = split_nonce(tx.quote.ty().op.nonce);

        if tx_nonce == on_chain_nonce {
            self.ready.push_back(tx);
        } else {
            self.blocked
                .entry(tx.quote.ty().op.eoa)
                .or_default()
                .entry(seq_key)
                .or_default()
                .insert(tx_nonce, tx);
        }
    }

    /// Invoked when on-chain nonce is changed.
    pub fn on_used_nonce(&mut self, eoa: Address, nonce: U256) {
        self.blocked.retain(|e, txs| {
            if e != &eoa {
                return true;
            }

            let (seq_key, nonce) = split_nonce(nonce);

            txs.retain(|seq, txs| {
                if seq != &seq_key {
                    return true;
                }

                // Try to get the transaction with lowest nonce
                let Some(entry) = txs.first_entry() else {
                    // if the set is empty, remove the entry
                    return false;
                };

                // If the transaction nonce is still higher than on-chain value, keep it in the set
                if *entry.key() > nonce + 1 {
                    return true;
                }

                // Otherwise, push it to ready queue.
                self.ready.push_back(entry.remove());

                !txs.is_empty()
            });

            !txs.is_empty()
        })
    }
}
