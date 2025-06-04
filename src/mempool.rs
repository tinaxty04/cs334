use crate::transaction::SignedTransaction;
use std::collections::HashMap;
use crate::crypto::hash::{H256, Hashable};
use log::{info, warn};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use crate::blockchain::Blockchain;

/// Store all the received valid transactions which have not been included in the blockchain yet.
pub struct Mempool {
    // Map of transaction hash to transaction
    transactions: HashMap<H256, SignedTransaction>,
    last_log_time: Instant,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            transactions: HashMap::new(),
            last_log_time: Instant::now(),
        }
    }

    /// Add a transaction to the mempool if it's valid
    pub fn add(&mut self, transaction: SignedTransaction) -> bool {
        let tx_hash = transaction.hash();
        
        // Check if transaction already exists
        if self.transactions.contains_key(&tx_hash) {
            warn!("[Mempool] Transaction {} already exists in mempool", tx_hash);
            return false;
        }

        // Add transaction
        self.transactions.insert(tx_hash, transaction);
        info!("[Mempool] Added transaction {} to mempool", tx_hash);
        
        // Log mempool contents every 5 seconds
        self.log_if_needed();
        true
    }

    /// Get a transaction by its hash
    pub fn get_transaction(&self, hash: &H256) -> Option<&SignedTransaction> {
        self.transactions.get(hash)
    }

    /// Remove a transaction from mempool (e.g., when it's included in a block)
    pub fn remove(&mut self, tx_hash: &H256) {
        if let Some(tx) = self.transactions.remove(tx_hash) {
            info!("[Mempool] Removed transaction {} from mempool: from={} to={} value={} nonce={}", 
                tx_hash, tx.raw.from_addr, tx.raw.to_addr, tx.raw.value, tx.raw.nonce);
        }
    }

    /// Get all transactions in the mempool
    pub fn get_all_transactions(&self) -> Vec<&SignedTransaction> {
        self.transactions.values().collect()
    }

    /// Get transactions up to a limit
    pub fn get_transactions(&self, limit: usize) -> Vec<SignedTransaction> {
        self.transactions.values()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Check if a transaction exists in the mempool
    pub fn contains(&self, tx_hash: &H256) -> bool {
        self.transactions.contains_key(tx_hash)
    }

    /// Get the number of transactions in the mempool
    pub fn size(&self) -> usize {
        self.transactions.len()
    }

    /// Check if mempool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Log all transactions in the mempool
    pub fn log_contents(&self) {
        info!("[Mempool] Current mempool contents ({} transactions):", self.transactions.len());
        for (hash, tx) in &self.transactions {
            info!("[Mempool] Pending tx {}: from={} to={} value={} nonce={}", 
                hash, tx.raw.from_addr, tx.raw.to_addr, tx.raw.value, tx.raw.nonce);
        }
    }

    pub fn cleanup_outdated_transactions(&mut self, blockchain: &Blockchain) {
        let state = blockchain.get_state_for_tip();
        let mut to_remove = Vec::new();

        // Check each transaction's nonce against current state
        for (hash, tx) in &self.transactions {
            let (current_nonce, _) = state.get(&tx.raw.from_addr).unwrap_or((0, 0));
            if tx.raw.nonce <= current_nonce {
                info!("[Mempool] Removing outdated transaction {}: from={} nonce={} (current={})", 
                    hash, tx.raw.from_addr, tx.raw.nonce, current_nonce);
                to_remove.push(*hash);
            }
        }

        // Remove outdated transactions
        for hash in to_remove {
            self.remove(&hash);
        }
    }

    fn log_if_needed(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_log_time) >= Duration::from_secs(5) {
            self.log_contents();
            self.last_log_time = now;
        }
    }
}