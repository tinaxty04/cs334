use crate::transaction::SignedTransaction;
use std::collections::HashMap;
use crate::crypto::hash::{H256, Hashable};
use log::info;
use log::warn;

/// Store all the received valid transactions which have not been included in the blockchain yet.
pub struct Mempool {
    // Map of transaction hash to transaction
    transactions: HashMap<H256, SignedTransaction>,
}

impl Mempool {
    pub fn new() -> Self {
        Mempool {
            transactions: HashMap::new(),
        }
    }

    /// Add a transaction to the mempool if it's valid
    pub fn add_transaction(&mut self, tx: SignedTransaction) -> bool {
        let tx_hash = tx.hash();
        if self.transactions.contains_key(&tx_hash) {
            info!("[Mempool] Transaction {} already in mempool", tx_hash);
            return false;
        }

        // Add transaction
        self.transactions.insert(tx_hash, tx);
        info!("[Mempool] Added transaction {} to mempool", tx_hash);
        
        // Optionally log contents
        // self.log_contents();
        true
    }

    /// Add a transaction to the mempool with a specific status
    pub fn add_with_status(&mut self, transaction: SignedTransaction, status: &str, reason: String) -> bool {
        let tx_hash = transaction.hash();
        
        // Check if transaction already exists
        if self.transactions.contains_key(&tx_hash) {
            warn!("[Mempool] Transaction {} already exists in mempool", tx_hash);
            return false;
        }

        // Add transaction with status
        self.transactions.insert(tx_hash, transaction);
        info!("[Mempool] Added {} transaction {} to mempool: {}", status, tx_hash, reason);
        
        // Optionally log contents
        // self.log_contents();
        true
    }

    /// Get a transaction by its hash
    pub fn get_transaction(&self, hash: &H256) -> Option<&SignedTransaction> {
        self.transactions.get(hash)
    }

    /// Remove transactions from mempool (e.g., when they're included in a block)
    pub fn remove_transactions(&mut self, tx_hashes: &[H256]) {
        for hash in tx_hashes {
            if self.transactions.remove(hash).is_some() {
                info!("[Mempool] Removed transaction {} from mempool", hash);
            }
        }
    }

    /// Get all transactions in the mempool
    pub fn get_all_transactions(&self) -> Vec<&SignedTransaction> {
        self.transactions.values().collect()
    }

    /// Get transactions up to a limit
    pub fn get_transactions_up_to(&self, limit: usize) -> Vec<&SignedTransaction> {
        self.transactions.values().take(limit).collect()
    }

    /// Get the number of transactions in the mempool
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Check if mempool is empty
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Remove a random transaction from the mempool and return it (or `None` if it is empty)
    pub fn pop(&mut self) -> Option<SignedTransaction> {
        let hash = self.transactions.keys().next().cloned();
        if let Some(hash) = hash {
            self.transactions.remove(&hash)
        } else {
            None
        }
    }
        
    // TODO Optional: you may want to add more methods here...

    pub fn add(&mut self, tx: SignedTransaction) {
        let tx_hash = tx.hash();
        self.transactions.insert(tx_hash, tx);
    }

    pub fn remove(&mut self, tx_hash: &H256) {
        self.transactions.remove(tx_hash);
    }

    pub fn get_transactions(&mut self, limit: usize) -> Vec<SignedTransaction> {
        let mut txs = Vec::new();
        let keys: Vec<H256> = self.transactions.keys().cloned().collect();
        
        for key in keys.iter().take(limit) {
            if let Some(tx) = self.transactions.remove(key) {
                txs.push(tx);
            }
        }
        
        txs
    }

    pub fn contains(&self, tx_hash: &H256) -> bool {
        self.transactions.contains_key(tx_hash)
    }

    pub fn size(&self) -> usize {
        self.transactions.len()
    }

    pub fn log_contents(&self) {
        info!("[Mempool] Logging all transactions ({} total):", self.transactions.len());
        for (i, tx) in self.transactions.values().enumerate() {
            info!("[Mempool] Tx {}: from={} to={} value={} nonce={}", i, tx.raw.from_addr, tx.raw.to_addr, tx.raw.value, tx.raw.nonce);
        }
    }
}