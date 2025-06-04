use serde::{Serialize,Deserialize};
use ring::signature::{Ed25519KeyPair, Signature, KeyPair, VerificationAlgorithm, EdDSAParameters};
use crate::crypto::hash::{H256, Hashable};

use crate::network::server::Handle as ServerHandle;
use std::thread;
use std::time;
use std::sync::{Arc, Mutex};
use crate::mempool::Mempool;
use crate::network::message::Message;
use crate::blockchain::{Blockchain};
use rand::seq::SliceRandom;
use rand::thread_rng;

pub struct TransactionGenerator {
    server: ServerHandle,
    mempool: Arc<Mutex<Mempool>>,
    blockchain: Arc<Mutex<Blockchain>>,
    controlled_keypair: Ed25519KeyPair,
}

impl TransactionGenerator {
    pub fn new(
        server: &ServerHandle,
        mempool: &Arc<Mutex<Mempool>>,
        blockchain: &Arc<Mutex<Blockchain>>,
        controlled_keypair: Ed25519KeyPair
    ) -> TransactionGenerator {
        TransactionGenerator {
            server: server.clone(),
            mempool: Arc::clone(mempool),
            blockchain: Arc::clone(blockchain),
            controlled_keypair,
        }
    }

    pub fn start(self) {
        thread::spawn(move || {
            self.generation_loop();
            log::warn!("Transaction Generator exited");
        });
    }

    /// Generate random transactions and send them to the server
    fn generation_loop(&self) {
        const INTERVAL_MILLISECONDS: u64 = 500; // how quickly to generate transactions (faster)
        const MAX_RETRIES: u32 = 3; // maximum number of retries for transaction generation

        // Use the same deterministic keypairs as the ICO
        let keypairs: Vec<Ed25519KeyPair> = (0u8..3).map(|i| crate::blockchain::get_deterministic_keypair(i)).collect();
        let addresses: Vec<crate::crypto::address::H160> = keypairs.iter().map(|k| crate::crypto::address::H160::from_pubkey(k.public_key().as_ref())).collect();

        let mut sender_index = 0;
        loop {
            let interval = time::Duration::from_millis(INTERVAL_MILLISECONDS);
            thread::sleep(interval);

                // Get current state
                let state = {
                    let blockchain = self.blockchain.lock().unwrap();
                    blockchain.get_state_for_tip().clone()
                };

            // Get sender and receiver addresses
            let from_addr = addresses[sender_index];
            let to_addr = addresses[(sender_index + 1) % addresses.len()];
            
            // Get current nonce and balance
            let (current_nonce, balance) = state.get(&from_addr).unwrap_or((0, 0));
            
            // Generate transaction with current nonce
            let value = 10; // Fixed value for simplicity
                let raw_tx = crate::transaction::RawTransaction {
                from_addr,
                to_addr,
                    value,
                nonce: current_nonce + 1,
                };
            
            let tx = crate::transaction::SignedTransaction::from_raw(raw_tx, &self.controlled_keypair);
            
            // Try to add to mempool with retries
            let mut retries = 0;
            let mut success = false;
            
            while retries < MAX_RETRIES && !success {
                // Check state again right before adding to mempool
                let current_state = {
                    let blockchain = self.blockchain.lock().unwrap();
                    blockchain.get_state_for_tip().clone()
                };
                
                let (latest_nonce, _) = current_state.get(&from_addr).unwrap_or((0, 0));
                
                if latest_nonce == current_nonce {
                    // State hasn't changed, safe to add transaction
                    let mut mempool = self.mempool.lock().unwrap();
                    success = mempool.add(tx.clone());
                    if success {
                        info!("[TxGen] Successfully generated tx: from={} to={} value={} nonce={}", 
                            from_addr, to_addr, value, current_nonce + 1);
                    }
                } else {
                    // State has changed, update nonce and retry
                    info!("[TxGen] State changed during generation, retrying with new nonce: old={} new={}", 
                        current_nonce, latest_nonce);
                    let raw_tx = crate::transaction::RawTransaction {
                        from_addr,
                        to_addr,
                        value,
                        nonce: latest_nonce + 1,
                    };
                    let tx = crate::transaction::SignedTransaction::from_raw(raw_tx, &self.controlled_keypair);
                    retries += 1;
                }
            }
            
            if !success {
                warn!("[TxGen] Failed to generate transaction after {} retries", MAX_RETRIES);
            }

            // Move to next sender
            sender_index = (sender_index + 1) % addresses.len();
        }
    }
}
