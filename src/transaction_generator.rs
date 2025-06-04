use std::time;
use std::thread;
use rand::Rng;
use crate::crypto::address::H160;
use crate::transaction::{RawTransaction, SignedTransaction};
use crate::crypto::hash::{H256, Hashable};
use crate::network::message::Message;
use log::{info, warn};
use std::sync::{Arc, Mutex};
use crate::network::server::Handle;
use crate::mempool::Mempool;
use crate::blockchain::Blockchain;
use ring::signature::KeyPair;

pub struct TransactionGenerator {
    server: Arc<Handle>,
    mempool: Arc<Mutex<Mempool>>,
    blockchain: Arc<Mutex<Blockchain>>,
}

impl TransactionGenerator {
    pub fn new(server: &Arc<Handle>, mempool: &Arc<Mutex<Mempool>>, blockchain: &Arc<Mutex<Blockchain>>) -> Self {
        info!("[TxGen] Initializing transaction generator");
        TransactionGenerator {
            server: server.clone(),
            mempool: mempool.clone(),
            blockchain: blockchain.clone(),
        }
    }

    pub fn start(self) {
        info!("[TxGen] Starting transaction generator");
        thread::spawn(move || {
            self.generation_loop();
            log::warn!("Transaction Generator exited");
        });
    }

    fn generation_loop(&self) {
        const INTERVAL_MILLISECONDS: u64 = 500;
        const MAX_RETRIES: u32 = 3;
        const RETRY_DELAY_MS: u64 = 100;
        
        let mut rng = rand::thread_rng();
        let account_indices: Vec<u8> = (0u8..10).collect();
        
        loop {
            thread::sleep(time::Duration::from_millis(INTERVAL_MILLISECONDS));

            // Pick a random sender and receiver (must be different)
            let sender_idx = account_indices[rng.gen_range(0, 10)];
            let mut receiver_idx = sender_idx;
            while receiver_idx == sender_idx {
                receiver_idx = account_indices[rng.gen_range(0, 10)];
            }

            // Get keypairs for sender and receiver
            let sender_keypair = crate::blockchain::get_deterministic_keypair(sender_idx);
            let sender_addr = H160::from_pubkey(sender_keypair.public_key().as_ref());
            let receiver_keypair = crate::blockchain::get_deterministic_keypair(receiver_idx);
            let receiver_addr = H160::from_pubkey(receiver_keypair.public_key().as_ref());

            // Try to generate a transaction with retries
            let mut retries = 0;
            let mut last_attempt_nonce = None;
            
            while retries < MAX_RETRIES {
                // Get fresh state for sender
                let (sender_nonce, sender_balance) = {
                    let blockchain = self.blockchain.lock().unwrap();
                    let state = blockchain.get_state_for_tip();
                    state.get(&sender_addr).unwrap_or((0, 0))
                };

                // Only proceed if sender has balance
                if sender_balance == 0 {
                    info!("[TxGen] Sender {} has zero balance, skipping tx generation", sender_addr);
                    break;
                }

                // Skip if we've already tried this nonce
                let next_nonce = sender_nonce + 1;
                if last_attempt_nonce == Some(next_nonce) {
                    info!("[TxGen] Already tried nonce {}, waiting for state update", next_nonce);
                    thread::sleep(time::Duration::from_millis(RETRY_DELAY_MS));
                    retries += 1;
                    continue;
                }
                last_attempt_nonce = Some(next_nonce);

                // Generate transaction with current nonce
                let max_value = sender_balance.min(10);
                let value = rng.gen_range(1, max_value + 1);
                
                info!("[TxGen] Attempting to generate tx: from={} to={} value={} current_nonce={} next_nonce={}", 
                    sender_addr, receiver_addr, value, sender_nonce, next_nonce);

                let raw_tx = RawTransaction {
                    from_addr: sender_addr,
                    to_addr: receiver_addr,
                    value,
                    nonce: next_nonce,
                };
                let signed_tx = SignedTransaction::from_raw(raw_tx.clone(), &sender_keypair);
                let tx_hash = signed_tx.hash();

                // Try to add to mempool
                let tx_added = {
                    let mut mempool = self.mempool.lock().unwrap();
                    mempool.add_transaction(signed_tx.clone())
                };

                if tx_added {
                    // Broadcast only if successfully added to mempool
                    self.server.broadcast(Message::NewTransactionHashes(vec![tx_hash]));
                    info!("[TxGen] Successfully generated and broadcast tx: from={} to={} value={} nonce={}", 
                        sender_addr, receiver_addr, value, next_nonce);
                    break; // Success, exit retry loop
                } else {
                    warn!("[TxGen] Failed to add transaction to mempool (attempt {}/{}): from={} to={} value={} nonce={}", 
                        retries + 1, MAX_RETRIES, sender_addr, receiver_addr, value, next_nonce);
                    retries += 1;
                    if retries < MAX_RETRIES {
                        thread::sleep(time::Duration::from_millis(RETRY_DELAY_MS));
                    }
                }
            }

            if retries == MAX_RETRIES {
                warn!("[TxGen] Failed to generate transaction after {} attempts for sender {}", 
                    MAX_RETRIES, sender_addr);
            }
        }
    }

    fn generate_transaction(&self) -> Option<SignedTransaction> {
        let mut rng = rand::thread_rng();
        // Occasionally generate an invalid transaction (e.g., 10% chance)
        if rng.gen_bool(0.1) {
            // Generate an invalid transaction (e.g., wrong nonce or overspending)
            let sender_idx = rng.gen_range(0, 10);
            let mut receiver_idx = sender_idx;
            while receiver_idx == sender_idx {
                receiver_idx = rng.gen_range(0, 10);
            }
            let sender_pair = crate::blockchain::get_deterministic_keypair(sender_idx);
            let receiver_pair = crate::blockchain::get_deterministic_keypair(receiver_idx);
            let from_addr = H160::from_pubkey(sender_pair.public_key().as_ref());
            let to_addr = H160::from_pubkey(receiver_pair.public_key().as_ref());
            let value = rng.gen_range(1, 1000);
            // Intentionally use a wrong nonce or overspend
            let nonce = rng.gen_range(0, 100); // Random nonce, likely invalid
            let raw = RawTransaction { from_addr, to_addr, value, nonce };
            let signature = sender_pair.sign(&raw.hash().as_ref()).as_ref().to_vec();
            let pub_key = sender_pair.public_key().as_ref().to_vec();
            Some(SignedTransaction { raw, signature, pub_key })
        } else {
            // Generate a valid transaction
            let sender_idx = rng.gen_range(0, 10);
            let mut receiver_idx = sender_idx;
            while receiver_idx == sender_idx {
                receiver_idx = rng.gen_range(0, 10);
            }
            let sender_pair = crate::blockchain::get_deterministic_keypair(sender_idx);
            let receiver_pair = crate::blockchain::get_deterministic_keypair(receiver_idx);
            let from_addr = H160::from_pubkey(sender_pair.public_key().as_ref());
            let to_addr = H160::from_pubkey(receiver_pair.public_key().as_ref());
            let value = rng.gen_range(1, 1000);
            let nonce = 0; // Valid nonce
            let raw = RawTransaction { from_addr, to_addr, value, nonce };
            let signature = sender_pair.sign(&raw.hash().as_ref()).as_ref().to_vec();
            let pub_key = sender_pair.public_key().as_ref().to_vec();
            Some(SignedTransaction { raw, signature, pub_key })
        }
    }
} 