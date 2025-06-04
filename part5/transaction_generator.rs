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
        const INTERVAL_MILLISECONDS: u64 = 3000; // how quickly to generate transactions

        // Use the same deterministic keypairs as the ICO
        let keypairs: Vec<Ed25519KeyPair> = (0u8..3).map(|i| crate::blockchain::get_deterministic_keypair(i)).collect();
        let addresses: Vec<crate::crypto::address::H160> = keypairs.iter().map(|k| crate::crypto::address::H160::from_pubkey(k.public_key().as_ref())).collect();

        let mut sender_index = 0;
        loop {
            let interval = time::Duration::from_millis(INTERVAL_MILLISECONDS);
            thread::sleep(interval);

            // Cycle through all accounts
            let sender_kp = &keypairs[sender_index];
            let sender_addr = addresses[sender_index];
            sender_index = (sender_index + 1) % keypairs.len();

            // Get current state
            let state = {
                let blockchain = self.blockchain.lock().unwrap();
                blockchain.get_state_for_tip().clone()
            };

            // Get sender's nonce and balance
            let (nonce, balance) = match state.get(&sender_addr) {
                Some((n, b)) => (n, b),
                None => continue, // skip if not found
            };
            if balance == 0 {
                continue; // skip if no balance
            }

            // Pick a random recipient (not self)
            let mut recipient_indices: Vec<usize> = (0..keypairs.len()).filter(|&i| i != sender_index).collect();
            if recipient_indices.is_empty() {
                continue;
            }
            let mut rng = thread_rng();
            let &recipient_index = recipient_indices.choose(&mut rng).unwrap();
            let recipient_addr = addresses[recipient_index];

            // Pick a value to send (1..=balance)
            let value = if balance > 1 { rng.gen_range(1..=balance) } else { 1 };

            // Create transaction
            let raw_tx = crate::transaction::RawTransaction {
                from_addr: sender_addr,
                to_addr: recipient_addr,
                value,
                nonce: nonce + 1,
            };
            let signed_tx = crate::transaction::SignedTransaction::from_raw(raw_tx, sender_kp);
            let tx_hash = signed_tx.hash();

            // Add to mempool
            {
                let mut mempool = self.mempool.lock().unwrap();
                mempool.add_transaction(signed_tx.clone());
            }

            // Broadcast
            self.server.broadcast(Message::NewTransactionHashes(vec![tx_hash]));

            log::info!("[TxGen] Generated tx from {} to {} value {} nonce {}", sender_addr, recipient_addr, value, nonce + 1);
        }
    }
}
