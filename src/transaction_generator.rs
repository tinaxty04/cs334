use serde::{Serialize,Deserialize};
use ring::signature::{Ed25519KeyPair, Signature, KeyPair, VerificationAlgorithm, EdDSAParameters};
use crate::crypto::hash::{H256, Hashable};

use crate::network::server::Handle as ServerHandle;
use std::thread;
use std::time::Duration;
use std::sync::{Arc, Mutex};
use crate::mempool::Mempool;
use crate::network::message::Message;
use crate::blockchain::{Blockchain};
use crate::crypto::address::{get_deterministic_keypair, H160};
use crate::transaction::{RawTransaction, SignedTransaction};
use log::info;

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
            let mut sender_idx = 0;
            loop {
                // Pick sender and recipient from ICO accounts
                let sender_key = get_deterministic_keypair(sender_idx);
                let sender_addr = H160::from_pubkey(sender_key.public_key().as_ref());
                let recipient_idx = (sender_idx + 1) % 10;
                let recipient_key = get_deterministic_keypair(recipient_idx);
                let recipient_addr = H160::from_pubkey(recipient_key.public_key().as_ref());

                // Get current state
                let blockchain = self.blockchain.lock().unwrap();
                let tip = blockchain.tip();
                let state = blockchain.hash_to_state.get(&tip).unwrap();
                let (nonce, balance) = state.map.get(&sender_addr).cloned().unwrap_or((0, 0));
                drop(blockchain);

                // Only send if sender has enough balance
                let value = 1;
                if balance >= value {
                    let raw_tx = RawTransaction {
                        from_addr: sender_addr,
                        to_addr: recipient_addr,
                        value,
                        nonce: nonce + 1,
                    };
                    let signed_tx = SignedTransaction::from_raw(raw_tx.clone(), &sender_key);

                    // Insert into mempool if valid
                    let mut mempool = self.mempool.lock().unwrap();
                    if mempool.get_transaction(&signed_tx.hash()).is_none() {
                        mempool.insert(signed_tx.clone());
                        info!("[TxGen] Generated and inserted transaction: from {:?} to {:?}, value {}, nonce {}", sender_addr, recipient_addr, value, nonce + 1);
                        drop(mempool);
                        // Broadcast the hash
                        self.server.broadcast(Message::NewTransactionHashes(vec![signed_tx.hash()]));
                        info!("[TxGen] Broadcasted transaction hash: {:?}", signed_tx.hash());
                    }
                } else {
                    info!("[TxGen] Sender {:?} has insufficient balance ({}), skipping", sender_addr, balance);
                }
                sender_idx = (sender_idx + 1) % 10;
                thread::sleep(Duration::from_secs(3));
            }
        });
    }
}
