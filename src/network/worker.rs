use super::message::Message;
use super::peer;
use crate::network::server::Handle as ServerHandle;
use crossbeam::channel;
use log::{debug, warn, info};
use std::sync::{Arc, Mutex};
use crate::blockchain::Blockchain;
use crate::crypto::hash::Hashable;
use crate::mempool::Mempool;
use std::collections::HashMap;
use once_cell::sync::Lazy;
use crate::transaction::SignedTransaction;
use crate::blockchain::State;
use crate::crypto::address::H160;
use crate::crypto::hash::H256;

use std::thread;

#[derive(Clone, Debug)]
pub enum TxStatus {
    Pending,
    Confirmed,
    Rejected(String),
}

#[derive(Clone, Debug)]
pub struct TxStatusInfo {
    pub hash: H256,
    pub from: H160,
    pub to: H160,
    pub value: u64,
    pub status: TxStatus,
    pub node: String,
}

// Global transaction status map (last 1000 entries)
pub static TX_STATUS_MAP: Lazy<Mutex<HashMap<H256, TxStatusInfo>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn validate_transaction(tx: &SignedTransaction, state: &State) -> Result<(), String> {
    // 1. Signature check
    if !tx.verify_signature() {
        return Err("Invalid signature".to_string());
    }
    // 2. Public key matches sender
    let from_addr = tx.raw.from_addr;
    let pubkey_addr = crate::crypto::address::H160::from_pubkey(&tx.pub_key);
    if from_addr != pubkey_addr {
        return Err("Public key does not match sender address".to_string());
    }
    // 3. Double spend: nonce and balance
    let (acc_nonce, acc_balance) = state.get(&from_addr).unwrap_or((0, 0));
    if tx.raw.nonce != acc_nonce + 1 {
        return Err(format!("Bad nonce (expected {}, got {})", acc_nonce + 1, tx.raw.nonce));
    }
    if tx.raw.value > acc_balance {
        return Err("Overspend (insufficient balance)".to_string());
    }
    Ok(())
}

#[derive(Clone)]
pub struct Context {
    msg_chan: channel::Receiver<(Vec<u8>, peer::Handle)>,
    num_worker: usize,
    server: ServerHandle,
    blockchain: Arc<Mutex<Blockchain>>,
    mempool: Arc<Mutex<Mempool>>,
    // (Optional: you may define other state variables here)
}

pub fn new(
    num_worker: usize,
    msg_src: channel::Receiver<(Vec<u8>, peer::Handle)>,
    server: &ServerHandle,
    blockchain: &Arc<Mutex<Blockchain>>,
    mempool: &Arc<Mutex<Mempool>>,
) -> Context {
    Context {
        msg_chan: msg_src,
        num_worker,
        server: server.clone(),
        blockchain: Arc::clone(blockchain),
        mempool: Arc::clone(mempool),
    }
}

impl Context {
    pub fn start(self) {
        let num_worker = self.num_worker;
        for i in 0..num_worker {
            let cloned = self.clone();
            thread::spawn(move || {
                cloned.worker_loop();
                warn!("Worker thread {} exited", i);
            });
        }
    }

    fn worker_loop(&self) {
        loop {
            let msg = self.msg_chan.recv().unwrap();
            let (msg, peer) = msg;
            let msg: Message = bincode::deserialize(&msg).unwrap();
            match msg {
                Message::Ping(nonce) => {
                    debug!("Ping: {}", nonce);
                    peer.write(Message::Pong(nonce.to_string()));
                }
                Message::Pong(nonce) => {
                    debug!("Pong: {}", nonce);
                }
                Message::NewBlockHashes(hashes) => {
                    // 1. NewBlockHashes: If hashes not in blockchain, ask for them
                    let mut unknown_hashes = Vec::new();
                    let blockchain = self.blockchain.lock().unwrap();
                    for hash in hashes {
                        if !blockchain.get_block(&hash).is_some() {
                            unknown_hashes.push(hash);
                        }
                    }
                    drop(blockchain);
                    if !unknown_hashes.is_empty() {
                        peer.write(Message::GetBlocks(unknown_hashes));
                    }
                }
                Message::GetBlocks(hashes) => {
                    // 2. GetBlocks: If hashes in blockchain, send them
                    let blockchain = self.blockchain.lock().unwrap();
                    let mut found_blocks = Vec::new();
                    for hash in hashes {
                        if let Some(block) = blockchain.get_block(&hash) {
                            found_blocks.push(block.clone());
                        }
                    }
                    drop(blockchain);
                    if !found_blocks.is_empty() {
                        peer.write(Message::Blocks(found_blocks));
                    }
                }
                Message::Blocks(blocks) => {
                    // 3. Blocks: For each block, check validity and insert
                    let mut new_hashes = Vec::new();
                    let mut to_process = blocks;
                    while let Some(block) = to_process.pop() {
                        let block_hash = block.hash();
                        let mut blockchain = self.blockchain.lock().unwrap();
                        if blockchain.get_block(&block_hash).is_some() {
                            continue; // already have it
                        }
                        // PoW validity check
                        let difficulty = block.header.difficulty;
                        let expected_difficulty = blockchain.get_block(&blockchain.tip()).unwrap().header.difficulty;
                        if !(block_hash <= difficulty && difficulty == expected_difficulty) {
                            info!("[Worker] Rejected block: hash={:?}", block_hash);
                            continue;
                        }
                        // Parent check
                        if blockchain.get_block(&block.header.parent).is_some() {
                            // Transaction validity checks
                            let state = blockchain.get_state_for_tip().clone();
                            let mut valid = true;
                            for tx in &block.content.transactions {
                                let result = validate_transaction(&tx, &state);
                                let tx_hash = tx.hash();
                                if let Err(reason) = result {
                                    info!("[Worker] Rejected block: tx invalid: {}", reason);
                                    valid = false;
                                    // Mark as rejected
                                    TX_STATUS_MAP.lock().unwrap().insert(tx_hash, TxStatusInfo {
                                        hash: tx_hash,
                                        from: tx.raw.from_addr,
                                        to: tx.raw.to_addr,
                                        value: tx.raw.value,
                                        status: TxStatus::Rejected(reason),
                                        node: self.server.get_addr().to_string(),
                                    });
                                    break;
                                } else {
                                    // Mark as confirmed
                                    TX_STATUS_MAP.lock().unwrap().insert(tx_hash, TxStatusInfo {
                                        hash: tx_hash,
                                        from: tx.raw.from_addr,
                                        to: tx.raw.to_addr,
                                        value: tx.raw.value,
                                        status: TxStatus::Confirmed,
                                        node: self.server.get_addr().to_string(),
                                    });
                                }
                            }
                            if !valid {
                                continue;
                            }
                            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
                            let delay = now.saturating_sub(block.header.timestamp);
                            blockchain.insert(&block);
                            blockchain.hash_to_origin.insert(block_hash, crate::blockchain::BlockOrigin::Received { delay_ms: delay });
                            let block_size = bincode::serialize(&block).unwrap().len();
                            let height = blockchain.hash_to_height.get(&block_hash).unwrap_or(&0);
                            info!("[Worker] Received block: height={}, hash={}, from={}", height, block_hash, peer.get_addr());
                            new_hashes.push(block_hash);
                            // Remove included transactions from mempool
                            let mut mempool = self.mempool.lock().unwrap();
                            for tx in &block.content.transactions {
                                let h = tx.hash();
                                mempool.remove(&h);
                            }
                            // Orphan handler: check if this block is parent to any orphans
                            let mut orphans_to_process = Vec::new();
                            if let Some(orphans) = blockchain.orphan_buffer.remove(&block_hash) {
                                orphans_to_process.extend(orphans);
                            }
                            drop(blockchain);
                            to_process.extend(orphans_to_process);
                        } else {
                            // Parent missing: add to orphan buffer and request parent
                            blockchain.orphan_buffer.entry(block.header.parent)
                                .or_insert_with(Vec::new)
                                .push(block.clone());
                            drop(blockchain);
                            peer.write(Message::GetBlocks(vec![block.header.parent]));
                        }
                    }
                    // Broadcast new block hashes if any
                    if !new_hashes.is_empty() {
                        self.server.broadcast(Message::NewBlockHashes(new_hashes));
                    }
                }
                Message::NewTransactionHashes(hashes) => {
                    // Request missing transactions from the sender
                    let mempool = self.mempool.lock().unwrap();
                    let missing: Vec<_> = hashes.into_iter().filter(|h| !mempool.contains(h)).collect();
                    drop(mempool);
                    if !missing.is_empty() {
                        peer.write(Message::GetTransactions(missing));
                    }
                }
                Message::GetTransactions(hashes) => {
                    // Send requested transactions from the mempool
                    let mempool = self.mempool.lock().unwrap();
                    let mut found = Vec::new();
                    for h in hashes {
                        if let Some(tx) = mempool.get_transaction(&h) {
                            found.push(tx.clone());
                        }
                    }
                    drop(mempool);
                    if !found.is_empty() {
                        peer.write(Message::Transactions(found));
                    }
                }
                Message::Transactions(txs) => {
                    // Validate each transaction
                    let blockchain = self.blockchain.lock().unwrap();
                    let state = blockchain.get_state_for_tip().clone();
                    drop(blockchain);
                    
                    let mut mempool = self.mempool.lock().unwrap();
                    let mut valid_hashes = Vec::new();
                    
                    for tx in txs {
                        let result = validate_transaction(&tx, &state);
                        let tx_hash = tx.hash();
                        if let Ok(()) = result {
                            if !mempool.contains(&tx_hash) {
                                mempool.add(tx.clone());
                                valid_hashes.push(tx_hash);
                            }
                            // Mark as pending
                            TX_STATUS_MAP.lock().unwrap().insert(tx_hash, TxStatusInfo {
                                hash: tx_hash,
                                from: tx.raw.from_addr,
                                to: tx.raw.to_addr,
                                value: tx.raw.value,
                                status: TxStatus::Pending,
                                node: self.server.get_addr().to_string(),
                            });
                        } else {
                            let reason = result.unwrap_err();
                            info!("[Worker] Rejected tx: {}", reason);
                            // Mark as rejected
                            TX_STATUS_MAP.lock().unwrap().insert(tx_hash, TxStatusInfo {
                                hash: tx_hash,
                                from: tx.raw.from_addr,
                                to: tx.raw.to_addr,
                                value: tx.raw.value,
                                status: TxStatus::Rejected(reason),
                                node: self.server.get_addr().to_string(),
                            });
                        }
                    }
                    
                    drop(mempool);
                    
                    // Broadcast valid tx hashes
                    if !valid_hashes.is_empty() {
                        self.server.broadcast(Message::NewTransactionHashes(valid_hashes));
                    }
                }
            }
        }
    }
}
