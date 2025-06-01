use super::message::Message;
use super::peer;
use crate::network::server::Handle as ServerHandle;
use crossbeam::channel;
use log::{debug, warn, info};
use std::sync::{Arc, Mutex};
use crate::blockchain::Blockchain;
use crate::crypto::hash::Hashable;
use crate::mempool::Mempool;

use std::thread;

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
                            info!("Received invalid block (PoW or difficulty mismatch)");
                            continue;
                        }
                        // Parent check
                        if blockchain.get_block(&block.header.parent).is_some() {
                            // Get parent state for transaction validation
                            let parent_state = blockchain.hash_to_state.get(&block.header.parent).unwrap();
                            
                            // Validate all transactions in the block
                            let mut valid_txs = true;
                            for tx in &block.content.transactions {
                                // 1. Get the transaction from mempool to check signature
                                let mut mempool = self.mempool.lock().unwrap();
                                if let Some(signed_tx) = mempool.get_transaction(&tx.hash()) {
                                    // 2. Signature verification
                                    if !signed_tx.verify_signature() {
                                        info!("Block contains transaction with invalid signature");
                                        valid_txs = false;
                                        break;
                                    }

                                    // 3. Check if public key matches the from address
                                    let derived_addr = crate::crypto::address::H160::from_pubkey(signed_tx.pub_key.as_ref());
                                    let from_pubkey = tx.from_addr;
                                    if from_pubkey != derived_addr {
                                        info!("Block contains transaction where public key doesn't match from address");
                                        valid_txs = false;
                                        break;
                                    }
                                }

                                // 4. State-based checks (balance and nonce)
                                if !parent_state.is_valid(tx) {
                                    info!("Block contains transaction with invalid state (balance/nonce)");
                                    valid_txs = false;
                                    break;
                                }
                            }

                            if !valid_txs {
                                info!("Rejecting block due to invalid transactions");
                                continue;
                            }

                            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
                            let delay = now.saturating_sub(block.header.timestamp);
                            let mut mempool = self.mempool.lock().unwrap();
                            blockchain.insert(&block, Some(&mut mempool));
                            blockchain.hash_to_origin.insert(block_hash, crate::blockchain::BlockOrigin::Received { delay_ms: delay });
                            let block_size = bincode::serialize(&block).unwrap().len();
                            info!("Received block: hash={:?}, delay={} ms, size={} bytes", block_hash, delay, block_size);
                            new_hashes.push(block_hash);
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
                // Transaction network messages
                Message::NewTransactionHashes(hashes) => {
                    use crate::crypto::hash::H256;
                    let mempool = self.mempool.lock().unwrap();
                    let missing: Vec<H256> = hashes.into_iter()
                        .filter(|h| mempool.get_transaction(h).is_none())
                        .collect();
                    drop(mempool);
                    if !missing.is_empty() {
                        log::info!("Requesting {} missing transactions from peer", missing.len());
                        peer.write(Message::GetTransactions(missing));
                    }
                }
                Message::GetTransactions(hashes) => {
                    use crate::transaction::SignedTransaction as Transaction;
                    let mempool = self.mempool.lock().unwrap();
                    let found: Vec<Transaction> = hashes.into_iter()
                        .filter_map(|h| mempool.get_transaction(&h).cloned())
                        .collect();
                    drop(mempool);
                    if !found.is_empty() {
                        log::info!("Sending {} transactions to peer", found.len());
                        peer.write(Message::Transactions(found));
                    }
                }
                Message::Transactions(txs) => {
                    use crate::transaction::SignedTransaction as Transaction;
                    let mut mempool = self.mempool.lock().unwrap();
                    let blockchain = self.blockchain.lock().unwrap();
                    let mut new_hashes = Vec::new();
                    
                    for tx in txs {
                        let hash = tx.hash();
                        if mempool.get_transaction(&hash).is_none() {
                            // 1. Signature verification
                            if !tx.verify_signature() {
                                log::warn!("Rejected transaction with invalid signature: {:?}", hash);
                                continue;
                            }

                            // 2. Check if public key matches the from address
                            let derived_addr = crate::crypto::address::H160::from_pubkey(tx.pub_key.as_ref());
                            let from_pubkey = tx.raw.from_addr;
                            if from_pubkey != derived_addr {
                                log::warn!("Rejected transaction: public key doesn't match from address: {:?}", hash);
                                continue;
                            }

                            // 3. State-based checks (balance and nonce)
                            let tip_state = blockchain.hash_to_state.get(&blockchain.tip()).unwrap();
                            if !tip_state.is_valid(&tx.raw) {
                                log::warn!("Rejected transaction: invalid state (balance/nonce): {:?}", hash);
                                continue;
                            }

                            // All checks passed, insert into mempool
                            mempool.insert(tx);
                            new_hashes.push(hash);
                            log::info!("Accepted new transaction: {:?}", hash);
                        }
                    }
                    drop(blockchain);
                    drop(mempool);
                    if !new_hashes.is_empty() {
                        log::info!("Broadcasting {} new transaction hashes", new_hashes.len());
                        self.server.broadcast(Message::NewTransactionHashes(new_hashes));
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::address::{H160, get_deterministic_keypair};
    use crate::transaction::{RawTransaction, SignedTransaction};
    use crate::block::Block;
    use crate::crypto::hash::Hashable;
    use ring::signature::KeyPair;

    fn setup_test_env() -> (Arc<Mutex<Blockchain>>, Arc<Mutex<Mempool>>) {
        let blockchain = Arc::new(Mutex::new(Blockchain::new()));
        let mempool = Arc::new(Mutex::new(Mempool::new()));
        (blockchain, mempool)
    }

    fn validate_and_insert(tx: &SignedTransaction, blockchain: &Blockchain, mempool: &mut Mempool) -> bool {
        // Signature check
        if !tx.verify_signature() {
            return false;
        }
        // Pubkey matches from_addr
        let derived_addr = H160::from_pubkey(tx.pub_key.as_ref());
        if tx.raw.from_addr != derived_addr {
            return false;
        }
        // State-based check
        let tip_state = blockchain.hash_to_state.get(&blockchain.tip()).unwrap();
        if !tip_state.is_valid(&tx.raw) {
            return false;
        }
        mempool.insert(tx.clone());
        true
    }

    #[test]
    fn test_transaction_signature_validation() {
        let (blockchain, mempool) = setup_test_env();
        let keypair = get_deterministic_keypair(0);
        let addr = H160::from_pubkey(keypair.public_key().as_ref());
        let raw_tx = RawTransaction {
            from_addr: addr,
            to_addr: H160::default(),
            value: 10,
            nonce: 1,
        };
        let valid_tx = SignedTransaction::from_raw(raw_tx, &keypair);
        let mut invalid_tx = valid_tx.clone();
        invalid_tx.signature[0] = invalid_tx.signature[0].wrapping_add(1);
        let mut mempool = mempool.lock().unwrap();
        let blockchain = blockchain.lock().unwrap();
        assert!(validate_and_insert(&valid_tx, &blockchain, &mut mempool));
        assert!(!validate_and_insert(&invalid_tx, &blockchain, &mut mempool));
    }

    #[test]
    fn test_public_key_address_matching() {
        let (blockchain, mempool) = setup_test_env();
        let keypair0 = get_deterministic_keypair(0);
        let keypair1 = get_deterministic_keypair(1);
        let addr0 = H160::from_pubkey(keypair0.public_key().as_ref());
        let raw_tx = RawTransaction {
            from_addr: addr0,
            to_addr: H160::default(),
            value: 10,
            nonce: 1,
        };
        let mismatched_tx = SignedTransaction::from_raw(raw_tx, &keypair1);
        let mut mempool = mempool.lock().unwrap();
        let blockchain = blockchain.lock().unwrap();
        assert!(!validate_and_insert(&mismatched_tx, &blockchain, &mut mempool));
    }

    #[test]
    fn test_state_based_validation() {
        let (blockchain, mempool) = setup_test_env();
        let keypair = get_deterministic_keypair(0);
        let addr = H160::from_pubkey(keypair.public_key().as_ref());
        let wrong_nonce_tx = SignedTransaction::from_raw(
            RawTransaction {
                from_addr: addr,
                to_addr: H160::default(),
                value: 10,
                nonce: 2,
            },
            &keypair
        );
        let insufficient_balance_tx = SignedTransaction::from_raw(
            RawTransaction {
                from_addr: addr,
                to_addr: H160::default(),
                value: 1000000,
                nonce: 1,
            },
            &keypair
        );
        let mut mempool = mempool.lock().unwrap();
        let blockchain = blockchain.lock().unwrap();
        assert!(!validate_and_insert(&wrong_nonce_tx, &blockchain, &mut mempool));
        assert!(!validate_and_insert(&insufficient_balance_tx, &blockchain, &mut mempool));
    }

    #[test]
    fn test_block_transaction_validation() {
        let (blockchain, mempool) = setup_test_env();
        let keypair = get_deterministic_keypair(0);
        let addr = H160::from_pubkey(keypair.public_key().as_ref());
        // Valid transaction
        let valid_tx = SignedTransaction::from_raw(
            RawTransaction {
                from_addr: addr,
                to_addr: H160::default(),
                value: 10,
                nonce: 1,
            },
            &keypair
        );
        // Invalid transaction (wrong nonce)
        let invalid_tx = SignedTransaction::from_raw(
            RawTransaction {
                from_addr: addr,
                to_addr: H160::default(),
                value: 10,
                nonce: 3, // should be 2 for next valid, but 1 is current
            },
            &keypair
        );
        // Only insert the valid transaction into the mempool
        {
            let mut mempool = mempool.lock().unwrap();
            mempool.insert(valid_tx.clone());
        }
        let mut blockchain = blockchain.lock().unwrap();
        // Create block with both transactions
        let block = Block {
            header: crate::block::Header {
                parent: blockchain.tip(),
                nonce: 0,
                difficulty: Block::default_difficulty(),
                timestamp: 0,
                merkle_root: Default::default(),
            },
            content: crate::block::Content {
                transactions: vec![valid_tx.raw.clone(), invalid_tx.raw.clone()],
            },
        };
        // Insert the block
        let mut mempool = mempool.lock().unwrap();
        blockchain.insert(&block, Some(&mut mempool));
        // The block should NOT be inserted
        assert!(blockchain.get_block(&block.hash()).is_none());
    }
}
