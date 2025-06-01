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
                            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis();
                            let delay = now.saturating_sub(block.header.timestamp);
                            blockchain.insert(&block);
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
            }
        }
    }
}
