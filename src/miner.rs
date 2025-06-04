use crate::network::server::Handle as ServerHandle;
use crate::blockchain::Blockchain;
use std::sync::{Arc, Mutex};

use log::info;

use crossbeam::channel::{unbounded, Receiver, Sender, TryRecvError};
use std::time;

use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::hash::Hashable;
use crate::mempool::Mempool;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand::Rng;

const BLOCK_TX_LIMIT: usize = 6;

enum ControlSignal {
    Start(u64), // the number controls the lambda of interval between block generation
    Exit,
}

enum OperatingState {
    Paused,
    Run(u64),
    ShutDown,
}

pub struct Context {
    /// Channel for receiving control signal
    control_chan: Receiver<ControlSignal>,
    operating_state: OperatingState,
    server: ServerHandle,
    blockchain: Arc<Mutex<Blockchain>>,
    mempool: Arc<Mutex<Mempool>>,
    blocks_mined: usize,
    miner_address: String,
}

#[derive(Clone)]
pub struct Handle {
    /// Channel for sending signal to the miner thread
    control_chan: Sender<ControlSignal>,
}

pub fn new(
    server: &ServerHandle,
    blockchain: &Arc<Mutex<Blockchain>>,
    mempool: &Arc<Mutex<Mempool>>,
    miner_address: String,
) -> (Context, Handle) {
    let (signal_chan_sender, signal_chan_receiver) = unbounded();

    let ctx = Context {
        control_chan: signal_chan_receiver,
        operating_state: OperatingState::Paused,
        server: server.clone(),
        blockchain: Arc::clone(blockchain),
        mempool: Arc::clone(mempool),
        blocks_mined: 0,
        miner_address,
    };

    let handle = Handle {
        control_chan: signal_chan_sender,
    };

    (ctx, handle)
}

impl Handle {
    pub fn exit(&self) {
        self.control_chan.send(ControlSignal::Exit).unwrap();
    }

    pub fn start(&self, lambda: u64) {
        self.control_chan
            .send(ControlSignal::Start(lambda))
            .unwrap();
    }

}

impl Context {
    pub fn start(mut self) {
        thread::Builder::new()
            .name("miner".to_string())
            .spawn(move || {
                self.miner_loop();
            })
            .unwrap();
        info!("Miner initialized into paused mode");
    }

    fn handle_control_signal(&mut self, signal: ControlSignal) {
        match signal {
            ControlSignal::Exit => {
                info!("Miner shutting down");
                let blockchain = self.blockchain.lock().unwrap();
                info!("Blocks mined by this process: {}", self.blocks_mined);
                info!("Blockchain length: {} blocks", blockchain.num_blocks());
                self.operating_state = OperatingState::ShutDown;
            }
            ControlSignal::Start(i) => {
                info!("Miner starting in continuous mode with lambda {}", i);
                self.operating_state = OperatingState::Run(i);
            }
        }
    }

    fn miner_loop(&mut self) {
        let mut rng = rand::thread_rng();
        loop {
            // Add random delay for mining fairness
            let delay: u64 = rng.gen_range(200, 1200); // 200ms to 1200ms
            std::thread::sleep(std::time::Duration::from_millis(delay));
            // check and react to control signals
            match self.operating_state {
                OperatingState::Paused => {
                    let signal = self.control_chan.recv().unwrap();
                    self.handle_control_signal(signal);
                    continue;
                }
                OperatingState::ShutDown => {
                    return;
                }
                _ => match self.control_chan.try_recv() {
                    Ok(signal) => {
                        self.handle_control_signal(signal);
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => panic!("Miner control channel detached"),
                },
            }
            if let OperatingState::ShutDown = self.operating_state {
                return;
            }

            info!("Mining attempt started...");

            // Get parent block and difficulty
            let (parent_hash, difficulty, parent_state) = {
                let blockchain = self.blockchain.lock().unwrap();
                let parent = blockchain.tip();
                let parent_block = blockchain.get_block(&parent).unwrap();
                info!("Current difficulty: {:?}", parent_block.header.difficulty);
                // To make mining faster, adjust the difficulty here if needed:
                // let difficulty = crate::block::Block::default_difficulty();
                let state = blockchain.get_state_for_tip().clone();
                (parent, parent_block.header.difficulty, state)
            };

            // Log mempool contents
            {
                let mut mempool = self.mempool.lock().unwrap();
                let blockchain = self.blockchain.lock().unwrap();
                info!("[Miner] Cleaning up outdated transactions in mempool");
                mempool.log_contents();
            }

            // Pull transactions from mempool (must have at least 6 valid)
            let transactions = {
                let mut mempool = self.mempool.lock().unwrap();
                let all_txs = mempool.get_transactions(1000); // get all for filtering
                let mut valid_txs = Vec::new();
                let mut temp_state = parent_state.clone();
                info!("[Miner] Processing {} transactions from mempool", all_txs.len());
                
                for tx in all_txs {
                    // Check signature
                    if !tx.verify_signature() { 
                        info!("[Miner] Transaction {} rejected: invalid signature", tx.hash());
                        continue; 
                    }
                    // Check pubkey matches from_addr
                    let from_addr = tx.raw.from_addr;
                    let pubkey_addr = crate::crypto::address::H160::from_pubkey(&tx.pub_key);
                    if from_addr != pubkey_addr { 
                        info!("[Miner] Transaction {} rejected: pubkey mismatch", tx.hash());
                        continue; 
                    }
                    // Check nonce and balance
                    let (acc_nonce, acc_balance) = temp_state.get(&from_addr).unwrap_or((0, 0));
                    if tx.raw.nonce != acc_nonce + 1 { 
                        info!("[Miner] Transaction {} rejected: invalid nonce (expected {}, got {})", 
                            tx.hash(), acc_nonce + 1, tx.raw.nonce);
                        continue; 
                    }
                    if tx.raw.value > acc_balance { 
                        info!("[Miner] Transaction {} rejected: insufficient balance (have {}, need {})", 
                            tx.hash(), acc_balance, tx.raw.value);
                        continue; 
                    }
                    // Apply to temp state
                    temp_state.update(from_addr, acc_nonce + 1, acc_balance - tx.raw.value);
                    let (to_nonce, to_balance) = temp_state.get(&tx.raw.to_addr).unwrap_or((0, 0));
                    temp_state.update(tx.raw.to_addr, to_nonce, to_balance + tx.raw.value);
                    let tx_hash = tx.hash();
                    valid_txs.push(tx);
                    info!("[Miner] Added valid transaction {} to block ({} of {})", 
                        tx_hash, valid_txs.len(), BLOCK_TX_LIMIT);
                    if valid_txs.len() >= BLOCK_TX_LIMIT { 
                        info!("[Miner] Reached maximum transactions per block ({})", BLOCK_TX_LIMIT);
                        break; 
                    }
                }
                if valid_txs.is_empty() {
                    info!("[Miner] No valid transactions found in mempool, waiting...");
                    drop(mempool);
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    continue;
                }
                info!("[Miner] Found {} valid transactions for new block", valid_txs.len());
                valid_txs
            };

            // Create merkle root from transactions
            let merkle_root = crate::crypto::merkle::MerkleTree::new(&transactions).root();

            // Try different nonces until we find a valid block
            let mut nonce = 0u32;
            let miner_addresses = ["account0", "account1", "account2"];
            let mut rng = thread_rng();
            let miner_address = miner_addresses.choose(&mut rng).unwrap().to_string();
            loop {
                // Create block header
                let header = crate::block::Header {
                    parent: parent_hash,
                    nonce,
                    difficulty,
                    timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis(),
                    merkle_root,
                    miner: miner_address.clone(),
                };

                // Create block content
                let content = crate::block::Content {
                    transactions: transactions.clone(),
                };

                // Create complete block
                let block = crate::block::Block { header, content };

                // Check if block satisfies proof-of-work
                let block_hash = block.hash();
                if block_hash <= difficulty {
                    let height = {
                        let blockchain = self.blockchain.lock().unwrap();
                        blockchain.hash_to_height.get(&parent_hash).unwrap() + 1
                    };
                    info!("[Miner] Found valid block: height={}, hash={}, parent={}, txs={}",
                        height,
                        block_hash,
                        parent_hash,
                        block.content.transactions.len()
                    );
                    // Log transactions in the block
                    for (i, tx) in block.content.transactions.iter().enumerate() {
                        info!("[Miner] Block tx {}: from={} to={} value={} nonce={}",
                            i, tx.raw.from_addr, tx.raw.to_addr, tx.raw.value, tx.raw.nonce);
                    }
                    // Insert block into blockchain
                    {
                        let mut blockchain = self.blockchain.lock().unwrap();
                        blockchain.insert(&block);
                        info!("[Miner] Block {} inserted at height {}", block_hash, height);
                        // Log consensus state
                        let tip = blockchain.tip();
                        let tip_height = blockchain.hash_to_height.get(&tip).unwrap();
                        info!("[Miner] Consensus state: tip={} at height={}, total_blocks={}",
                            tip, tip_height, blockchain.num_blocks());
                    }
                    // Remove included transactions from mempool
                    {
                        let mut mempool = self.mempool.lock().unwrap();
                        info!("[Miner] Removing {} transactions from mempool after block inclusion", transactions.len());
                        for tx in &transactions {
                            let tx_hash = tx.hash();
                            info!("[Miner] Removing transaction {} from mempool: from={} to={} value={} nonce={}", 
                                tx_hash, tx.raw.from_addr, tx.raw.to_addr, tx.raw.value, tx.raw.nonce);
                            mempool.remove(&tx_hash);
                        }
                        // Log remaining mempool contents
                        mempool.log_contents();
                    }
                    self.blocks_mined += 1;
                    info!("[Miner] Moving to next block...");
                    break;
                }
                nonce = nonce.wrapping_add(1);
            }

            if let OperatingState::Run(i) = self.operating_state {
                // Remove or reduce this sleep to speed up main chain growth
                // if i != 0 {
                //     let interval = time::Duration::from_micros(i as u64);
                //     thread::sleep(interval);
                // }
            }
        }
    }
}