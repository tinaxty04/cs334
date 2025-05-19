use crate::network::server::Handle as ServerHandle;
use crate::blockchain::Blockchain;
use std::sync::{Arc, Mutex};

use log::info;

use crossbeam::channel::{unbounded, Receiver, Sender, TryRecvError};
use std::time;

use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::crypto::hash::Hashable;

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
    blocks_mined: usize,
}

#[derive(Clone)]
pub struct Handle {
    /// Channel for sending signal to the miner thread
    control_chan: Sender<ControlSignal>,
}

pub fn new(
    server: &ServerHandle,
    blockchain: &Arc<Mutex<Blockchain>>,
) -> (Context, Handle) {
    let (signal_chan_sender, signal_chan_receiver) = unbounded();

    let ctx = Context {
        control_chan: signal_chan_receiver,
        operating_state: OperatingState::Paused,
        server: server.clone(),
        blockchain: Arc::clone(blockchain),
        blocks_mined: 0,
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
        loop {
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
            let (parent_hash, difficulty) = {
                let blockchain = self.blockchain.lock().unwrap();
                let parent = blockchain.tip();
                let parent_block = blockchain.get_block(&parent).unwrap();
                info!("Current difficulty: {:?}", parent_block.header.difficulty);
                (parent, parent_block.header.difficulty)
            };

            // Create new block
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            info!("Block timestamp (ms since epoch): {}", timestamp);

            // Empty transactions for now
            let transactions: Vec<crate::transaction::RawTransaction> = Vec::new();
            
            // Create merkle root from transactions
            let merkle_root = if transactions.is_empty() {
                Default::default()
            } else {
                crate::crypto::merkle::MerkleTree::new(&transactions).root()
            };

            // Try different nonces until we find a valid block
            let mut nonce = 0u32;
            loop {
                // Create block header
                let header = crate::block::Header {
                    parent: parent_hash,
                    nonce,
                    difficulty,
                    timestamp,
                    merkle_root,
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
                    info!("Found a block! Hash: {:?}", block_hash);
                    info!("Difficulty: {:?}", difficulty);
                    let block_size = bincode::serialize(&block).unwrap().len();
                    info!("Block size: {} bytes", block_size);
                    // Insert block into blockchain
                    let mut blockchain = self.blockchain.lock().unwrap();
                    blockchain.insert(&block);
                    drop(blockchain);
                    // Broadcast new block hash to peers
                    self.server.broadcast(crate::network::message::Message::NewBlockHashes(vec![block_hash]));
                    info!("Block inserted into blockchain");
                    self.blocks_mined += 1;
                    break;
                }

                // Try next nonce
                nonce = nonce.wrapping_add(1);
            }

            if let OperatingState::Run(i) = self.operating_state {
                if i != 0 {
                    let interval = time::Duration::from_micros(i as u64);
                    thread::sleep(interval);
                }
            }
        }
    }
}