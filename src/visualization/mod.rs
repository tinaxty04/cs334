use serde::{Serialize, Deserialize};
use crate::blockchain::Blockchain;
use crate::transaction::SignedTransaction;
use crate::crypto::hash::H256;
use crate::crypto::address::H160;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeState {
    pub id: String,
    pub address: String,
    pub tip_hash: H256,
    pub tip_height: u64,
    pub total_blocks: usize,
    pub blocks_mined: usize,
    pub mempool_size: usize,
    pub accounts: HashMap<H160, (u32, u64)>, // (nonce, balance)
    pub recent_transactions: Vec<TransactionInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionInfo {
    pub hash: H256,
    pub from: H160,
    pub to: H160,
    pub value: u64,
    pub status: TransactionStatus,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TransactionStatus {
    Pending,
    Confirmed,
    Invalid,
}

pub struct Visualizer {
    pub blockchain: Arc<Mutex<Blockchain>>,
    nodes: HashMap<String, NodeState>,
}

impl Visualizer {
    pub fn new(blockchain: Arc<Mutex<Blockchain>>) -> Self {
        Visualizer {
            blockchain,
            nodes: HashMap::new(),
        }
    }

    pub fn update_node_state(&mut self, node_id: &str, address: &str) {
        let blockchain = self.blockchain.lock().unwrap();
        let tip = blockchain.tip();
        let tip_block = blockchain.get_block(&tip).unwrap();
        
        let state = NodeState {
            id: node_id.to_string(),
            address: address.to_string(),
            tip_hash: tip,
            tip_height: *blockchain.hash_to_height.get(&tip).unwrap(),
            total_blocks: blockchain.num_blocks(),
            blocks_mined: blockchain.hash_to_origin.iter()
                .filter(|(_, origin)| matches!(origin, crate::blockchain::BlockOrigin::Mined))
                .count(),
            mempool_size: 0, // TODO: Get from mempool
            accounts: HashMap::new(), // Temporary stub
            recent_transactions: Vec::new(), // TODO: Track recent transactions
        };
        
        self.nodes.insert(node_id.to_string(), state);
    }

    pub fn get_visualization_data(&self) -> String {
        serde_json::to_string(&self.nodes).unwrap()
    }
} 