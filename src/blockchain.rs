use crate::block::Block;
use crate::crypto::hash::{H256, Hashable};
use crate::crypto::address::H160;
use std::collections::HashMap;
use ring::signature::{Ed25519KeyPair, KeyPair};
use log::info;

#[derive(Clone)]
pub struct State {
    pub map: HashMap<H160, (u32, u64)>
}

impl State {
    /// Initial coin offering; generate an initial state.
    fn ico() -> Self {
        let mut state = HashMap::new();
        // Create 10 accounts with balances: 10000, 9000, ..., 1000
        info!("[State] Starting Initial Coin Offering (ICO)");
        for i in 0..10 {
            let pair = get_deterministic_keypair(i as u8);
            let address = H160::from_pubkey(pair.public_key().as_ref());
            let balance: u64 = 1000 * ((10 - i) as u64);
            let nonce: u32 = 0;
            state.insert(address, (nonce, balance));
            info!("[State] ICO Account {}: address={}, initial_balance={}, initial_nonce={}", i, address, balance, nonce);
        }
        info!("[State] ICO completed with {} accounts", state.len());
        State { map: state }
    }

    /// Get account state (nonce and balance)
    pub fn get(&self, addr: &H160) -> Option<(u32, u64)> {
        self.map.get(addr).cloned()
    }

    /// Update account state
    pub fn update(&mut self, addr: H160, nonce: u32, balance: u64) {
        let old_state = self.map.get(&addr).cloned();
        self.map.insert(addr, (nonce, balance));
        if let Some((old_nonce, old_balance)) = old_state {
            info!("[State] Account {} updated: nonce {}->{}, balance {}->{}", 
                addr, old_nonce, nonce, old_balance, balance);
        } else {
            info!("[State] New account {} created: nonce={}, balance={}", 
                addr, nonce, balance);
        }
    }

    /// Create a new state by applying transactions
    pub fn apply_transactions(&self, transactions: &[crate::transaction::SignedTransaction]) -> Option<Self> {
        let mut new_state = self.clone();
        info!("[State] Applying {} transactions", transactions.len());
        for (i, tx) in transactions.iter().enumerate() {
            let from_addr = tx.raw.from_addr;
            let to_addr = tx.raw.to_addr;
            info!("[State] Processing transaction {}: from={} to={} value={} nonce={}", 
                i, from_addr, to_addr, tx.raw.value, tx.raw.nonce);
            
            // Get current state
            let (from_nonce, from_balance) = new_state.get(&from_addr)?;
            info!("[State] Sender {} current state: nonce={}, balance={}", 
                from_addr, from_nonce, from_balance);
            
            // Verify nonce
            if tx.raw.nonce != from_nonce + 1 {
                info!("[State] Transaction rejected: invalid nonce for account {} (expected {}, got {})", 
                    from_addr, from_nonce + 1, tx.raw.nonce);
                return None;
            }
            
            // Verify balance
            if tx.raw.value > from_balance {
                info!("[State] Transaction rejected: insufficient balance for account {} (have {}, need {})", 
                    from_addr, from_balance, tx.raw.value);
                return None;
            }
            
            // Update sender
            new_state.update(from_addr, from_nonce + 1, from_balance - tx.raw.value);
            
            // Update receiver (create new account if needed)
            let (to_nonce, to_balance) = new_state.get(&to_addr).unwrap_or((0, 0));
            info!("[State] Receiver {} current state: nonce={}, balance={}", 
                to_addr, to_nonce, to_balance);
            new_state.update(to_addr, to_nonce, to_balance + tx.raw.value);
            
            info!("[State] Transaction {} completed: {} sent {} coins to {}", 
                i, from_addr, tx.raw.value, to_addr);
        }
        Some(new_state)
    }

    /// Log all account balances
    pub fn log_balances(&self) {
        info!("[State] Current account balances:");
        for (addr, (nonce, balance)) in &self.map {
            info!("[State] Account {}: nonce={}, balance={}", addr, nonce, balance);
        }
    }

    /// Return all accounts as (address, nonce, balance)
    pub fn all_accounts(&self) -> Vec<(H160, u32, u64)> {
        self.map.iter().map(|(addr, (nonce, balance))| (*addr, *nonce, *balance)).collect()
    }
}

/// Get a deterministic keypair from a nonce
pub fn get_deterministic_keypair(nonce: u8) -> Ed25519KeyPair {
    let mut seed = [0u8; 32];
    seed[0] = nonce;
    Ed25519KeyPair::from_seed_unchecked(&seed).unwrap()
}

pub enum BlockOrigin {
    Mined,
    Received { delay_ms: u128 },
}

pub struct Blockchain {
    pub hash_to_block: HashMap<H256, Block>,
    pub hash_to_height: HashMap<H256, u64>,
    // Current tip (hash of the last block in the longest chain)
    tip: H256,
    // Fixed difficulty for all blocks
    difficulty: H256,
    // Orphan buffer: parent hash -> list of orphan blocks
    pub orphan_buffer: HashMap<H256, Vec<Block>>,
    // Block origin tracking
    pub hash_to_origin: HashMap<H256, BlockOrigin>,
    // State tracking: block hash -> state after executing the block
    pub hash_to_state: HashMap<H256, State>,
}

impl Blockchain {
    /// Create a new blockchain, only containing the genesis block
    pub fn new() -> Self {
        let genesis = Block::genesis();
        let genesis_hash = genesis.hash();
        let mut hash_to_block = HashMap::new();
        let mut hash_to_height = HashMap::new();
        let mut hash_to_origin = HashMap::new();
        let mut hash_to_state = HashMap::new();
        
        // Insert genesis block
        hash_to_block.insert(genesis_hash, genesis);
        hash_to_height.insert(genesis_hash, 0);
        hash_to_origin.insert(genesis_hash, BlockOrigin::Mined);
        
        // Initialize state with ICO
        let initial_state = State::ico();
        initial_state.log_balances(); // Log initial balances
        hash_to_state.insert(genesis_hash, initial_state);
        
        Blockchain {
            hash_to_block,
            hash_to_height,
            tip: genesis_hash,
            difficulty: Block::default_difficulty(),
            orphan_buffer: HashMap::new(),
            hash_to_origin,
            hash_to_state,
        }
    }

    /// Get the state for a specific block
    pub fn get_state(&self, block_hash: &H256) -> Option<&State> {
        self.hash_to_state.get(block_hash)
    }

    /// Get the state for the current tip
    pub fn get_state_for_tip(&self) -> &State {
        self.hash_to_state.get(&self.tip).unwrap()
    }

    /// Insert a block into blockchain, process orphans if possible
    pub fn insert(&mut self, block: &Block) {
        let block_hash = block.hash();
        let parent_hash = block.header.parent;
        // Only insert if parent exists
        if !self.hash_to_block.contains_key(&parent_hash) {
            // Add to orphan buffer
            self.orphan_buffer.entry(parent_hash).or_insert_with(Vec::new).push(block.clone());
            return;
        }
        // Get parent height and calculate new block's height
        let parent_height = self.hash_to_height.get(&parent_hash).unwrap();
        let new_height = parent_height + 1;
        // Get parent state and apply transactions
        let parent_state = self.hash_to_state.get(&parent_hash).unwrap();
        info!("[Blockchain] Inserting block {} at height {} with {} transactions", block_hash, new_height, block.content.transactions.len());
        for (i, tx) in block.content.transactions.iter().enumerate() {
            info!("[Blockchain] Block tx {}: from={} to={} value={} nonce={}", i, tx.raw.from_addr, tx.raw.to_addr, tx.raw.value, tx.raw.nonce);
        }
        if let Some(new_state) = parent_state.apply_transactions(&block.content.transactions) {
            // Insert the block and its state
            self.hash_to_block.insert(block_hash, block.clone());
            self.hash_to_height.insert(block_hash, new_height);
            self.hash_to_state.insert(block_hash, new_state.clone());
            // Log state changes
            info!("[Blockchain] Block {} inserted at height {}", block_hash, new_height);
            new_state.log_balances();
            // Mark as received (default, can be updated by caller)
            self.hash_to_origin.entry(block_hash).or_insert(BlockOrigin::Received { delay_ms: 0 });
            // Update tip if this block extends the longest chain
            if new_height > *self.hash_to_height.get(&self.tip).unwrap() {
                self.tip = block_hash;
                info!("[Blockchain] New tip: {} at height {}", block_hash, new_height);
            }
            // Process orphans that have this block as parent
            let mut queue = vec![block_hash];
            while let Some(parent) = queue.pop() {
                if let Some(children) = self.orphan_buffer.remove(&parent) {
                    for child in children {
                        let child_hash = child.hash();
                        let child_height = self.hash_to_height.get(&parent).unwrap() + 1;
                        // Get parent state and apply transactions
                        let parent_state = self.hash_to_state.get(&parent).unwrap();
                        info!("[Blockchain] Inserting orphan block {} at height {} with {} transactions", child_hash, child_height, child.content.transactions.len());
                        for (i, tx) in child.content.transactions.iter().enumerate() {
                            info!("[Blockchain] Orphan block tx {}: from={} to={} value={} nonce={}", i, tx.raw.from_addr, tx.raw.to_addr, tx.raw.value, tx.raw.nonce);
                        }
                        if let Some(new_state) = parent_state.apply_transactions(&child.content.transactions) {
                            self.hash_to_block.insert(child_hash, child.clone());
                            self.hash_to_height.insert(child_hash, child_height);
                            self.hash_to_state.insert(child_hash, new_state.clone());
                            // Log state changes for orphan blocks
                            info!("[Blockchain] Orphan block {} inserted at height {}", child_hash, child_height);
                            new_state.log_balances();
                            self.hash_to_origin.entry(child_hash).or_insert(BlockOrigin::Received { delay_ms: 0 });
                            if child_height > *self.hash_to_height.get(&self.tip).unwrap() {
                                self.tip = child_hash;
                                info!("[Blockchain] New tip (from orphan): {} at height {}", child_hash, child_height);
                            }
                            queue.push(child_hash);
                        }
                    }
                }
            }
        } else {
            info!("[Blockchain] Block {} at height {} rejected: invalid transactions", block_hash, new_height);
        }
    }

    /// Get the last block's hash of the longest chain
    pub fn tip(&self) -> H256 {
        self.tip
    }

    /// Get the last block's hash of the longest chain
    pub fn all_blocks_in_longest_chain(&self) -> Vec<H256> {
        let mut chain = Vec::new();
        let mut current_hash = self.tip;
        
        // Traverse from tip to genesis
        while current_hash != H256::default() {
            chain.push(current_hash);
            if let Some(block) = self.hash_to_block.get(&current_hash) {
                current_hash = block.header.parent;
            } else {
                break;
            }
        }
        
        // Add genesis block
        chain.push(H256::default());
        
        // Reverse to get genesis to tip order
        chain.reverse();
        chain
    }

    /// Get the number of blocks in the blockchain
    pub fn num_blocks(&self) -> usize {
        self.hash_to_block.len()
    }

    /// Get a block by its hash
    pub fn get_block(&self, hash: &H256) -> Option<&Block> {
        self.hash_to_block.get(hash)
    }
}
#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::block::test::generate_random_block;

    #[test]
    fn insert_one() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block = generate_random_block(&genesis_hash);
        blockchain.insert(&block);
        assert_eq!(blockchain.tip(), block.hash());
    }
    #[test]
    fn mp1_insert_chain() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let mut block = generate_random_block(&genesis_hash);
        blockchain.insert(&block);
        assert_eq!(blockchain.tip(), block.hash());
        for _ in 0..50 {
            let h = block.hash();
            block = generate_random_block(&h);
            blockchain.insert(&block);
            assert_eq!(blockchain.tip(), block.hash());
        }
    }

    #[test]
    fn mp1_insert_3_fork_and_back() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block_1 = generate_random_block(&genesis_hash);
        blockchain.insert(&block_1);
        assert_eq!(blockchain.tip(), block_1.hash());
        let block_2 = generate_random_block(&block_1.hash());
        blockchain.insert(&block_2);
        assert_eq!(blockchain.tip(), block_2.hash());
        let block_3 = generate_random_block(&block_2.hash());
        blockchain.insert(&block_3);
        assert_eq!(blockchain.tip(), block_3.hash());
        let fork_block_1 = generate_random_block(&block_2.hash());
        blockchain.insert(&fork_block_1);
        assert_eq!(blockchain.tip(), block_3.hash());
        let fork_block_2 = generate_random_block(&fork_block_1.hash());
        blockchain.insert(&fork_block_2);
        assert_eq!(blockchain.tip(), fork_block_2.hash());
        let block_4 = generate_random_block(&block_3.hash());
        blockchain.insert(&block_4);
        assert_eq!(blockchain.tip(), fork_block_2.hash());
        let block_5 = generate_random_block(&block_4.hash());
        blockchain.insert(&block_5);
        assert_eq!(blockchain.tip(), block_5.hash());
    }
}