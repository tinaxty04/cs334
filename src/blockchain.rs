use crate::block::Block;
use crate::crypto::hash::{H256, Hashable};
use crate::crypto::address::{H160, get_deterministic_keypair};
use std::collections::HashMap;
use crate::transaction::RawTransaction;
use crate::mempool::Mempool;
use ring::signature::KeyPair;

#[derive(Clone)]
pub struct State {
    pub map: HashMap<H160, (u32, u64)>, // address -> (nonce, balance)
}

impl State {
    /// Initial coin offering; generate an initial state.
    pub fn ico() -> Self {
        let mut state = HashMap::new();
        // give the i-th account 1000 * (10 - i) coins, i = 0, 1, 2, ..., 9
        for i in 0..10 {
            let pair = get_deterministic_keypair(i);
            let address = H160::from_pubkey(pair.public_key().as_ref());
            let balance: u64 = 1000 * ((10 - i) as u64);
            let nonce: u32 = 0;
            state.insert(address, (nonce, balance));
        }
        State { map: state }
    }

    /// Check if a transaction is valid with respect to this state
    pub fn is_valid(&self, tx: &RawTransaction) -> bool {
        if let Some((nonce, balance)) = self.map.get(&tx.from_addr) {
            if *balance < tx.value {
                return false;
            }
            if tx.nonce != *nonce + 1 {
                return false;
            }
        } else {
            return false;
        }
        true
    }

    /// Apply a transaction to the state (assumes it is valid)
    pub fn apply(&mut self, tx: &RawTransaction) {
        // Subtract from sender
        if let Some((nonce, balance)) = self.map.get_mut(&tx.from_addr) {
            *nonce += 1;
            *balance -= tx.value;
        }
        // Add to receiver (create if needed)
        let entry = self.map.entry(tx.to_addr).or_insert((0, 0));
        entry.1 += tx.value;
    }
}

pub enum BlockOrigin {
    Mined,
    Received { delay_ms: u128 },
}

pub struct Blockchain {
    // Map block hashes to blocks
    hash_to_block: HashMap<H256, Block>,
    // Map block hashes to their heights
    hash_to_height: HashMap<H256, u64>,
    // Current tip (hash of the last block in the longest chain)
    tip: H256,
    // Fixed difficulty for all blocks
    difficulty: H256,
    // Orphan buffer: parent hash -> list of orphan blocks
    pub orphan_buffer: HashMap<H256, Vec<Block>>,
    // Block origin tracking
    pub hash_to_origin: HashMap<H256, BlockOrigin>,
    // State per block: block hash -> State
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
        // Initial state (ICO)
        let state = State::ico();
        hash_to_state.insert(genesis_hash, state);
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

    /// Insert a block into blockchain, process orphans if possible
    pub fn insert(&mut self, block: &Block, mempool: Option<&mut Mempool>) {
        let block_hash = block.hash();
        let parent_hash = block.header.parent;
        // Only insert if parent exists
        if !self.hash_to_block.contains_key(&parent_hash) {
            self.orphan_buffer.entry(parent_hash).or_insert_with(Vec::new).push(block.clone());
            return;
        }
        // Validate all transactions in the block BEFORE any insertion
        for tx in &block.content.transactions {
            // 1. Check if transaction is in the mempool (if available)
            let signed_tx = if let Some(ref mempool) = mempool {
                mempool.get_transaction(&tx.hash()).cloned()
            } else {
                None
            };
            // 2. Signature check (if signed_tx available)
            if let Some(signed_tx) = &signed_tx {
                if !signed_tx.verify_signature() {
                    log::warn!("Block contains transaction with invalid signature");
                    return; // Reject block
                }
                // 3. Pubkey matches from_addr
                let derived_addr = crate::crypto::address::H160::from_pubkey(signed_tx.pub_key.as_ref());
                if tx.from_addr != derived_addr {
                    log::warn!("Block contains transaction where public key doesn't match from address");
                    return; // Reject block
                }
            }
            // 4. State-based check
            let parent_state = self.hash_to_state.get(&block.header.parent).unwrap();
            if !parent_state.is_valid(tx) {
                log::warn!("Block contains transaction with invalid state (balance/nonce): from_addr={:?}, nonce={}, expected_nonce={}, balance={}, value={}",
                    tx.from_addr,
                    tx.nonce,
                    parent_state.map.get(&tx.from_addr).map(|(n, _)| *n + 1).unwrap_or(0),
                    parent_state.map.get(&tx.from_addr).map(|(_, b)| *b).unwrap_or(0),
                    tx.value
                );
                return; // Reject block
            }
        }
        // Get parent height and calculate new block's height
        let parent_height = self.hash_to_height.get(&parent_hash).unwrap();
        let new_height = parent_height + 1;
        // Insert the block
        self.hash_to_block.insert(block_hash, block.clone());
        self.hash_to_height.insert(block_hash, new_height);
        self.hash_to_origin.entry(block_hash).or_insert(BlockOrigin::Received { delay_ms: 0 });
        // Update tip if this block extends the longest chain
        if new_height > *self.hash_to_height.get(&self.tip).unwrap() {
            self.tip = block_hash;
        }
        // --- State update per block ---
        // Clone parent state
        let parent_state = self.hash_to_state.get(&parent_hash).unwrap().clone();
        let mut new_state = parent_state.clone();
        // Apply each transaction in the block
        for tx in &block.content.transactions {
            if new_state.is_valid(tx) {
                new_state.apply(tx);
            } else {
                // Optionally: log or handle invalid tx in block
            }
        }
        self.hash_to_state.insert(block_hash, new_state.clone());
        // --- Mempool revalidation ---
        if let Some(mempool) = mempool {
            let mut to_remove = Vec::new();
            for hash in mempool.all_hashes() {
                if let Some(tx) = mempool.get_transaction(&hash) {
                    if !new_state.is_valid(&tx.raw) {
                        to_remove.push(hash);
                    }
                }
            }
            for hash in to_remove {
                mempool.remove(&hash);
            }
        }
        // Process orphans that have this block as parent
        let mut queue = vec![block_hash];
        while let Some(parent) = queue.pop() {
            if let Some(children) = self.orphan_buffer.remove(&parent) {
                for child in children {
                    let child_hash = child.hash();
                    let child_height = self.hash_to_height.get(&parent).unwrap() + 1;
                    self.hash_to_block.insert(child_hash, child.clone());
                    self.hash_to_height.insert(child_hash, child_height);
                    self.hash_to_origin.entry(child_hash).or_insert(BlockOrigin::Received { delay_ms: 0 });
                    if child_height > *self.hash_to_height.get(&self.tip).unwrap() {
                        self.tip = child_hash;
                    }
                    queue.push(child_hash);
                }
            }
        }
    }

    /// Get the last block's hash of the longest chain
    pub fn tip(&self) -> H256 {
        self.tip
    }

    /// Get the last block's hash of the longest chain
    #[cfg(test)]
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
    use ring::signature::KeyPair;
    // use crate::block::test::generate_random_block;

    /*
    #[test]
    fn insert_one() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block = generate_random_block(&genesis_hash);
        blockchain.insert(&block, None);
        assert_eq!(blockchain.tip(), block.hash());
    }
    #[test]
    fn mp1_insert_chain() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let mut block = generate_random_block(&genesis_hash);
        blockchain.insert(&block, None);
        assert_eq!(blockchain.tip(), block.hash());
        for _ in 0..50 {
            let h = block.hash();
            block = generate_random_block(&h);
            blockchain.insert(&block, None);
            assert_eq!(blockchain.tip(), block.hash());
        }
    }
    #[test]
    fn mp1_insert_3_fork_and_back() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let block_1 = generate_random_block(&genesis_hash);
        blockchain.insert(&block_1, None);
        assert_eq!(blockchain.tip(), block_1.hash());
        let block_2 = generate_random_block(&block_1.hash());
        blockchain.insert(&block_2, None);
        assert_eq!(blockchain.tip(), block_2.hash());
        let block_3 = generate_random_block(&block_2.hash());
        blockchain.insert(&block_3, None);
        assert_eq!(blockchain.tip(), block_3.hash());
        let fork_block_1 = generate_random_block(&block_2.hash());
        blockchain.insert(&fork_block_1, None);
        assert_eq!(blockchain.tip(), block_3.hash());
        let fork_block_2 = generate_random_block(&fork_block_1.hash());
        blockchain.insert(&fork_block_2, None);
        assert_eq!(blockchain.tip(), fork_block_2.hash());
        let block_4 = generate_random_block(&block_3.hash());
        blockchain.insert(&block_4, None);
        assert_eq!(blockchain.tip(), fork_block_2.hash());
        let block_5 = generate_random_block(&block_4.hash());
        blockchain.insert(&block_5, None);
        assert_eq!(blockchain.tip(), block_5.hash());
    }
    */

    use crate::crypto::address::{get_deterministic_keypair, H160};
    use crate::transaction::{RawTransaction, SignedTransaction};
    use crate::block::Header;
    use rand::seq::SliceRandom;

    #[test]
    fn insert_account_based_block() {
        let mut blockchain = Blockchain::new();
        let genesis_hash = blockchain.tip();
        let parent_state = blockchain.hash_to_state.get(&genesis_hash).unwrap().clone();
        let mut state = parent_state.clone();
        let mut txs = Vec::new();
        let mut rng = rand::thread_rng();
        let mut senders: Vec<_> = (0..10).collect();
        senders.shuffle(&mut rng);
        for i in 0..5 {
            let sender_idx = senders[i % senders.len()];
            let sender_key = get_deterministic_keypair(sender_idx as u8);
            let sender_addr = H160::from_pubkey(sender_key.public_key().as_ref());
            let (nonce, balance) = state.map.get(&sender_addr).cloned().unwrap();
            if balance == 0 { continue; }
            let value = 1;
            let receiver_idx = (sender_idx + 1) % 10;
            let receiver_key = get_deterministic_keypair(receiver_idx as u8);
            let receiver_addr = H160::from_pubkey(receiver_key.public_key().as_ref());
            let raw_tx = RawTransaction {
                from_addr: sender_addr,
                to_addr: receiver_addr,
                value,
                nonce: nonce + 1,
            };
            let signed_tx = SignedTransaction::from_raw(raw_tx.clone(), &sender_key);
            txs.push(raw_tx.clone());
            state.apply(&raw_tx);
        }
        let block = Block {
            header: Header {
                parent: genesis_hash,
                nonce: 0,
                difficulty: blockchain.difficulty,
                timestamp: 0,
                merkle_root: Default::default(),
            },
            content: crate::block::Content {
                transactions: txs.clone(),
            },
        };
        blockchain.insert(&block, None);
        let new_state = blockchain.hash_to_state.get(&block.hash()).unwrap();
        for tx in &txs {
            let (nonce, balance) = new_state.map.get(&tx.from_addr).unwrap();
            assert!(*nonce >= 1);
            assert!(*balance <= 10000);
        }
        assert_eq!(blockchain.tip(), block.hash());
    }
}