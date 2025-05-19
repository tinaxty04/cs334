use crate::block::Block;
use crate::crypto::hash::{H256, Hashable};
use std::collections::HashMap;

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
}

impl Blockchain {
    /// Create a new blockchain, only containing the genesis block
    pub fn new() -> Self {
        let genesis = Block::genesis();
        let genesis_hash = genesis.hash();
        let mut hash_to_block = HashMap::new();
        let mut hash_to_height = HashMap::new();
        let mut hash_to_origin = HashMap::new();
        // Insert genesis block
        hash_to_block.insert(genesis_hash, genesis);
        hash_to_height.insert(genesis_hash, 0);
        hash_to_origin.insert(genesis_hash, BlockOrigin::Mined);
        Blockchain {
            hash_to_block,
            hash_to_height,
            tip: genesis_hash,
            difficulty: Block::default_difficulty(),
            orphan_buffer: HashMap::new(),
            hash_to_origin,
        }
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
        // Insert the block
        self.hash_to_block.insert(block_hash, block.clone());
        self.hash_to_height.insert(block_hash, new_height);
        // Mark as received (default, can be updated by caller)
        self.hash_to_origin.entry(block_hash).or_insert(BlockOrigin::Received { delay_ms: 0 });
        // Update tip if this block extends the longest chain
        if new_height > *self.hash_to_height.get(&self.tip).unwrap() {
            self.tip = block_hash;
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