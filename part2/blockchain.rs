use crate::block::Block;
use crate::crypto::hash::{H256, Hashable};
use std::collections::HashMap;

pub struct Blockchain {
    // Map block hashes to blocks
    hash_to_block: HashMap<H256, Block>,
    // Map block hashes to their heights
    hash_to_height: HashMap<H256, u64>,
    // Current tip (hash of the last block in the longest chain)
    tip: H256,
}

impl Blockchain {
    /// Create a new blockchain, only containing the genesis block
    pub fn new() -> Self {
        let genesis = Block::genesis();
        let genesis_hash = genesis.hash();
        
        let mut hash_to_block = HashMap::new();
        let mut hash_to_height = HashMap::new();
        
        // Insert genesis block
        hash_to_block.insert(genesis_hash, genesis);
        hash_to_height.insert(genesis_hash, 0);
        
        Blockchain {
            hash_to_block,
            hash_to_height,
            tip: genesis_hash,
        }
    }

    /// Insert a block into blockchain
    pub fn insert(&mut self, block: &Block) {
        let block_hash = block.hash();
        let parent_hash = block.header.parent;
        
        // Get parent height and calculate new block's height
        let parent_height = self.hash_to_height.get(&parent_hash).unwrap();
        let new_height = parent_height + 1;
        
        // Insert the block
        self.hash_to_block.insert(block_hash, block.clone());
        self.hash_to_height.insert(block_hash, new_height);
        
        // Update tip if this block extends the longest chain
        if new_height > *self.hash_to_height.get(&self.tip).unwrap() {
            self.tip = block_hash;
        }
    }

    /// Get the last block's hash of the longest chain
    pub fn tip(&self) -> H256 {
        self.tip
    }

    /// Get the last block's hash of the longest chain
    #[cfg(any(test, test_utilities))]
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
}
