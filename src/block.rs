//! This module defines the layout of a block.
//! 
//! You do not need to modify this file, except for the `default_difficulty` function.
//! Please read this file to understand the structure of a block.

use serde::{Serialize, Deserialize};
use crate::crypto::hash::{H256, Hashable};
use crate::transaction::RawTransaction;

/// The block header
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    pub parent: H256,        // Hash of the previous block in the chain
    pub nonce: u32,          // Random number used in proof-of-work mining
    pub difficulty: H256,    // Target hash value for mining (smaller = harder)
    pub timestamp: u128,     // When the block was created
    pub merkle_root: H256,   // Root hash of the merkle tree of transactions
}

/// Transactions contained in a block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Content {
    pub transactions: Vec<RawTransaction>,
}

/// A block in the blockchain
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub header: Header,
    pub content: Content,
}

/// Returns the default difficulty, which is a big-endian 32-byte integer.
/// - Note: a valid block must satisfy that `block.hash() <= difficulty`.
///   In other words, the _smaller_ the `difficulty`, the harder it actually is to mine a block!
fn default_difficulty() -> [u8; 32] {
    // Set difficulty to a very hard value
    let mut difficulty = [0u8; 32];
    difficulty[31] = 0x01; // Only hashes ending in 0x00 or 0x01 are valid
    difficulty
}

impl Block {
    /// Creates the genesis block (first block in the chain)
    /// 
    /// The genesis block is deterministic and has:
    /// - Empty transactions list
    /// - Parent hash of 0 (default)
    /// - Nonce of 0
    /// - Default difficulty
    /// - Timestamp of 0
    /// - Empty merkle root
    pub fn genesis() -> Block {
        let transactions: Vec<RawTransaction> = vec![];
        let header = Header {
            parent: Default::default(),
            nonce: 0,
            difficulty: default_difficulty().into(),
            timestamp: 0,
            merkle_root: Default::default(),
        };
        let content = Content { transactions };
        Block { header, content }
    }

    /// Returns the default difficulty, which is a big-endian 32-byte integer.
    /// - Note: a valid block must satisfy that `block.hash() <= difficulty`.
    ///   In other words, the _smaller_ the `difficulty`, the harder it actually is to mine a block!
    pub fn default_difficulty() -> H256 {
        // Set difficulty to a very hard value
        let mut difficulty = [0u8; 32];
        difficulty[31] = 0x01; // Only hashes ending in 0x00 or 0x01 are valid
        H256::from(difficulty)
    }
}

/// Implement hashing for the block header
/// 
/// This is used for:
/// - Block identification
/// - Proof of work verification
/// - Parent-child relationships
impl Hashable for Header {
    /// Hash the block header using SHA256
    fn hash(&self) -> H256 {
        // Serialize header to bytes
        let bytes = bincode::serialize(&self).unwrap();
        // Compute SHA256 hash
        ring::digest::digest(&ring::digest::SHA256, &bytes).into()
    }
}

/// Implement hashing for the entire block
/// 
/// Note: We only hash the header, not the content
/// This is a common optimization in blockchains
impl Hashable for Block {
    /// Hash only the block header
    fn hash(&self) -> H256 {
        self.header.hash()
    }
}

/* Please add the following code snippet into `src/transaction.rs`: */
// impl Hashable for Transaction {
//     fn hash(&self) -> H256 {
//         let bytes = bincode::serialize(&self).unwrap();
//         ring::digest::digest(&ring::digest::SHA256, &bytes).into()
//     }
// }

/// Test utilities for creating random blocks
#[cfg(any(test, test_utilities))]
pub mod test {
    use super::*;
    use crate::crypto::hash::H256;
    use crate::crypto::merkle::MerkleTree;
    use rand::Rng;

    pub fn generate_random_block(parent: &H256) -> Block {
        let mut rng = rand::thread_rng();
        let nonce = rng.gen();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        
        let transactions: Vec<RawTransaction> = vec![Default::default()];
        let merkle_tree = MerkleTree::new(&transactions);
        let merkle_root = merkle_tree.root();
        
        Block {
            header: Header {
                parent: *parent,
                nonce,
                difficulty: Block::default_difficulty(),
                timestamp,
                merkle_root,
            },
            content: Content { transactions },
        }
    }
}
