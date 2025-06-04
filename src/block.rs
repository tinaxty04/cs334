//! This module defines the layout of a block.
//! 
//! You do not need to modify this file, except for the `default_difficulty` function.
//! Please read this file to understand the structure of a block.

use serde::{Serialize, Deserialize};
use crate::crypto::hash::{H256, Hashable};
<<<<<<< HEAD
use crate::transaction::RawTransaction;
=======
use crate::transaction::SignedTransaction;
>>>>>>> b920444 (Initial commit for demo done)

/// The block header
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Header {
    pub parent: H256,        // Hash of the previous block in the chain
    pub nonce: u32,          // Random number used in proof-of-work mining
    pub difficulty: H256,    // Target hash value for mining (smaller = harder)
    pub timestamp: u128,     // When the block was created
    pub merkle_root: H256,   // Root hash of the merkle tree of transactions
<<<<<<< HEAD
=======
    pub miner: String,        // Add miner field
>>>>>>> b920444 (Initial commit for demo done)
}

/// Transactions contained in a block
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Content {
<<<<<<< HEAD
    pub transactions: Vec<RawTransaction>,
=======
    pub transactions: Vec<SignedTransaction>,
>>>>>>> b920444 (Initial commit for demo done)
}

/// A block in the blockchain
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub header: Header,
    pub content: Content,
}


//default difficulty
pub fn default_difficulty() -> H256 {
    let mut difficulty = [0x00u8; 32];
<<<<<<< HEAD
    // Try requiring the first two bytes to be zero, and the third to be 0x0f
    // This means only hashes starting with 16 bits of zero and the next nibble <= 0x0f are valid
    difficulty[0] = 0x00;
    difficulty[1] = 0x00;
    difficulty[2] = 0x03; // You can lower this to 0x07, 0x03, or 0x01 for even harder
=======
    difficulty[0] = 0x00;
    difficulty[1] = 0x00;
    difficulty[2] = 0x06;
    difficulty[3] = 0xff;
>>>>>>> b920444 (Initial commit for demo done)
    H256::from(difficulty)
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
<<<<<<< HEAD
        let transactions: Vec<RawTransaction> = vec![];
=======
        let transactions: Vec<SignedTransaction> = vec![];
>>>>>>> b920444 (Initial commit for demo done)
        let header = Header {
            parent: Default::default(),
            nonce: 0,
            difficulty: default_difficulty().into(),
            timestamp: 0,
            merkle_root: Default::default(),
<<<<<<< HEAD
=======
            miner: "genesis".to_string(), // Set miner for genesis
>>>>>>> b920444 (Initial commit for demo done)
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
        
<<<<<<< HEAD
        let transactions: Vec<RawTransaction> = vec![Default::default()];
=======
        let transactions: Vec<SignedTransaction> = vec![Default::default()];
>>>>>>> b920444 (Initial commit for demo done)
        let merkle_tree = MerkleTree::new(&transactions);
        let merkle_root = merkle_tree.root();
        
        Block {
            header: Header {
                parent: *parent,
                nonce,
                difficulty: Block::default_difficulty(),
                timestamp,
                merkle_root,
<<<<<<< HEAD
=======
                miner: "random".to_string(), // Set miner for random block
>>>>>>> b920444 (Initial commit for demo done)
            },
            content: Content { transactions },
        }
    }
}
