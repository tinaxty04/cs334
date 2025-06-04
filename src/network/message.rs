use serde::{Serialize, Deserialize};
use crate::crypto::hash::H256;
use crate::block::Block;
use crate::transaction::SignedTransaction as Transaction;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Message {
    Ping(String),
    Pong(String),
    NewBlockHashes(Vec<H256>),
    GetBlocks(Vec<H256>),
    Blocks(Vec<Block>),
<<<<<<< HEAD
    // Transaction network messages
=======
>>>>>>> b920444 (Initial commit for demo done)
    NewTransactionHashes(Vec<H256>),
    GetTransactions(Vec<H256>),
    Transactions(Vec<Transaction>),
}
