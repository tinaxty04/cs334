<<<<<<< HEAD
use ring::signature::{Ed25519KeyPair, KeyPair};
=======
use ring::signature::{Ed25519KeyPair, Signature, KeyPair};
>>>>>>> b920444 (Initial commit for demo done)
use serde::{Serialize, Deserialize};
use bincode;
use rand::random;
use crate::crypto::hash::{H256, Hashable};
use crate::crypto::address::H160;
<<<<<<< HEAD
use crate::mempool::Mempool;
use std::collections::HashSet;

// Account-based transaction 
=======

>>>>>>> b920444 (Initial commit for demo done)
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct RawTransaction {
    pub from_addr: H160,
    pub to_addr: H160,
    pub value: u64,
    pub nonce: u32,
}

<<<<<<< HEAD
// A Signed transaction is a Raw transaction with a signature
=======
>>>>>>> b920444 (Initial commit for demo done)
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SignedTransaction {
    pub raw: RawTransaction,
    pub pub_key: Vec<u8>,
    pub signature: Vec<u8>,
}

<<<<<<< HEAD

impl SignedTransaction {
    /// Create a new transaction from a raw transaction and a key pair
    pub fn from_raw(raw: RawTransaction, key: &Ed25519KeyPair) -> SignedTransaction {
        let pub_key = key.public_key().as_ref().to_vec();
        let signature = sign(&raw, key);
        SignedTransaction { raw, pub_key, signature }
    }

    /// Verify the signature of this transaction
=======
impl SignedTransaction {
    pub fn from_raw(raw: RawTransaction, key: &Ed25519KeyPair) -> SignedTransaction {
        let pub_key = key.public_key().as_ref().to_vec();
        let signature = sign(&raw, key).as_ref().to_vec();
        SignedTransaction { raw, pub_key, signature }
    }
>>>>>>> b920444 (Initial commit for demo done)
    pub fn verify_signature(&self) -> bool {
        let serialized_raw = bincode::serialize(&self.raw).unwrap();
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519, &self.pub_key[..]);
        public_key.verify(&serialized_raw, self.signature.as_ref()).is_ok()
    }
}

/// Create digital signature of a transaction
<<<<<<< HEAD
pub fn sign(t: &RawTransaction, key: &Ed25519KeyPair) -> Vec<u8> {
    let serialized = bincode::serialize(t).unwrap();
    key.sign(&serialized).as_ref().to_vec()
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(t: &RawTransaction, pub_key_bytes: &[u8], signature: &[u8]) -> bool {
    let serialized = bincode::serialize(t).unwrap();
    let public_key = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, pub_key_bytes);
    public_key.verify(&serialized, signature).is_ok()
}

=======
pub fn sign(t: &RawTransaction, key: &Ed25519KeyPair) -> Signature {
    let serialized = bincode::serialize(t).unwrap();
    key.sign(&serialized)
}

/// Verify digital signature of a transaction, using public key instead of secret key
pub fn verify(t: &RawTransaction, public_key: &<Ed25519KeyPair as KeyPair>::PublicKey, signature: &Signature) -> bool {
    let serialized = bincode::serialize(t).unwrap();
    let unparsed = ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, public_key.as_ref());
    unparsed.verify(&serialized, signature.as_ref()).is_ok()
}

/* Please add the following code snippet into `src/transaction.rs`: */
>>>>>>> b920444 (Initial commit for demo done)
impl Hashable for RawTransaction {
    fn hash(&self) -> H256 {
        let bytes = bincode::serialize(&self).unwrap();
        ring::digest::digest(&ring::digest::SHA256, &bytes).into()
    }
}

impl Hashable for SignedTransaction {
    fn hash(&self) -> H256 {
<<<<<<< HEAD
        let bytes = bincode::serialize(&self).unwrap();
=======
        let bytes = bincode::serialize(self).unwrap();
>>>>>>> b920444 (Initial commit for demo done)
        ring::digest::digest(&ring::digest::SHA256, &bytes).into()
    }
}

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::crypto::key_pair;
<<<<<<< HEAD
    use crate::mempool::Mempool;
    use std::collections::HashSet;

    /*
    // Old UTXO-based test code (commented out)
=======

>>>>>>> b920444 (Initial commit for demo done)
    pub fn generate_random_transaction() -> RawTransaction {
        // Create a simple transaction with just one input and one output
        let input = Input {
            previous_output: random(), // Random u32
        };

        let output = Output {
            value: random(), // Random u32
        };

        RawTransaction {
            inputs: vec![input],
            outputs: vec![output],
        }
    }

    #[test]
    fn sign_verify() {
        let t = generate_random_transaction();
        let key = key_pair::random();
        let signature = sign(&t, &key);
        assert!(verify(&t, &(key.public_key()), &signature));
    }
<<<<<<< HEAD
    */

    // New account-based tests
    #[test]
    fn sign_and_verify_account_transaction() {
        let key = key_pair::random();
        let from_addr = crate::crypto::address::H160::from_pubkey(key.public_key().as_ref());
        let to_key = key_pair::random();
        let to_addr = crate::crypto::address::H160::from_pubkey(to_key.public_key().as_ref());
        let raw = RawTransaction {
            from_addr,
            to_addr,
            value: 100,
            nonce: 1,
        };
        let signed = SignedTransaction::from_raw(raw.clone(), &key);
        assert!(signed.verify_signature());
        // Tamper with transaction
        let mut tampered = signed.clone();
        tampered.raw.value = 200;
        assert!(!tampered.verify_signature());
        // Tamper with signature
        let mut tampered2 = signed.clone();
        tampered2.signature[0] ^= 0xFF;
        assert!(!tampered2.verify_signature());
    }

    #[test]
    fn transaction_hash_consistency() {
        let key = key_pair::random();
        let from_addr = crate::crypto::address::H160::from_pubkey(key.public_key().as_ref());
        let to_key = key_pair::random();
        let to_addr = crate::crypto::address::H160::from_pubkey(to_key.public_key().as_ref());
        let raw = RawTransaction {
            from_addr,
            to_addr,
            value: 42,
            nonce: 7,
        };
        let hash1 = raw.hash();
        let hash2 = raw.hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn signed_transaction_hash_uniqueness() {
        let key1 = key_pair::random();
        let key2 = key_pair::random();
        let addr1 = crate::crypto::address::H160::from_pubkey(key1.public_key().as_ref());
        let addr2 = crate::crypto::address::H160::from_pubkey(key2.public_key().as_ref());
        let raw1 = RawTransaction { from_addr: addr1, to_addr: addr2, value: 1, nonce: 1 };
        let raw2 = RawTransaction { from_addr: addr2, to_addr: addr1, value: 1, nonce: 1 };
        let signed1 = SignedTransaction::from_raw(raw1, &key1);
        let signed2 = SignedTransaction::from_raw(raw2, &key2);
        assert_ne!(signed1.hash(), signed2.hash());
    }

    #[test]
    fn mempool_insertion_and_duplicate() {
        let key = key_pair::random();
        let from_addr = crate::crypto::address::H160::from_pubkey(key.public_key().as_ref());
        let to_key = key_pair::random();
        let to_addr = crate::crypto::address::H160::from_pubkey(to_key.public_key().as_ref());
        let raw = RawTransaction { from_addr, to_addr, value: 10, nonce: 1 };
        let signed = SignedTransaction::from_raw(raw, &key);
        let mut mempool = Mempool::new();
        mempool.insert(signed.clone());
        // Insert duplicate
        mempool.insert(signed.clone());
        // Only one should exist
        let mut count = 0;
        while let Some(_) = mempool.pop() { count += 1; }
        assert_eq!(count, 1);
    }

    #[test]
    fn mempool_pop_behavior() {
        let key = key_pair::random();
        let from_addr = crate::crypto::address::H160::from_pubkey(key.public_key().as_ref());
        let to_key = key_pair::random();
        let to_addr = crate::crypto::address::H160::from_pubkey(to_key.public_key().as_ref());
        let mut mempool = Mempool::new();
        for i in 0..5 {
            let raw = RawTransaction { from_addr, to_addr, value: i, nonce: i as u32 };
            let signed = SignedTransaction::from_raw(raw, &key);
            mempool.insert(signed);
        }
        let mut seen = HashSet::new();
        while let Some(tx) = mempool.pop() {
            assert!(seen.insert(tx.hash()));
        }
        assert_eq!(seen.len(), 5);
    }

    #[test]
    fn account_address_uniqueness() {
        let mut addrs = HashSet::new();
        for _ in 0..20 {
            let key = key_pair::random();
            let addr = crate::crypto::address::H160::from_pubkey(key.public_key().as_ref());
            assert!(addrs.insert(addr));
        }
    }
=======
>>>>>>> b920444 (Initial commit for demo done)
}

