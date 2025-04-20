use serde::{Serialize,Deserialize};
use ring::signature::{Ed25519KeyPair, Signature, KeyPair, VerificationAlgorithm, EdDSAParameters, ED25519};
use bincode;
use rand::random;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Input {
    pub previous_output: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Output {
    pub value: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RawTransaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignedTransaction {
    pub transaction: RawTransaction,
    pub signature: Vec<u8>, // bytes of signature
    pub public_key: Vec<u8>, // public key needed to verify
}

/// Create digital signature of a transaction
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

#[cfg(any(test, test_utilities))]
mod tests {
    use super::*;
    use crate::crypto::key_pair;
    use rand::random;

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
}

