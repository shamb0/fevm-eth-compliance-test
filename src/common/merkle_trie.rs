use bytes::Bytes;
use hash_db::Hasher;
use plain_hasher::PlainHasher;
use sha3::{Digest, Keccak256};
pub use triehash::sec_trie_root;

use super::{B256, H160, H256};

pub fn trie_root(acc_data: Vec<(H160, Bytes)>) -> B256 {
    B256(sec_trie_root::<KeccakHasher, _, _, _>(acc_data.into_iter()).0)
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct KeccakHasher;

impl Hasher for KeccakHasher {
    type Out = H256;
    type StdHasher = PlainHasher;
    const LENGTH: usize = 32;
    fn hash(x: &[u8]) -> Self::Out {
        let out = Keccak256::digest(x);
        H256::from_slice(out.as_slice())
    }
}
