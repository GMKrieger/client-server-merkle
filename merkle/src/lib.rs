use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct MerkleNode {
    pub hash: Vec<u8>,
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
}

pub struct MerkleTree {
    pub root: MerkleNode,
}

fn hash_concat(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

impl MerkleTree {
    pub fn from_leaves(mut leaves: Vec<Vec<u8>>) -> Self {
        if leaves.is_empty() {
            panic!("Cannot create a Merkle Tree from no leaves");
        }
        while leaves.len() % 2 != 0 {
            leaves.push(leaves.last().unwrap().clone()); // duplicate last if odd
        }

        let mut nodes: Vec<MerkleNode> = leaves
            .into_iter()
            .map(|h| MerkleNode {
                hash: h,
                left: None,
                right: None,
            })
            .collect();

        while nodes.len() > 1 {
            let mut next_level = Vec::new();
            for i in (0..nodes.len()).step_by(2) {
                let left = Box::new(nodes[i].clone());
                let right = Box::new(nodes[i + 1].clone());
                let parent_hash = hash_concat(&left.hash, &right.hash);
                next_level.push(MerkleNode {
                    hash: parent_hash,
                    left: Some(left),
                    right: Some(right),
                });
            }
            nodes = next_level;
        }

        MerkleTree {
            root: nodes.remove(0),
        }
    }

    pub fn root_hash(&self) -> &[u8] {
        &self.root.hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root() {
        let data = vec![b"file1".to_vec(), b"file2".to_vec(), b"file3".to_vec()];
        let leaves: Vec<_> = data
            .into_iter()
            .map(|bytes| Sha256::digest(&bytes).to_vec())
            .collect();

        let tree = MerkleTree::from_leaves(leaves);
        println!("Root hash: {:?}", hex::encode(tree.root_hash()));
    }
}
