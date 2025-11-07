//! Simple Merkle tree implementation: build tree, generate proofs, verify proofs.
//! - Leaves are raw hashes (Vec<u8>), e.g. SHA-256(file_bytes).
//! - When a level has an odd number of nodes we duplicate the last node to make pairs.
//! - Proof items indicate the sibling hash and whether the sibling is on the left.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read};
use std::path::Path;

pub type Hash = Vec<u8>;

/// A single item in a Merkle proof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofNode {
    /// sibling hash bytes
    pub hash: Hash,
    /// true if this sibling is on the left of the current node
    pub is_left: bool,
}

#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// levels[0] = leaves, levels[1] = parent level, ... last level contains root only
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build a Merkle tree from an iterator of leaf hashes.
    /// Leaves must already be hashes (e.g. SHA-256 of file bytes).
    pub fn from_leaves(leaves: Vec<Hash>) -> Self {
        if leaves.is_empty() {
            panic!("Cannot build Merkle tree from empty leaves");
        }

        // Duplicate last leaf if odd to keep pairs; we'll do this every level during building
        let mut levels: Vec<Vec<Hash>> = Vec::new();
        levels.push(leaves);

        while levels.last().unwrap().len() > 1 {
            let current = levels.last().unwrap();
            let mut next_level: Vec<Hash> = Vec::with_capacity((current.len() + 1) / 2);

            let mut i = 0;
            while i < current.len() {
                let left = &current[i];
                let right = if i + 1 < current.len() {
                    &current[i + 1]
                } else {
                    left
                }; // duplicate last if odd
                let parent = hash_concat(left, right);
                next_level.push(parent);
                i += 2;
            }
            levels.push(next_level);
        }

        MerkleTree { levels }
    }

    /// Build from raw file bytes (hash each file with SHA-256)
    pub fn from_bytes_vec(files: &[Vec<u8>]) -> Self {
        let leaves: Vec<Hash> = files.iter().map(|b| sha256(b)).collect();
        MerkleTree::from_leaves(leaves)
    }

    /// Build from file paths (reads files into memory)
    pub fn from_file_paths(paths: &[impl AsRef<Path>]) -> io::Result<Self> {
        let mut leaves = Vec::with_capacity(paths.len());
        for p in paths {
            let mut f = fs::File::open(p.as_ref())?;
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            leaves.push(sha256(&buf));
        }
        Ok(MerkleTree::from_leaves(leaves))
    }

    /// Return the root hash
    pub fn root_hash(&self) -> Hash {
        self.levels.last().unwrap()[0].clone()
    }

    /// Number of leaves
    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    /// Generate Merkle proof for a leaf at `index` (0-based).
    /// Returns a vector of ProofNode ordered from leaf-level upward (first sibling is the sibling of the leaf).
    pub fn generate_proof(&self, mut index: usize) -> Vec<ProofNode> {
        if index >= self.leaf_count() {
            panic!("Index out of bound in gen_proof");
        }

        let mut proof: Vec<ProofNode> = Vec::new();

        for level in 0..(self.levels.len() - 1) {
            let level_nodes = &self.levels[level];
            let is_right = index % 2 == 1;
            let sibling_index = if is_right { index - 1 } else { index + 1 };

            // if sibling index beyond bounds, sibling is the same node (duplication)
            let sibling_hash = if sibling_index < level_nodes.len() {
                level_nodes[sibling_index].clone()
            } else {
                level_nodes[index].clone()
            };

            proof.push(ProofNode {
                hash: sibling_hash,
                is_left: is_right, // if current is right, the sibling is left
            });

            // move to parent index
            index /= 2;
        }

        proof
    }

    /// Verify a proof: starting from leaf_hash, apply proof nodes to derive root and compare.
    pub fn verify_proof(leaf_hash: &[u8], proof: &[ProofNode], expected_root: &[u8]) -> bool {
        let mut cur: Hash = leaf_hash.to_vec();

        for node in proof {
            if node.is_left {
                // sibling is left: hash(sibling || cur)
                cur = hash_concat(&node.hash, &cur);
            } else {
                // sibling is right: hash(cur || sibling)
                cur = hash_concat(&cur, &node.hash);
            }
        }

        cur == expected_root
    }
}

/// Compute sha256 digest
pub fn sha256(bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

/// Hash concat helper for parent computation
fn hash_concat(left: &[u8], right: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn smoke_tree_and_proof_verify() {
        // small example with 3 leaves (tests duplication of last)
        let data = vec![b"alpha".to_vec(), b"bravo".to_vec(), b"charlie".to_vec()];
        let files: Vec<Vec<u8>> = data;
        let tree = MerkleTree::from_bytes_vec(&files);
        let root = tree.root_hash();
        assert_eq!(tree.leaf_count(), 3);

        // Generate proof for leaf 1 (bravo)
        let leaf_index = 1usize;
        let leaf_hash = sha256(&files[leaf_index]);
        let proof = tree.generate_proof(leaf_index);

        // Debug print
        println!("root: {}", hex::encode(&root));
        for (i, n) in proof.iter().enumerate() {
            println!(
                "proof[{}] side left? {} hash {}",
                i,
                n.is_left,
                hex::encode(&n.hash)
            );
        }

        // Verify
        let ok = MerkleTree::verify_proof(&leaf_hash, &proof, &root);
        assert!(ok, "proof should verify against root");
    }

    #[test]
    fn verify_fails_if_tampered() {
        let files = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let tree = MerkleTree::from_bytes_vec(&files);
        let root = tree.root_hash();
        let leaf_index = 2usize;
        let leaf_hash = sha256(&files[leaf_index]);
        let mut proof = tree.generate_proof(leaf_index);

        // Tamper with proof
        proof[0].hash[0] ^= 0xff;
        assert!(!MerkleTree::verify_proof(&leaf_hash, &proof, &root));
    }
}
