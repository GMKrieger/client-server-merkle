// Merkle Tree Library
//
// A SHA-256 based Merkle tree implementation for verifiable data integrity in distributed systems.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self};
use thiserror::Error;

/// Type alias for backward compatibility
pub type Hash = Vec<u8>;

/// Errors that can occur during Merkle tree operations
#[derive(Error, Debug)]
pub enum MerkleError {
    #[error("Cannot build Merkle tree from empty leaves")]
    EmptyLeaves,

    #[error("Index {index} out of bounds (tree has {leaf_count} leaves)")]
    IndexOutOfBounds { index: usize, leaf_count: usize },

    #[error("Leaf hash not found in tree")]
    LeafNotFound,

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Proof verification failed")]
    VerificationFailed,
}

/// Result type for Merkle tree operations
pub type Result<T> = std::result::Result<T, MerkleError>;

/// A single item in a Merkle proof.
///
/// Contains the sibling hash and its position (left or right) needed to
/// reconstruct the path from a leaf to the root.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProofNode {
    /// Sibling hash bytes
    pub hash: Hash,
    /// True if this sibling is on the left of the current node
    pub is_left: bool,
}

/// A Merkle tree for verifiable data integrity.
///
/// The tree is built from leaf hashes and stores all levels from leaves to root.
/// Nodes at each level are paired and hashed together. When a level has an odd
/// number of nodes, the last node is duplicated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// levels[0] = leaves, levels[1] = parent level, ... last level contains root only
    levels: Vec<Vec<Hash>>,
}

impl MerkleTree {
    /// Build from raw file bytes (hash each file with SHA-256).
    /// # Arguments
    ///
    /// * `files` - Vector of bytes
    ///
    /// # Errors
    ///
    /// Returns `MerkleError::EmptyLeaves` if the leaves vector is empty.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle::MerkleTree;
    ///
    /// let files = vec![b"file1".to_vec(), b"file2".to_vec()];
    /// let tree = MerkleTree::from_bytes_vec(&files)?;
    /// # Ok::<(), merkle::MerkleError>(())
    /// ```
    pub fn from_bytes_vec(files: &[Vec<u8>]) -> Result<Self> {
        let leaves: Vec<Hash> = files.iter().map(|b| sha256(b)).collect();
        MerkleTree::from_leaves(leaves)
    }

    /// Build a Merkle tree from leaf hashes.
    fn from_leaves(leaves: Vec<Hash>) -> Result<Self> {
        if leaves.is_empty() {
            return Err(MerkleError::EmptyLeaves);
        }

        let mut levels: Vec<Vec<Hash>> = Vec::new();
        levels.push(leaves);

        while levels.last().ok_or(MerkleError::EmptyLeaves)?.len() > 1 {
            let current = levels.last().ok_or(MerkleError::EmptyLeaves)?;
            let mut next_level: Vec<Hash> = Vec::with_capacity((current.len() + 1) / 2);

            let mut i = 0;
            while i < current.len() {
                let left = &current[i];
                let right = if i + 1 < current.len() {
                    &current[i + 1]
                } else {
                    left // duplicate last if odd
                };
                let parent = hash_concat(left, right);
                next_level.push(parent);
                i += 2;
            }
            levels.push(next_level);
        }

        Ok(MerkleTree { levels })
    }

    /// Generate Merkle proof for a leaf at `index` (0-based).
    ///
    /// Returns a vector of ProofNode ordered from leaf-level upward.
    ///
    /// # Errors
    ///
    /// Returns `MerkleError::IndexOutOfBounds` if index >= leaf_count.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle::{MerkleTree, sha256};
    ///
    /// let files = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
    /// let tree = MerkleTree::from_bytes_vec(&files)?;
    /// let proof = tree.generate_proof(1)?;
    /// # Ok::<(), merkle::MerkleError>(())
    /// ```
    pub fn generate_proof(&self, mut index: usize) -> Result<Vec<ProofNode>> {
        if index >= self.leaf_count() {
            return Err(MerkleError::IndexOutOfBounds {
                index,
                leaf_count: self.leaf_count(),
            });
        }

        let mut proof: Vec<ProofNode> = Vec::with_capacity(self.levels.len() - 1);

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

        Ok(proof)
    }

    /// Verify a proof against this tree's root.
    ///
    /// # Examples
    ///
    /// ```
    /// use merkle::{MerkleTree, sha256};
    ///
    /// let files = vec![b"a".to_vec(), b"b".to_vec()];
    /// let tree = MerkleTree::from_bytes_vec(&files)?;
    /// let proof = tree.generate_proof(0)?;
    /// let leaf_hash = sha256(b"a");
    /// assert!(tree.verify(&leaf_hash, &proof)?);
    /// # Ok::<(), merkle::MerkleError>(())
    /// ```
    pub fn verify(&self, leaf_hash: &[u8], proof: &[ProofNode]) -> Result<bool> {
        Ok(Self::verify_proof(leaf_hash, proof, self.root_hash_ref()?))
    }

    /// Verify a proof: starting from leaf_hash, apply proof nodes to derive root and compare.
    ///
    /// This is a static method for verifying proofs without needing the full tree.
    pub fn verify_proof(leaf_hash: &[u8], proof: &[ProofNode], expected_root: &[u8]) -> bool {
        let computed_root = Self::compute_root_from_proof(leaf_hash, proof);
        computed_root == expected_root
    }

    /// Compute the root hash by applying a proof to a leaf hash.
    fn compute_root_from_proof(leaf_hash: &[u8], proof: &[ProofNode]) -> Hash {
        let mut current: Hash = leaf_hash.to_vec();

        for node in proof {
            if node.is_left {
                // sibling is left: hash(sibling || current)
                current = hash_concat(&node.hash, &current);
            } else {
                // sibling is right: hash(current || sibling)
                current = hash_concat(&current, &node.hash);
            }
        }

        current
    }

    /// Return a reference to the root hash.
    pub fn root_hash_ref(&self) -> Result<&[u8]> {
        self.levels
            .last()
            .and_then(|level| level.first())
            .map(|hash| hash.as_slice())
            .ok_or(MerkleError::EmptyLeaves)
    }

    /// Number of leaves in the tree.
    pub fn leaf_count(&self) -> usize {
        self.levels[0].len()
    }

    /// Height of the tree (number of levels).
    pub fn tree_height(&self) -> usize {
        self.levels.len()
    }

    /// Get all leaf hashes.
    pub fn get_leaves(&self) -> &[Hash] {
        &self.levels[0]
    }

    /// Serialize the tree to JSON.
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }

    /// Deserialize a tree from JSON.
    pub fn from_json(json: &str) -> Result<Self> {
        Ok(serde_json::from_str(json)?)
    }
}

/// Compute SHA-256 digest of data.
///
/// # Examples
///
/// ```
/// use merkle::sha256;
///
/// let hash = sha256(b"hello world");
/// assert_eq!(hash.len(), 32);
/// ```
pub fn sha256(bytes: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().to_vec()
}

/// Hash concatenation helper for parent node computation.
fn hash_concat(left: &[u8], right: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_leaf() {
        let data = vec![b"single".to_vec()];
        let tree = MerkleTree::from_bytes_vec(&data).unwrap();
        assert_eq!(tree.leaf_count(), 1);
        assert_eq!(tree.tree_height(), 1);

        let proof = tree.generate_proof(0).unwrap();
        assert!(proof.is_empty()); // single leaf has no siblings

        let leaf_hash = sha256(b"single");
        assert!(tree.verify(&leaf_hash, &proof).unwrap());
    }

    #[test]
    fn test_two_leaves() {
        let data = vec![b"left".to_vec(), b"right".to_vec()];
        let tree = MerkleTree::from_bytes_vec(&data).unwrap();
        assert_eq!(tree.leaf_count(), 2);
        assert_eq!(tree.tree_height(), 2);

        // Test both proofs
        let proof0 = tree.generate_proof(0).unwrap();
        assert_eq!(proof0.len(), 1);
        assert!(tree.verify(&sha256(b"left"), &proof0).unwrap());

        let proof1 = tree.generate_proof(1).unwrap();
        assert_eq!(proof1.len(), 1);
        assert!(tree.verify(&sha256(b"right"), &proof1).unwrap());
    }

    #[test]
    fn test_three_leaves_odd_duplication() {
        // Tests duplication of last node when odd
        let data = vec![b"alpha".to_vec(), b"bravo".to_vec(), b"charlie".to_vec()];
        let tree = MerkleTree::from_bytes_vec(&data).unwrap();
        assert_eq!(tree.leaf_count(), 3);

        for i in 0..3 {
            let leaf_hash = sha256(&data[i]);
            let proof = tree.generate_proof(i).unwrap();
            assert!(
                tree.verify(&leaf_hash, &proof).unwrap(),
                "proof for index {} should verify",
                i
            );
        }
    }

    #[test]
    fn test_power_of_two_leaves() {
        // 4 leaves = perfect binary tree
        let data = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let tree = MerkleTree::from_bytes_vec(&data).unwrap();
        assert_eq!(tree.leaf_count(), 4);
        assert_eq!(tree.tree_height(), 3); // leaves, intermediate, root

        // All proofs should have same length
        for i in 0..4 {
            let proof = tree.generate_proof(i).unwrap();
            assert_eq!(proof.len(), 2); // log2(4) = 2
        }
    }

    #[test]
    fn test_verify_fails_if_tampered() {
        let files = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec(), b"d".to_vec()];
        let tree = MerkleTree::from_bytes_vec(&files).unwrap();
        let leaf_hash = sha256(&files[2]);
        let mut proof = tree.generate_proof(2).unwrap();

        // Tamper with proof
        proof[0].hash[0] ^= 0xff;
        assert!(!tree.verify(&leaf_hash, &proof).unwrap());
    }

    #[test]
    fn test_verify_fails_wrong_leaf() {
        let files = vec![b"a".to_vec(), b"b".to_vec()];
        let tree = MerkleTree::from_bytes_vec(&files).unwrap();
        let proof = tree.generate_proof(0).unwrap();

        // Try to verify with wrong leaf
        let wrong_leaf = sha256(b"wrong");
        assert!(!tree.verify(&wrong_leaf, &proof).unwrap());
    }

    #[test]
    fn test_empty_leaves_error() {
        let empty: Vec<Vec<u8>> = vec![];
        let result = MerkleTree::from_bytes_vec(&empty);
        assert!(matches!(result, Err(MerkleError::EmptyLeaves)));
    }

    #[test]
    fn test_index_out_of_bounds() {
        let data = vec![b"a".to_vec(), b"b".to_vec()];
        let tree = MerkleTree::from_bytes_vec(&data).unwrap();

        let result = tree.generate_proof(2);
        assert!(matches!(result, Err(MerkleError::IndexOutOfBounds { .. })));
    }

    #[test]
    fn test_get_leaves() {
        let data = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let tree = MerkleTree::from_bytes_vec(&data).unwrap();

        let leaves = tree.get_leaves();
        assert_eq!(leaves.len(), 3);
        assert_eq!(leaves[0], sha256(b"a"));
        assert_eq!(leaves[1], sha256(b"b"));
        assert_eq!(leaves[2], sha256(b"c"));
    }

    #[test]
    fn test_serialization() {
        let data = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let tree = MerkleTree::from_bytes_vec(&data).unwrap();

        // Serialize
        let json = tree.to_json().unwrap();
        assert!(json.contains("levels"));

        // Deserialize
        let tree2 = MerkleTree::from_json(&json).unwrap();
        assert_eq!(
            tree.root_hash_ref().unwrap(),
            tree2.root_hash_ref().unwrap()
        );
        assert_eq!(tree.leaf_count(), tree2.leaf_count());
    }

    #[test]
    fn test_large_tree() {
        // Test with 100 leaves
        let data: Vec<Vec<u8>> = (0..100)
            .map(|i| format!("data{}", i).into_bytes())
            .collect();

        let tree = MerkleTree::from_bytes_vec(&data).unwrap();
        assert_eq!(tree.leaf_count(), 100);

        // Verify all proofs
        for i in 0..100 {
            let leaf_hash = sha256(&data[i]);
            let proof = tree.generate_proof(i).unwrap();
            assert!(tree.verify(&leaf_hash, &proof).unwrap());

            // Proof length should be log2(100) ≈ 7
            assert!(proof.len() >= 6 && proof.len() <= 8);
        }
    }
}
