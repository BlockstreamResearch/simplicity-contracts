use simplicityhl::simplicity::elements::hashes::HashEngine as _;
use simplicityhl::simplicity::hashes::{Hash, sha256};

use super::build_witness::{DEPTH, u256};

#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq)]
pub enum TreeNode {
    Leaf {
        leaf_hash: u256,
    },
    Branch {
        hash: u256,
        left: Box<TreeNode>,
        right: Box<TreeNode>,
    },
}

impl TreeNode {
    pub fn get_hash(&self) -> u256 {
        match self {
            TreeNode::Leaf { leaf_hash } => *leaf_hash,
            TreeNode::Branch { hash, .. } => *hash,
        }
    }
}

pub struct SparseMerkleTree {
    root: Box<TreeNode>,
    precalculate_hashes: [u256; DEPTH],
}

impl SparseMerkleTree {
    #[must_use]
    pub fn new() -> Self {
        let mut precalculate_hashes = [[0u8; 32]; DEPTH];
        let mut eng = sha256::Hash::engine();
        let zero = [0u8; 32];
        eng.input(&zero);
        precalculate_hashes[0] = *sha256::Hash::from_engine(eng).as_byte_array();

        for i in 1..DEPTH {
            let mut eng = sha256::Hash::engine();
            eng.input(&precalculate_hashes[i - 1]);
            eng.input(&precalculate_hashes[i - 1]);
            precalculate_hashes[i] = *sha256::Hash::from_engine(eng).as_byte_array();
        }

        Self {
            root: Box::new(TreeNode::Leaf {
                leaf_hash: precalculate_hashes[0],
            }),
            precalculate_hashes,
        }
    }

    fn calculate_hash(left: &mut TreeNode, right: &mut TreeNode) -> u256 {
        let mut eng = sha256::Hash::engine();
        eng.input(&left.get_hash());
        eng.input(&right.get_hash());
        *sha256::Hash::from_engine(eng).as_byte_array()
    }

    // Return array of hashes
    fn traverse(
        precalculate_hashes: &[u256; DEPTH],
        leaf: &u256,
        path: [bool; DEPTH],
        depth: usize,
        root: &mut Box<TreeNode>,
        hashes: &mut [u256; DEPTH],
    ) {
        if depth == DEPTH {
            let tag = sha256::Hash::hash(b"TapData");
            let mut eng = sha256::Hash::engine();
            eng.input(tag.as_byte_array());
            eng.input(tag.as_byte_array());
            eng.input(leaf);

            **root = TreeNode::Leaf {
                leaf_hash: *sha256::Hash::from_engine(eng).as_byte_array(),
            };
            return;
        }

        if matches!(**root, TreeNode::Leaf { .. }) {
            let left_branch = precalculate_hashes[DEPTH - depth - 1];
            let right_branch = precalculate_hashes[DEPTH - depth - 1];

            let new_branch = Box::new(TreeNode::Branch {
                hash: [0u8; 32],
                left: Box::new(TreeNode::Leaf {
                    leaf_hash: left_branch,
                }),
                right: Box::new(TreeNode::Leaf {
                    leaf_hash: right_branch,
                }),
            });

            *root = new_branch;
        }

        if let TreeNode::Branch {
            ref mut left,
            ref mut right,
            ref mut hash,
        } = **root
        {
            let is_go_right = path[depth];

            if is_go_right {
                hashes[depth] = left.get_hash();
                Self::traverse(precalculate_hashes, leaf, path, depth + 1, left, hashes);
            } else {
                hashes[depth] = right.get_hash();
                Self::traverse(precalculate_hashes, leaf, path, depth + 1, right, hashes);
            }

            *hash = Self::calculate_hash(left, right);
        } else {
            unreachable!("Should be a branch at this point");
        }
    }

    // For insert change 0 to leaf.
    // For delete vice versa.
    // And for udpate change old value to new.
    // Then, recalculate hashes
    pub fn update(&mut self, leaf: &u256, path: [bool; DEPTH]) -> [u256; DEPTH] {
        let mut hashes = self.precalculate_hashes;
        Self::traverse(
            &self.precalculate_hashes,
            leaf,
            path,
            0,
            &mut self.root,
            &mut hashes,
        );
        hashes
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}
