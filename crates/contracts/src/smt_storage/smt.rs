use simplicityhl::simplicity::elements::hashes::HashEngine as _;
use simplicityhl::simplicity::hashes::{Hash, sha256};

use crate::smt_storage::get_path_bits;

use super::build_witness::{DEPTH, u256};

/// Represents a node within the Sparse Merkle Tree.
///
/// The tree is structured as a recursive binary tree where:
/// - [`TreeNode::Leaf`] represents the bottom-most layer containing the actual data hash.
/// - [`TreeNode::Branch`] represents an internal node containing the combined hash of its children.
#[derive(Debug, Clone, bincode::Encode, bincode::Decode, PartialEq, Eq)]
enum TreeNode {
    /// A leaf node at the bottom of the tree.
    ///
    /// Contains the `leaf_hash` which is the hash of the stored value (or a default empty value).
    Leaf { leaf_hash: u256 },
    /// An internal branch node.
    ///
    /// Contains pointers to the `left` and `right` child nodes and their combined `hash`.
    /// The `hash` is typically calculated as `Hash(Left_Child_Hash || Right_Child_Hash)`.
    Branch {
        hash: u256,
        left: Box<Self>,
        right: Box<Self>,
    },
}

impl TreeNode {
    pub const fn get_hash(&self) -> u256 {
        match self {
            Self::Leaf { leaf_hash } => *leaf_hash,
            Self::Branch { hash, .. } => *hash,
        }
    }
}

/// An implementation of a Sparse Merkle Tree (SMT) with fixed depth.
///
/// Functionally, this structure acts as a **Key-Value store**:
/// - **Key**: The path from the root to the leaf.
/// - **Value**: The data hash stored at that specific leaf.
///
/// A Sparse Merkle Tree is a perfectly balanced binary tree where most leaves are empty (contain default values).
/// Instead of storing every node of the massive tree (which would be impossible for depths like 256),
/// this implementation stores only the non-empty branches.
///
/// # Optimization: Precalculated Hashes
///
/// To efficiently handle the "sparse" nature of the tree, we utilize a `precalculate_hashes` array.
/// This array stores the default hash values for empty subtrees at each height level.
/// - `precalculate_hashes[0]` is the hash of an empty leaf.
/// - `precalculate_hashes[1]` is the hash of a branch connecting two empty leaves.
/// - ...and so on.
///
/// This allows getting the hash of an empty branch at any level in **O(1)** time without recomputing it.
///
/// # Security & Attack Mitigation
///
/// This implementation explicitly guards against **Second Preimage Attacks** (specifically
/// Merkle Substitution or Length Extension attacks) using the following techniques:
///
/// 1. **Path Binding (Position Binding)**:
///    The `raw_path` (bit representation of the tree path) is mixed into the initial leaf hash via
///    `eng.input(&[get_path_bits(...)])`.
///    * *Why?* This binds the data to a specific location in the tree. It prevents an attacker from
///      taking a valid internal node hash (from a deeper level) and presenting it as a valid leaf
///      at a higher level. Even if the data matches, the path/position will differ, changing the hash.
///
/// 2. **Domain Separation**:
///    The function initializes with `Hash(b"TapData")`.
///    * *Why?* This ensures that hashes generated for this SMT state cannot be confused with other
///      Bitcoin/Elements hashes (like `TapLeaf` or `TapBranch` hashes), preventing cross-context collisions.
///
/// # See Also
///
/// * [What is a Sparse Merkle Tree?](https://medium.com/@kelvinfichter/whats-a-sparse-merkle-tree-acda70aeb837)
/// * [Merkle Tree Concepts](https://en.wikipedia.org/wiki/Merkle_tree)
pub struct SparseMerkleTree {
    /// The root node of the tree, initialized to a leaf containing `precalculate_hashes[0]` by default.
    root: Box<TreeNode>,
    /// Cache of default hashes for empty subtrees at each depth level [0..DEPTH].
    precalculate_hashes: [u256; DEPTH],
}

impl SparseMerkleTree {
    /// Initializes a new SMT with precalculated default hashes.
    ///
    /// Computes hashes for empty subtrees at all depths (0..DEPTH) to optimize
    /// calculation. The tree starts with a root pointing to the default empty leaf (`precalculate_hashes[0]`).
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

    /// Computes parent hash: `SHA256(left_child_hash || right_child_hash)`.
    fn calculate_hash(left: &TreeNode, right: &TreeNode) -> u256 {
        let mut eng = sha256::Hash::engine();
        eng.input(&left.get_hash());
        eng.input(&right.get_hash());
        *sha256::Hash::from_engine(eng).as_byte_array()
    }

    /// Internal recursive DFS helper to insert or update a node.
    ///
    /// Navigates down based on `path`. Expands `Leaf` nodes into `Branch` nodes
    /// when descending. Collects sibling hashes into `hashes` and recalculates
    /// branch hashes on the return path.
    fn traverse(
        defaults: &[u256],
        leaf: &u256,
        path: &[bool],
        ind: usize,
        root: &mut Box<TreeNode>,
        hashes: &mut [u256],
    ) {
        if ind >= DEPTH {
            let tag = sha256::Hash::hash(b"TapData");
            let mut eng = sha256::Hash::engine();
            eng.input(tag.as_byte_array());
            eng.input(tag.as_byte_array());
            eng.input(leaf);
            eng.input(&[get_path_bits(path, true)]);

            **root = TreeNode::Leaf {
                leaf_hash: *sha256::Hash::from_engine(eng).as_byte_array(),
            };
            return;
        }

        let (child_zero, remaining_defaults) = defaults
            .split_last()
            .expect("Defaults length must match path length");

        if matches!(**root, TreeNode::Leaf { .. }) {
            let new_branch = Box::new(TreeNode::Branch {
                hash: [0u8; 32],
                left: Box::new(TreeNode::Leaf {
                    leaf_hash: *child_zero,
                }),
                right: Box::new(TreeNode::Leaf {
                    leaf_hash: *child_zero,
                }),
            });

            *root = new_branch;
        }

        let (current_hash_slot, remaining_hashes) = hashes
            .split_first_mut()
            .expect("Hashes length must match path length");

        if let TreeNode::Branch {
            ref mut left,
            ref mut right,
            ref mut hash,
        } = **root
        {
            if path[ind] {
                *current_hash_slot = left.get_hash();
                Self::traverse(
                    remaining_defaults,
                    leaf,
                    path,
                    ind + 1,
                    right,
                    remaining_hashes,
                );
            } else {
                *current_hash_slot = right.get_hash();
                Self::traverse(
                    remaining_defaults,
                    leaf,
                    path,
                    ind + 1,
                    left,
                    remaining_hashes,
                );
            }

            *hash = Self::calculate_hash(left, right);
        } else {
            unreachable!("Should be a branch at this point");
        }
    }

    /// Inserts or updates a leaf at the specified path.
    ///
    /// Traverses the tree, modifying the target leaf and recalculating the root.
    ///
    /// # Arguments
    ///
    /// * `leaf` - The 32-byte value to be stored at the target position.
    /// * `path` - The navigation path represented as a fixed-size boolean array.
    ///   The order of bits is from **Root to Leaf** (index 0 is the first step from the root).
    ///
    /// # Returns
    /// An array of sibling hashes (Merkle path) collected from the root down to the leaf.
    pub fn update(&mut self, leaf: &u256, path: [bool; DEPTH]) -> [u256; DEPTH] {
        let mut hashes = self.precalculate_hashes;
        Self::traverse(
            &self.precalculate_hashes,
            leaf,
            &path,
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
