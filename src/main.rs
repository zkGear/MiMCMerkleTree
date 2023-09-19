use ark_bn254::Fr;
use ark_crypto_primitives::merkle_tree::{Config, MerkleTree};
use ark_crypto_primitives::{crh::TwoToOneCRH, CRH};
use arkworks_mimc::{params::mimc_7_91_bn254::MIMC_7_91_BN254_PARAMS, MiMCFeistelCRH};

type H = MiMCFeistelCRH<Fr, MIMC_7_91_BN254_PARAMS>;

struct MiMCMerkleTreeParams;

impl Config for MiMCMerkleTreeParams {
    type LeafHash = H;
    type TwoToOneHash = H;
}
type MiMCMerkleTree = MerkleTree<MiMCMerkleTreeParams>;

fn main() {
    let mut rng = ark_std::test_rng();
    let mut leaves = vec![1u8, 2, 8, 16, 3, 4, 28, 5];
    let leaf_crh_params = <H as CRH>::setup(&mut rng).unwrap();
    let two_to_one_crh_params = <H as TwoToOneCRH>::setup(&mut rng).unwrap();
    let mut tree = MiMCMerkleTree::new(
        &leaf_crh_params.clone(),
        &two_to_one_crh_params.clone(),
        &leaves,
    )
    .unwrap();
    let mut root = tree.root();
    // test merkle tree functionality without update
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.generate_proof(i).unwrap();
        assert!(proof
            .verify(&leaf_crh_params, &two_to_one_crh_params, &root, &leaf)
            .unwrap());
    }

    let update_query = vec![(0usize, 1u8)];
    // test merkle tree update functionality
    for (i, v) in update_query {
        tree.update(i, &v).unwrap();
        leaves[i] = v.clone();
    }
    // update the root
    root = tree.root();
    // verify again
    for (i, leaf) in leaves.iter().enumerate() {
        let proof = tree.generate_proof(i).unwrap();
        assert!(proof
            .verify(&leaf_crh_params, &two_to_one_crh_params, &root, &leaf)
            .unwrap());
    }
}
