use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::poseidon::{PoseidonConfig, find_poseidon_ark_and_mds};
use ark_ff::PrimeField;

pub fn get_poseidon_config() -> PoseidonConfig<Fr> {
    let full_rounds: usize = 8;
    let partial_rounds: usize = 31;
    let alpha = 5;
    let rate = 2;

    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
        Fr::MODULUS_BIT_SIZE as u64,
        rate,
        full_rounds as u64,
        partial_rounds as u64,
        0,
    );

    PoseidonConfig::new(full_rounds, partial_rounds, alpha, mds, ark, rate, 1)
}
