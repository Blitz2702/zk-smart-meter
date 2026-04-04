use ark_bls12_381::Fr;
use ark_crypto_primitives::sponge::{CryptographicSponge, poseidon::PoseidonSponge};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381::{EdwardsAffine, Fr as JFr};
use ark_ff::{BigInteger, PrimeField};
use ark_std::UniformRand;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::poseidon_setup::get_poseidon_config;

pub struct TPMChip {
    pub public_key: EdwardsAffine,
    private_key: JFr,
}

#[allow(non_snake_case)]
pub struct SchnorrSignature {
    pub Commitment: EdwardsAffine,
    pub Response: JFr,
}

impl TPMChip {
    pub fn boot_new() -> Self {
        let mut rng = OsRng;
        let private_key = JFr::rand(&mut rng);

        let generator = EdwardsAffine::generator();
        let public_key = (generator * private_key).into_affine();

        TPMChip {
            public_key,
            private_key,
        }
    }

    #[allow(non_snake_case)]
    pub fn sign_measurement(&self, measurement: JFr) -> SchnorrSignature {
        let schnorr_gen = EdwardsAffine::generator();

        let mut hasher = Sha256::new();
        hasher.update(self.private_key.into_bigint().to_bytes_le());
        hasher.update(measurement.into_bigint().to_bytes_le());

        // Generate the random number
        let random_number = JFr::from_le_bytes_mod_order(&hasher.finalize());

        // Generate Commitment to the random number
        let Commitment = (schnorr_gen * random_number).into_affine();

        // Compute the FS-Heuristic Challenge
        let chlng = Self::compute_challenge(&Commitment, measurement, &self.public_key);

        // Compute the Response
        let Response = random_number + (chlng * self.private_key);

        SchnorrSignature {
            Commitment,
            Response,
        }
    }

    #[allow(non_snake_case)]
    pub fn compute_challenge(
        cmt_rnd_num: &EdwardsAffine,
        measurement: JFr,
        public_key: &EdwardsAffine,
    ) -> JFr {
        let m_bls = Fr::from_bigint(measurement.into_bigint())
            .expect("Failed to cast measurement into BLS12_381 Fr");

        // Initialize the Poseidon Sponge
        let config = get_poseidon_config();
        let mut sponge = PoseidonSponge::<Fr>::new(&config);

        // Sponge will absorb the data
        sponge.absorb(&cmt_rnd_num.x);
        sponge.absorb(&cmt_rnd_num.y);
        sponge.absorb(&public_key.x);
        sponge.absorb(&public_key.y);
        sponge.absorb(&m_bls);

        // Get the challenge from the sponge
        let chlng_bls: Fr = sponge.squeeze_field_elements(1)[0];
        let chlng_bytes = chlng_bls.into_bigint().to_bytes_le();

        JFr::from_le_bytes_mod_order(&chlng_bytes)
    }
}
