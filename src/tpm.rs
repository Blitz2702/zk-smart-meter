use ark_bls12_381::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381::{EdwardsAffine, Fr as JFr};
use ark_ff::{BigInteger, PrimeField};
use ark_std::UniformRand;
use rand::rngs::OsRng;

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

    pub fn sign_measurement(&self, measurement: JFr) -> SchnorrSignature {
        let mut rnd = OsRng;
        let schnorr_gen = EdwardsAffine::generator();

        // Generate the random number
        let random_number = JFr::rand(&mut rnd);

        // Generate Commitment to the random number
        let cmt_rnd_num = (schnorr_gen * random_number).into_affine();

        // Compute the FS-Heuristic Challenge
        let chlng = Self::compute_challenge(&cmt_rnd_num, measurement, &self.public_key);

        // Compute the Response
        let response = random_number + (chlng * self.private_key);

        SchnorrSignature {
            Commitment: cmt_rnd_num,
            Response: response,
        }
    }

    #[allow(non_snake_case)]
    pub fn compute_challenge(
        cmt_rnd_num: &EdwardsAffine,
        measurement: JFr,
        public_key: &EdwardsAffine,
    ) -> JFr {
        /* let mut hasher = Sha256::new();

        let cmt_bytes_X = cmt_rnd_num.x.into_bigint().to_bytes_le();
        let cmt_bytes_Y = cmt_rnd_num.y.into_bigint().to_bytes_le();

        let pk_bytes_X = public_key.x.into_bigint().to_bytes_le();
        let pk_bytes_Y = public_key.y.into_bigint().to_bytes_le();

        let m_bytes = measurement.into_bigint().to_bytes_le();

        hasher.update(&cmt_bytes_X);
        hasher.update(&cmt_bytes_Y);
        hasher.update(&pk_bytes_X);
        hasher.update(&pk_bytes_Y);
        hasher.update(&m_bytes);

        let hash_result = hasher.finalize();

        JFr::from_le_bytes_mod_order(&hash_result) */

        // Mimicking the ZK-Friendly Hash (Poseidon)
        let m_bls = Fr::from_bigint(measurement.into_bigint())
            .expect("Failed to cast measurement to BLS curve");
        let chlng_bls = cmt_rnd_num.x + public_key.x + m_bls;

        let chlng_bls_bytes = chlng_bls.into_bigint().to_bytes_le();

        JFr::from_le_bytes_mod_order(&chlng_bls_bytes)
    }
}
