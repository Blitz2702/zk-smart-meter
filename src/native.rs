use ark_ec::{AffineRepr, CurveGroup};
use ark_ed_on_bls12_381::{EdwardsAffine, Fr};
use ark_ff::UniformRand;
use rand::rngs::OsRng;

#[allow(non_snake_case)]
pub fn initiate_native_calculation() -> (
    EdwardsAffine,
    EdwardsAffine,
    EdwardsAffine,
    EdwardsAffine,
    Fr,
    Fr,
    Fr,
) {
    let mut rnd = OsRng;
    let g_native = EdwardsAffine::generator();

    let h_native_scalar = Fr::rand(&mut rnd);
    let h_native = (g_native * h_native_scalar).into_affine();

    let f_native_scalar = Fr::rand(&mut rnd);
    let f_native = (g_native * f_native_scalar).into_affine();

    let secret_pk = Fr::from(3154u64);
    let data = Fr::from(298u64);
    let secret_r = Fr::rand(&mut rnd);

    let C_Data_native =
        ((g_native * secret_pk) + (h_native * data) + (f_native * secret_r)).into_affine();

    (
        g_native,
        h_native,
        f_native,
        C_Data_native,
        secret_pk,
        data,
        secret_r,
    )
}
