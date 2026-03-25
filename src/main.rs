use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_snark::SNARK;
use rand::rngs::OsRng;

use crate::{circuit::ZKSmartMeterContract, native::initiate_native_calculation};

mod circuit;
mod native;
/*
zk-smart-meter/
├── Cargo.toml          # The dependencies
├── README.md           # Explain the math and the use-case here.
├── src/
│   ├── main.rs         # The Trusted Setup, Prover, and Verifier execution.
│   ├── circuit.rs      # Your struct and the ConstraintSynthesizer implementation.
│   └── native.rs       # Cleanly separate your native Jubjub math here.
*/

#[allow(non_snake_case)]
fn main() {
    let mut rnd_main = OsRng;
    /*------------------------------------
    THE PRECOMPUTE OF PEDERSON COMMITMENT
    ------------------------------------*/
    let (g_native, h_native, f_native, C_Data_native, secret_pk, measurement, secret_r) =
        initiate_native_calculation();

    /*----------------
    THE TRUSTED SETUP
    ----------------*/
    let dummy_circuit = ZKSmartMeterContract {
        g: g_native,
        h: h_native,
        f: f_native,
        C_data: None,
        T: None,
        pk: None,
        M: None,
        r: None,
    };

    let (pk_circuit, vk_circuit) =
        Groth16::<Bls12_381>::circuit_specific_setup(dummy_circuit, &mut rnd_main)
            .expect("Circuit Setup Failed!");

    /*---------------
    THE PROVER'S RUN
    ---------------*/
    let threshold = Fr::from(375u64);

    let pk_bytes = secret_pk.into_bigint();
    let secret_pk_bls = Fr::from_bigint(pk_bytes).unwrap();

    let measurement_bytes = measurement.into_bigint();
    let measurement_bls = Fr::from_bigint(measurement_bytes).unwrap();

    let r_bytes = secret_r.into_bigint();
    let secret_r_bls = Fr::from_bigint(r_bytes).unwrap();

    let valid_circuit = ZKSmartMeterContract {
        g: g_native,
        h: h_native,
        f: f_native,
        C_data: Some(C_Data_native),
        T: Some(threshold),
        pk: Some(secret_pk_bls),
        M: Some(measurement_bls),
        r: Some(secret_r_bls),
    };

    let proof = Groth16::<Bls12_381>::prove(&pk_circuit, valid_circuit, &mut rnd_main)
        .expect("Proof Generation Failed!");

    /*-----------------
    THE VERIFIER'S RUN
    -----------------*/
    let pub_inputs = vec![C_Data_native.x, C_Data_native.y, threshold];

    let verify_res = Groth16::<Bls12_381>::verify(&vk_circuit, &pub_inputs, &proof)
        .expect("Proof Verification Failed!");

    if verify_res {
        println!("Measurement is under the threshold.");
    } else {
        println!("Measurement is over the threshold.");
    }
}
