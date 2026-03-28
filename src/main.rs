use ark_bls12_381::{Bls12_381, Fr};
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use rand::rngs::OsRng;
use std::io::{Write, stdin, stdout};
use std::time::Instant;

use crate::{circuit::ZKSmartMeterContract, native::initiate_native_calculation};

mod circuit;
mod native;
//=========================================================================================================================================================================

fn get_user_input(prompt: &str) -> u64 {
    let mut input = String::new();
    loop {
        print!("{}", prompt);
        stdout().flush().unwrap();
        input.clear();
        stdin().read_line(&mut input).expect("Read Failed!");

        if let Ok(num) = input.trim().parse::<u64>() {
            return num;
        }
        println!("Invalid Input! Please Try Again.");
    }
}

#[allow(non_snake_case)]
fn main() {
    /*--------------------------------
    CLI COSMETICS FOR USER EXPERIENCE
    --------------------------------*/
    println!("==============================================");
    println!("  🔒 ZERO-KNOWLEDGE SMART METER PROTOCOL 🔒");
    println!("==============================================");
    println!("Grid Policy: Maximum monthly usage is 375 kWh.");
    println!("----------------------------------------------");
    //=========================================================================================================================================================================

    /*---------------
    GLOBAL VARIABLES
    ---------------*/
    let mut rnd_main = OsRng;
    let threshold_data = get_user_input("[Grid] Enter the current policy threshold (kWh): ");
    let measurement_data = get_user_input("[Smart Meter] Enter your actual usage (kWh): ");
    //=========================================================================================================================================================================

    /*------------------------------------
    THE PRECOMPUTE OF PEDERSON COMMITMENT
    ------------------------------------*/
    println!("[+] Booting Smart Meter...");
    let (g_native, h_native, f_native, C_Data_native, secret_pk, measurement, secret_r) =
        initiate_native_calculation(measurement_data);
    //=========================================================================================================================================================================

    /*----------------
    THE TRUSTED SETUP
    ----------------*/
    println!("[+] Running Trusted Setup (Generating Proving & Verifying Keys)...");
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
    //=========================================================================================================================================================================

    /*---------------
    THE PROVER'S RUN
    ---------------*/
    // Building the Valid Circuit
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
        T: Some(Fr::from(threshold_data)),
        pk: Some(secret_pk_bls),
        M: Some(measurement_bls),
        r: Some(secret_r_bls),
    };

    // Pre Proof Computation Constraint Sanity Check
    println!("[+] Prover: Performing pre-compute constraint check...");
    let debug_cs = ConstraintSystem::<Fr>::new_ref();
    valid_circuit
        .clone()
        .generate_constraints(debug_cs.clone())
        .expect("Failed to build constraints");

    if !debug_cs.is_satisfied().unwrap() {
        println!("\n[!] FATAL: Proof Generation Aborted!");
        println!("[!] The Smart Meter data violates the Grid Policy.");

        if let Some(bad_constraint) = debug_cs.which_is_unsatisfied().unwrap() {
            println!("\t => Unsatisfied Constraint: {}", bad_constraint);
        }
        return;
    }

    // Proof Computation
    println!("[+] Prover: Compressing matrix into Zero-Knowledge Proof...");

    let prove_start_time = Instant::now();
    let proof = Groth16::<Bls12_381>::prove(&pk_circuit, valid_circuit, &mut rnd_main).unwrap();
    let prove_end_time = prove_start_time.elapsed();

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes).unwrap();

    println!("\tProof generated successfully!");
    println!("\tProve time: {:.2?}", prove_end_time);
    println!(
        "\tProof size: {} bytes",
        proof.serialized_size(Compress::Yes)
    );

    //=========================================================================================================================================================================

    /*-----------------
    THE VERIFIER'S RUN
    -----------------*/
    println!("\n[+] Verifier: Checking the proof against the Grid Policy...");
    let pub_inputs = vec![C_Data_native.x, C_Data_native.y, Fr::from(threshold_data)];

    let verify_res = Groth16::<Bls12_381>::verify(&vk_circuit, &pub_inputs, &proof);
    println!("\tNo data was revealed to the Grid.");

    match verify_res {
        Ok(true) => {
            println!("\t[*] VERIFIED: Measurement is under the threshold.");
            println!("==============================================");
        }
        Ok(false) => {
            println!("\t[!] ERROR: Cryptographic Verification Failed! Proof is invalid or forged.");
            println!("==============================================");
        }
        Err(err) => {
            println!(
                "Structural Failure. Bad Request format or length mismatch. Error: {}",
                err
            );
        }
    }
    //=========================================================================================================================================================================
}
