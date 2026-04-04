use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::EdwardsAffine;
// use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::{Groth16, Proof};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress};
use ark_snark::SNARK;
use rand::Rng;
use rand::rngs::OsRng;
use std::env;
use std::error::Error;
use std::fmt::Display;
use std::io::{Write, stdin, stdout};
use std::time::Instant;

use crate::{circuit::ZKSmartMeterContract, native::initiate_native_calculation};

mod circuit;
mod native;
mod poseidon_setup;
mod tpm;
//=========================================================================================================================================================================

/*-------------------------
HELPER FUNCTIONS AND ENUMS
-------------------------*/
#[derive(Debug)]
enum SmartMeterError {
    ConstraintUnsatisfied(String),
    ProofGenerationFailed(SynthesisError),
    VerificationError(SynthesisError),
    CircuitSetupFailed(SynthesisError),
    InvalidInput(String),
    InvalidCurvePoint(String),
    DeserializationError(String),
}
impl Display for SmartMeterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SmartMeterError::InvalidInput(msg) => write!(f, "Invalid Input: {}", msg),
            SmartMeterError::CircuitSetupFailed(err) => write!(f, "Circuit Setup Failed: {}", err),
            SmartMeterError::ConstraintUnsatisfied(gate) => {
                write!(f, "Constraint Unsatisfied at gate: {}", gate)
            }
            SmartMeterError::ProofGenerationFailed(err) => {
                write!(f, "Proof Generation Failed: {}", err)
            }
            SmartMeterError::InvalidCurvePoint(msg) => write!(f, "Invalid Curve Point: {}", msg),
            SmartMeterError::VerificationError(err) => write!(f, "Verification Error: {}", err),
            SmartMeterError::DeserializationError(msg) => {
                write!(f, "Proof Deserialization Failed: {}", msg)
            }
        }
    }
}
impl Error for SmartMeterError {}

// User input helper function
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

// Circuit builder helper function
#[allow(non_snake_case)]
fn build_circuit(
    g: EdwardsAffine,
    h: EdwardsAffine,
    f: EdwardsAffine,
    c_data: EdwardsAffine,
    T: u64,
    pk: Fr,
    M: Fr,
    r: Fr,
    tpm_pk: EdwardsAffine,
    tpm_s_cmt: EdwardsAffine,
    tpm_s_resp: Fr,
) -> ZKSmartMeterContract {
    ZKSmartMeterContract {
        g,
        h,
        f,
        C_data: Some(c_data),
        T: Some(Fr::from(T)),
        pk: Some(pk),
        M: Some(M),
        r: Some(r),
        TPM_pk: Some(tpm_pk),
        TPM_sign_cmt: Some(tpm_s_cmt),
        TPM_sign_resp: Some(tpm_s_resp),
    }
}

//=========================================================================================================================================================================

#[allow(non_snake_case)]
fn main() -> Result<(), SmartMeterError> {
    let args: Vec<String> = env::args().collect();
    let mitm_demo_run = args.contains(&String::from("--attack-demo"));
    /*--------------------------------
    CLI COSMETICS FOR USER EXPERIENCE
    --------------------------------*/
    println!("==============================================");
    println!("  🔒 ZERO-KNOWLEDGE SMART METER PROTOCOL 🔒");
    println!("==============================================");
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
    let (
        g_native,
        h_native,
        f_native,
        C_Data_native,
        secret_pk,
        measurement,
        secret_r,
        tpm_module_public_key,
        tpm_measurement_signature,
    ) = initiate_native_calculation(measurement_data);
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
        TPM_pk: None,
        TPM_sign_cmt: None,
        TPM_sign_resp: None,
    };

    let (pk_circuit, vk_circuit) =
        Groth16::<Bls12_381>::circuit_specific_setup(dummy_circuit, &mut rnd_main)
            .map_err(SmartMeterError::CircuitSetupFailed)?;
    //=========================================================================================================================================================================

    /*---------------
    THE PROVER'S RUN
    ---------------*/
    // Building the Valid Circuit
    let pk_bytes = secret_pk.into_bigint();
    let secret_pk_bls = Fr::from_bigint(pk_bytes)
        .ok_or_else(|| SmartMeterError::InvalidInput("Invalid Private Key (pk)".to_string()))?;

    let measurement_bytes = measurement.into_bigint();
    let measurement_bls = Fr::from_bigint(measurement_bytes)
        .ok_or_else(|| SmartMeterError::InvalidInput("Invalid Measurement (M)".to_string()))?;

    let r_bytes = secret_r.into_bigint();
    let secret_r_bls = Fr::from_bigint(r_bytes)
        .ok_or_else(|| SmartMeterError::InvalidInput("Invalid Blinder (r)".to_string()))?;

    let tpm_sign_resp_bytes = tpm_measurement_signature.Response.into_bigint();
    let tpm_dign_resp_bls = Fr::from_bigint(tpm_sign_resp_bytes)
        .ok_or_else(|| SmartMeterError::InvalidInput("Invalid Signature Response".to_string()))?;

    let valid_circuit = build_circuit(
        g_native,
        h_native,
        f_native,
        C_Data_native,
        threshold_data,
        secret_pk_bls,
        measurement_bls,
        secret_r_bls,
        tpm_module_public_key,
        tpm_measurement_signature.Commitment,
        tpm_dign_resp_bls,
    );
    let debug_circuit = build_circuit(
        g_native,
        h_native,
        f_native,
        C_Data_native,
        threshold_data,
        secret_pk_bls,
        measurement_bls,
        secret_r_bls,
        tpm_module_public_key,
        tpm_measurement_signature.Commitment,
        tpm_dign_resp_bls,
    );

    // Pre Proof Computation Constraint Sanity Check
    println!("[+] Prover: Performing pre-compute constraint check...");
    let debug_cs = ConstraintSystem::<Fr>::new_ref();
    debug_circuit
        .generate_constraints(debug_cs.clone())
        .map_err(SmartMeterError::ProofGenerationFailed)?;

    if !debug_cs.is_satisfied().unwrap_or(false) {
        println!("\n[!] FATAL: Proof Generation Aborted!");
        println!("[!] The Smart Meter data violates the Grid Policy.");

        let bad_constraint = debug_cs
            .which_is_unsatisfied()
            .unwrap_or_default()
            .unwrap_or_else(|| "Unknow Error".to_string());
        println!("\t => Unsatisfied Constraint: {}", bad_constraint);

        return Err(SmartMeterError::ConstraintUnsatisfied(bad_constraint));
    }

    // Proof Computation
    println!("[+] Prover: Compressing matrix into Zero-Knowledge Proof...");

    let prove_start_time = Instant::now();
    let generated_proof = Groth16::<Bls12_381>::prove(&pk_circuit, valid_circuit, &mut rnd_main)
        .map_err(SmartMeterError::ProofGenerationFailed)?;
    let prove_end_time = prove_start_time.elapsed();

    let mut proof_bytes = Vec::new();
    generated_proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|_| SmartMeterError::InvalidInput("Seriliazation Failure".to_string()))?;

    println!("\tProof generated successfully!");
    println!("\tProve time: {:.2?}", prove_end_time);
    println!(
        "\tProof size: {} bytes",
        generated_proof.serialized_size(Compress::Yes)
    );

    //=========================================================================================================================================================================

    /*---------------------
    THE NETWORK SIMULATION
    ---------------------*/
    println!(
        "\n [*] Network: Transmitting {} bytes of proof to the grid for verification...",
        proof_bytes.len()
    );
    //=========================================================================================================================================================================

    /*------------------
    THE MITM Simulation
    ------------------*/
    if mitm_demo_run {
        println!("\n---------------MITM--SIMULATION---------------");
        println!("\n[X] Attacker: Intercepting network payload...");

        let mut byte_selector = rand::thread_rng();
        let rand_byte = byte_selector.gen_range(10..45);

        println!(
            "\t[X] Attacker: Flipping byte {}: 0x{:02X} → 0x{:02X}",
            rand_byte,
            proof_bytes[rand_byte],
            proof_bytes[rand_byte] ^ 0xFF
        );

        let mut intercepted_proof_bytes = proof_bytes.clone();
        intercepted_proof_bytes[rand_byte] ^= 0xFF;

        println!("[+] Grid Verifier: Analyzing intercepted payload for cryptographic soundness...");
        let tampered_proof_result =
            Proof::<Bls12_381>::deserialize_compressed(&intercepted_proof_bytes[..]);

        let proof_check_start_tampered = Instant::now();
        match tampered_proof_result {
            Ok(tampered_proof) => {
                let pub_inputs = vec![
                    C_Data_native.x,
                    C_Data_native.y,
                    Fr::from(threshold_data),
                    tpm_module_public_key.x,
                    tpm_module_public_key.y,
                ];

                let is_valid =
                    Groth16::<Bls12_381>::verify(&vk_circuit, &pub_inputs, &tampered_proof)
                        .unwrap_or(false);

                if !is_valid {
                    println!(
                        "[+] Success! Soundness Verified: Tampered proof was mathematically rejected by the pairing check."
                    );
                }
            }
            Err(_) => {
                println!(
                    "[+] Success! Soundness Verified: Tampered Proof failed to deserialize due to Corrupt Geometry"
                );
            }
        }
        let proof_check_end_tampered = proof_check_start_tampered.elapsed();
        println!(
            "    Proof Check Completed in {:.2?}",
            proof_check_end_tampered
        );
        println!("\n----------------------------------------------");
    } else {
        println!("[#] Run with --attack-demo to simulate a MITM tampering attack");
    }
    //=========================================================================================================================================================================

    /*-----------------
    THE VERIFIER'S RUN
    -----------------*/
    println!("\n[+] Verifier: Checking the proof received against the Grid Policy...");

    // Create a trusted TPM Hardware registry and Check the TPM Public Key
    let trusted_tmp_hw_registry = vec![tpm_module_public_key];
    if !trusted_tmp_hw_registry.contains(&tpm_module_public_key) {
        println!("\t[!] ERROR: Untrusted Hardware! TPM Public Key is not registered.");
        return Err(SmartMeterError::InvalidInput(
            "Untrusted TPM Identity".to_string(),
        ));
    }

    let received_proof_bytes = proof_bytes;
    // The Public Input Check
    if !C_Data_native.is_on_curve() || !C_Data_native.is_in_correct_subgroup_assuming_on_curve() {
        println!("\t[!] ERROR: Incorrect commitment point! Commitment is not on the Jubjub curve.");
        return Err(SmartMeterError::InvalidCurvePoint(
            "Commitment Point is EITHER not a valid curve point OR not in correct subgroup"
                .to_string(),
        ));
    }

    let pub_inputs = vec![
        C_Data_native.x,
        C_Data_native.y,
        Fr::from(threshold_data),
        tpm_module_public_key.x,
        tpm_module_public_key.y,
    ];

    let deserialized_proof = Proof::<Bls12_381>::deserialize_compressed(&received_proof_bytes[..])
        .map_err(|_| SmartMeterError::DeserializationError("Proof bytes corrupted".to_string()))?;

    let verify_res = Groth16::<Bls12_381>::verify(&vk_circuit, &pub_inputs, &deserialized_proof)
        .map_err(SmartMeterError::VerificationError)?;

    if verify_res {
        println!("[*] VERIFIED: Measurement is under the threshold.");
        println!("==============================================");
    } else {
        println!("[!] ERROR: Proof Verification Failed! Proof is EITHER invalid OR forged.");
        println!("==============================================");
    }
    Ok(())
    //=========================================================================================================================================================================
}
