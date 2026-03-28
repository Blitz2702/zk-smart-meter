use ark_bls12_381::{Bls12_381, Fr};
use ark_ed_on_bls12_381::EdwardsAffine;
// use ark_ec::AffineRepr;
use ark_ff::PrimeField;
use ark_groth16::Groth16;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisError};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use rand::rngs::OsRng;
use std::error::Error;
use std::fmt::Display;
use std::io::{Write, stdin, stdout};
use std::time::Instant;

use crate::{circuit::ZKSmartMeterContract, native::initiate_native_calculation};

mod circuit;
mod native;
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
    T: Fr,
    pk: Fr,
    M: Fr,
    r: Fr,
) -> ZKSmartMeterContract {
    ZKSmartMeterContract {
        g,
        h,
        f,
        C_data: Some(c_data),
        T: Some(T),
        pk: Some(pk),
        M: Some(M),
        r: Some(r),
    }
}

//=========================================================================================================================================================================

#[allow(non_snake_case)]
fn main() -> Result<(), SmartMeterError> {
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
    let proof = Groth16::<Bls12_381>::prove(&pk_circuit, valid_circuit, &mut rnd_main)
        .map_err(SmartMeterError::ProofGenerationFailed)?;
    let prove_end_time = prove_start_time.elapsed();

    let mut proof_bytes = Vec::new();
    proof
        .serialize_compressed(&mut proof_bytes)
        .map_err(|_| SmartMeterError::InvalidInput("Seriliazation Failure".to_string()))?;

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

    // The Public Input Check
    if !C_Data_native.is_on_curve() || !C_Data_native.is_in_correct_subgroup_assuming_on_curve() {
        println!("\t[!] ERROR: Incorrect commitment point! Commitment is not on the Jubjub curve.");
        return Err(SmartMeterError::InvalidCurvePoint(
            "Commitment Point is EITHER not a valid curve point OR not in correct subgroup"
                .to_string(),
        ));
    }

    let pub_inputs = vec![C_Data_native.x, C_Data_native.y, Fr::from(threshold_data)];

    let verify_res = Groth16::<Bls12_381>::verify(&vk_circuit, &pub_inputs, &proof)
        .map_err(SmartMeterError::VerificationError)?;
    println!("\tNo data was revealed to the Grid.");

    if verify_res {
        println!("\t[*] VERIFIED: Measurement is under the threshold.");
        println!("==============================================");
    } else {
        println!("\t[!] ERROR: Proof Verification Failed! Proof is EITHER invalid OR forged.");
        println!("==============================================");
    }
    Ok(())
    //=========================================================================================================================================================================
}
