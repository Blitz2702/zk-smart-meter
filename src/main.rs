use std::{
    io::{Write, stdin, stdout},
    panic,
};

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

    println!("[+] Prover: Compressing matrix into Zero-Knowledge Proof...");
    println!(
        "    (Note: If data is invalid, the Arkworks Framework will emit a constraint trace warning and abort.)\n"
    );

    let og_hook = panic::take_hook();
    panic::set_hook(Box::new(|_| {}));

    let proof_result = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        Groth16::<Bls12_381>::prove(&pk_circuit, valid_circuit, &mut rnd_main).unwrap()
    }));
    panic::set_hook(og_hook);

    let proof = match proof_result {
        Ok(p) => {
            println!("\tProof generated successfully!");
            p
        }
        Err(_) => {
            println!("[!] FATAL: Proof Generation Failed!");
            println!(
                "[!] Proof Generation Failed! The matrix detected a constraint violation (Data > Threshold)."
            );
            return;
        }
    };
    //=========================================================================================================================================================================

    /*-----------------
    THE VERIFIER'S RUN
    -----------------*/
    println!("\n[+] Verifier: Checking the proof against the Grid Policy...");
    let pub_inputs = vec![C_Data_native.x, C_Data_native.y, threshold];

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
