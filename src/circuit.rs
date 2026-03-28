use ark_bls12_381::Fr;
use ark_ed_on_bls12_381::{EdwardsAffine, constraints::EdwardsVar};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result, SynthesisError};
use std::cmp::Ordering;

#[allow(non_snake_case)]
#[derive(Clone)]
pub struct ZKSmartMeterContract {
    pub g: EdwardsAffine,              // Generator for pk
    pub h: EdwardsAffine,              // Generator for M
    pub f: EdwardsAffine,              // Generator for r
    pub C_data: Option<EdwardsAffine>, // Public Commitment of Power Used
    pub T: Option<Fr>,                 // Threshold Value
    pub pk: Option<Fr>,                // Private Key
    pub M: Option<Fr>,                 // Measurement of Power Used
    pub r: Option<Fr>,                 // Blinding Factor
}

#[allow(non_snake_case)]
impl ConstraintSynthesizer<Fr> for ZKSmartMeterContract {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<()> {
        // Generate the constants. These will be passed in the dummy circuit
        let g_var = EdwardsVar::new_constant(cs.clone(), self.g)?;
        let h_var = EdwardsVar::new_constant(cs.clone(), self.h)?;
        let f_var = EdwardsVar::new_constant(cs.clone(), self.f)?;

        // Generate Output/Public Variables. These will be passed as "None" in dummy ciruit
        let C_Data = EdwardsVar::new_input(cs.clone(), || {
            self.C_data.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let T_var = FpVar::new_input(cs.clone(), || {
            self.T.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Generate the Witness Variables. These are also passed as "None" in dummy cicruit
        let pk_var = FpVar::new_witness(cs.clone(), || {
            self.pk.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let M_var = FpVar::new_witness(cs.clone(), || {
            self.M.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let r_var = FpVar::new_witness(cs.clone(), || {
            self.r.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Perform Multiplication (Adding Elliptic Curve Point [FpVar] times)
        let g_pk_var = g_var.scalar_mul_le(pk_var.to_bits_le()?.iter())?;
        let h_M_var = h_var.scalar_mul_le(M_var.to_bits_le()?.iter())?;
        let f_r_var = f_var.scalar_mul_le(r_var.to_bits_le()?.iter())?;

        // Perform Addition to get the final output value
        let final_c_data = g_pk_var + h_M_var + f_r_var;

        // Range Proof for M<T
        M_var.enforce_cmp(&T_var, Ordering::Less, false)?;

        // Final Equality Constraint of the R1CS Matrix
        final_c_data.enforce_equal(&C_Data)?;

        Ok(())
    }
}
//=========================================================================================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::initiate_native_calculation;
    use ark_bls12_381::Fr;
    use ark_ff::PrimeField;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_std::UniformRand;
    use rand::rngs::OsRng;

    // Helper Fucntion to Build the Circuit
    fn build_test_circuit(measurement: u64, threshold: u64) -> ZKSmartMeterContract {
        let (g, h, f, c_data, pk, m, r) = initiate_native_calculation(measurement);

        let pk_bls = Fr::from_bigint(pk.into_bigint()).unwrap();
        let m_bls = Fr::from_bigint(m.into_bigint()).unwrap();
        let r_bls = Fr::from_bigint(r.into_bigint()).unwrap();

        ZKSmartMeterContract {
            g,
            h,
            f,
            C_data: Some(c_data),
            T: Some(Fr::from(threshold)),
            pk: Some(pk_bls),
            M: Some(m_bls),
            r: Some(r_bls),
        }
    }

    #[test]
    fn test_honest_meter_pass() {
        let valid_circuit = build_test_circuit(333u64, 444u64);
        let cs = ConstraintSystem::<Fr>::new_ref();
        valid_circuit.generate_constraints(cs.clone()).unwrap();

        assert!(cs.is_satisfied().unwrap(), "[!] Honest meter was rejected");
    }

    #[test]
    fn test_cheating_meter_fail() {
        let invalid_circuit = build_test_circuit(333u64, 123u64);
        let cs = ConstraintSystem::<Fr>::new_ref();
        invalid_circuit.generate_constraints(cs.clone()).unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "[!] Cheating meter was accepted"
        );
    }

    #[test]
    fn test_boundary_condition_fail() {
        let boundary_circuit = build_test_circuit(111u64, 111u64);
        let cs = ConstraintSystem::<Fr>::new_ref();
        boundary_circuit.generate_constraints(cs.clone()).unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "[!] Boundary condition values bypassed the constraints"
        );
    }

    #[test]
    fn test_blinder_forgery_fail() {
        let mut forged_circuit = build_test_circuit(254u64, 366u64);
        let cs = ConstraintSystem::<Fr>::new_ref();

        forged_circuit.r = Some(Fr::rand(&mut OsRng));
        forged_circuit.generate_constraints(cs.clone()).unwrap();

        assert!(
            !cs.is_satisfied().unwrap(),
            "[!] Forged Blinder (r) accepted"
        )
    }

    #[test]
    fn test_fuzzy_values() {
        use rand::Rng;
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let random_t: u64 = rng.gen_range(0..1000);
            let random_m: u64 = rng.gen_range(1..1000);

            let circuit = build_test_circuit(random_m, random_t);
            let cs = ConstraintSystem::<Fr>::new_ref();

            circuit.generate_constraints(cs.clone()).unwrap();

            let is_satisfied = cs.is_satisfied().unwrap();
            let native_truth = random_m < random_t;

            assert_eq!(
                is_satisfied, native_truth,
                "Incorrect value combination accepted. M: {}, T:{}",
                random_m, random_t
            );
        }
    }
}
