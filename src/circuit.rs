use ark_bls12_381::Fr;
use ark_ed_on_bls12_381::{EdwardsAffine, constraints::EdwardsVar};
use ark_r1cs_std::{fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, Result, SynthesisError};
use std::cmp::Ordering;

#[allow(non_snake_case)]
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
