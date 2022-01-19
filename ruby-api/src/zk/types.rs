use fawkes_crypto::{backend::bellman_groth16::engines::Bn256, engines::bn256::JubJubBN256};

pub type Fr = fawkes_crypto::engines::bn256::Fr;
pub type E = Bn256;
pub type JjParams = JubJubBN256;
