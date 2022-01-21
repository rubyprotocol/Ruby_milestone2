use fawkes_crypto::{
    backend::bellman_groth16::verifier,
    core::sizedvec::SizedVec,
    ff_uint::Num,
    native::ecc::*,
    rand::{thread_rng, Rng},
};

use num_bigint::ToBigInt;
use ruby::math::matrix::BigIntMatrix;

use ruby::zk::qp::ZkQp;

use ruby::zk::sip::ZkSip;
use ruby::zk::types::{Fr, JjParams};
use ruby::zk::ToEncoding;

pub type Bn256Fr = fawkes_crypto::engines::bn256::Fr;
pub type Bn12381Fr = fawkes_crypto::engines::bls12_381::Fr;

#[test]
fn test_zk_quadratic_polynomial_zk() {
    const N: usize = 1;
    let mut rng = thread_rng();
    let jubjub_params = JjParams::new();

    let g1 = EdwardsPoint::<Fr>::rand(&mut rng, &jubjub_params).mul(Num::from(8), &jubjub_params);
    let sk: Num<Fr> = rng.gen();
    let h1 = g1.mul(sk.to_other_reduced(), &jubjub_params);

    let s: SizedVec<Num<Fr>, N> = (0..N).map(|_| rng.gen()).collect();
    let t: SizedVec<Num<Fr>, N> = (0..N).map(|_| rng.gen()).collect();

    let bound: i32 = 64;
    let low = (-bound).to_bigint().unwrap();
    let high = bound.to_bigint().unwrap();
    let bigint_f = BigIntMatrix::new_random(N, N, &low, &high);

    let snark = ZkQp::<N>::generate(&g1, &h1, &s, &t, &bigint_f);

    let res = verifier::verify(&snark.vk, &snark.proof, &snark.inputs);
    assert!(res, "Verifier result should be true");

    println!("Inputs: ");
    println!("{}", snark.inputs.encode());

    println!("Proof: ");
    println!("{}", snark.proof.encode());

    println!("vk: ");
    println!("{}", snark.vk.encode());
}

#[test]
fn test_zk_simple_inner_product_zk() {
    const N: usize = 2;
    let mut rng = thread_rng();
    let jubjub_params = JjParams::new();

    let g = EdwardsPoint::<Fr>::rand(&mut rng, &jubjub_params).mul(Num::from(8), &jubjub_params);

    let sk: Num<Fr> = rng.gen();

    let h = g.mul(sk.to_other_reduced(), &jubjub_params);
    let s: SizedVec<Num<Fr>, N> = (0..N).map(|_| rng.gen()).collect();

    let y: SizedVec<Num<Fr>, N> = (0..N).map(|_| rng.gen()).collect();
    let snark = ZkSip::<N>::generate(&g, &h, &s, &y);

    let res = verifier::verify(&snark.vk, &snark.proof, &snark.inputs);
    assert!(res, "Verifier result should be true");

    println!("Inputs: ");
    println!("{}", snark.inputs.encode());

    println!("Proof: ");
    println!("{}", snark.proof.encode());

    println!("vk: ");
    println!("{}", snark.vk.encode());
}
