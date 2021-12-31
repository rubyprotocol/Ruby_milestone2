use num_bigint::{BigInt, ToBigInt,Sign};
use fawkes_crypto::{
    backend::bellman_groth16::{
        prover,
        verifier,
        engines::{Bn256, Bls12_381},
        setup::setup
    },
    circuit::cs::{CS},
    circuit::num::CNum,
    circuit::bitify::c_into_bits_le_strict,
    circuit::ecc::*,
    core::signal::Signal,
    core::sizedvec::SizedVec,
    engines::bn256::{JubJubBN256},
    engines::bls12_381::{JubJubBLS12_381},
    native::ecc::*,
    rand::{thread_rng, Rng},
    ff_uint::{Num, PrimeFieldParams},
    BorshSerialize,
};
use ruby::utils::{inner_product_result};
use ruby::utils::rand_utils::{RandUtilsRng, Sample};
use ruby::simple_ip::{Sip,SipMpk,SipMsk};
use ruby::traits::FunctionalEncryption;
use miracl_core::bls12381::ecp::ECP;
use ruby::define::{BigNum, G1, CURVE_ORDER, MODULUS};
pub type Bn256Fr = fawkes_crypto::engines::bn256::Fr;
use std::str::FromStr;
use std::iter::FromIterator;
use ruby::utils::{baby_step_giant_step_g1, reduce};
use ruby::zk::types::{Fr, E, JjParams};
#[test]
fn test_sip() {
    use std::time::Instant;

    let mut rng = RandUtilsRng::new(); 
    const L: usize = 2;
    let bound: i32 = 100;
    let low = (-bound).to_bigint().unwrap();
    let high = bound.to_bigint().unwrap();

    let mut sip = Sip::<L>::new();
   
    let mut rng = thread_rng();
    let jubjub_params =JjParams::new();
    let g = EdwardsPoint::<Fr>::rand(&mut rng, &jubjub_params)
        .mul(Num::from(8), &jubjub_params);
    let sk: Num<Fr> = rng.gen();
    let h = g.mul(sk.to_other_reduced(), &jubjub_params);

    // let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high); 
    // let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    let x:[BigInt;L] = [80.to_bigint().unwrap(),19.to_bigint().unwrap()];
    let y:[BigInt;L] = [-52.to_bigint().unwrap(),92.to_bigint().unwrap()];
    
    let plain_result = inner_product_result(&x, &y);
    println!("Groud truth: {:?}", plain_result);

    let now = Instant::now();
    let cipher = sip.encrypt(&x);
    print!("{:?}\n",cipher);
    let c0 = vec![cipher.getc0bytes()];
    let mut c =  cipher.getcbytes();
    print!("c0: {:?}\n",c0);
    print!("c: {:?}\n",c);
    
    let dk = sip.derive_fe_key(&y);
    //print!("{:?}\n",dk);
    let y_bytes = vec![dk.get_y()];
    let dk1 = dk.get_dk();
    print!("y: {:?}\n",y_bytes);
    print!("dk: {:?}\n",dk1);

    let now = Instant::now();
    let result = sip.decrypt(&cipher, &dk, &BigInt::from(bound)); 
    let elapsed = now.elapsed();
    println!("result is  {:?}", result);
    println!("[SIP Decrypt]: {:.2?}", elapsed);

    assert!(result.is_some());
    assert_eq!(result.unwrap(), plain_result);
}

