use fawkes_crypto::{
    ff_uint::{Num},
    native::ecc::*,
    rand::{thread_rng, Rng},
};

use num_bigint::{BigInt, ToBigInt};

use ruby::simple_ip::{Sip};
use ruby::traits::FunctionalEncryption;
use ruby::utils::inner_product_result;
use ruby::utils::rand_utils::{RandUtilsRng};
pub type Bn256Fr = fawkes_crypto::engines::bn256::Fr;

use ruby::zk::types::{Fr, JjParams};


#[test]
fn test_sip() {
    use std::time::Instant;

    let _rng = RandUtilsRng::new();
    const L: usize = 2;
    let bound: i32 = 100;
    let _low = (-bound).to_bigint().unwrap();
    let _high = bound.to_bigint().unwrap();

    let sip = Sip::<L>::new();

    let mut rng = thread_rng();
    let jubjub_params = JjParams::new();
    let g = EdwardsPoint::<Fr>::rand(&mut rng, &jubjub_params).mul(Num::from(8), &jubjub_params);
    let sk: Num<Fr> = rng.gen();
    let _h = g.mul(sk.to_other_reduced(), &jubjub_params);

    // let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    // let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    let x: [BigInt; L] = [80.to_bigint().unwrap(), 19.to_bigint().unwrap()];
    let y: [BigInt; L] = [-(52.to_bigint().unwrap()), 92.to_bigint().unwrap()];

    let plain_result = inner_product_result(&x, &y);
    println!("Groud truth: {:?}", plain_result);

    let _now = Instant::now();
    let cipher = sip.encrypt(&x);
    println!("{:?}", cipher);
    let c0 = vec![cipher.getc0bytes()];
    let c = cipher.getcbytes();
    println!("c0: {:?}", c0);
    println!("c: {:?}", c);

    let dk = sip.derive_fe_key(&y);
    //print!("{:?}\n",dk);
    let y_bytes = vec![dk.get_y()];
    let dk1 = dk.get_dk();
    println!("y: {:?}", y_bytes);
    println!("dk: {:?}", dk1);

    let now = Instant::now();
    let result = sip.decrypt(&cipher, &dk, &BigInt::from(bound));
    let elapsed = now.elapsed();
    println!("result is  {:?}", result);
    println!("[SIP Decrypt]: {:.2?}", elapsed);

    assert!(result.is_some());
    assert_eq!(result.unwrap(), plain_result);
}
