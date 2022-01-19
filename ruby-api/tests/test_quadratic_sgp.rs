


use num_bigint::{BigInt, ToBigInt};

use ruby::math::matrix::BigIntMatrix;
use ruby::quadratic_sgp::{Sgp, SgpPlain};
use ruby::traits::FunctionalEncryption;
use ruby::utils::quadratic_result;
use ruby::utils::rand_utils::{RandUtilsRng};



pub type Bn256Fr = fawkes_crypto::engines::bn256::Fr;
#[test]
fn test_sgp_2() {
    use std::time::Instant;

    let _rng = RandUtilsRng::new();
    const L: usize = 2;
    let bound: i32 = 100;
    let _low = (-bound).to_bigint().unwrap();
    let _high = bound.to_bigint().unwrap();

    let sgp = Sgp::<L>::new();

    const N: usize = 1;

    let x: [BigInt; L] = [0.to_bigint().unwrap(), -(25.to_bigint().unwrap())];
    let y: [BigInt; L] = [-(79.to_bigint().unwrap()), -(72.to_bigint().unwrap())];
    let f = BigIntMatrix::new_ints(&[-81, 23, -48, 42], 2, 2);
    let plain_result = quadratic_result(&x, &y, &f);
    println!("Groud truth: {:?}", plain_result);

    let plain = SgpPlain { x, y };
    let cipher = sgp.encrypt(&plain);
    println!("g1_mul_gamma: {:?}\n", cipher.getg1_mul_gammabytes());
    println!("a: {:?}\n", cipher.getabytes());
    println!("b: {:?}\n", cipher.getbbytes());

    let dk = sgp.derive_fe_key(&f);

    let now = Instant::now();
    let result = sgp.decrypt(&cipher, &dk, &BigInt::from(bound));
    println!("result: {:?}\n", result);
    let elapsed = now.elapsed();
    println!("[Quadratic Decrypt]: {:.2?}", elapsed);

    assert!(result.is_some());
    assert_eq!(result.unwrap(), plain_result);
}
