use num_bigint::{BigInt, ToBigInt};
use ruby::math::matrix::BigIntMatrix;
use ruby::quadratic_sgp::{Sgp, SgpPlain};
use ruby::traits::FunctionalEncryption;
use ruby::utils::rand_utils::{RandUtilsRng, Sample};

fn main() {
    let mut rng = RandUtilsRng::new();
    const L: usize = 2;
    let bound: i32 = 100;
    let low = (-bound).to_bigint().unwrap();
    let high = bound.to_bigint().unwrap();

    let sgp = Sgp::<L>::new();
    print!(" Sgp is :   {:?}", sgp);
    println!();
    print!(" mpk is :   {:?}", sgp.get_mpk());
    println!();
    let tmp = sgp.get_mpk().getg1s();
    print!(" g1s  is :   {:?}", tmp);
    println!();
    print!(" g1s len is :   {:?}", tmp[0].len());
    println!();

    let tmpbytes = sgp.get_mpk().getg1sbytes();
    print!(" g1s bytes is :   {:?}", tmpbytes);
    println!();
    print!(" g1sbytes len is :   {:?}", tmpbytes.len());
    println!();
    print!(" g1s0 bytes  is :   {:?}", tmpbytes[0]);
    println!();
    print!(" g1s0 bytes len is :   {:?}", tmpbytes[0].len());
    println!();

    let tmp1 = sgp.get_mpk().getg2t();
    print!(" g2t  is :   {:?}", tmp1);
    println!();
    print!(" g2t len is :   {:?}", tmp1.len());
    println!();
    let tmp1vbytes = sgp.get_mpk().getg2tbytes();
    print!(" g2t bytes is :   {:?}", tmp1vbytes);
    println!();
    print!(" g2tbytes len is :   {:?}", tmp1vbytes.len());
    println!();

    let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    let f = BigIntMatrix::new_random(L, L, &low, &high);
    print!(" x is :   {:?}", x);
    println!();
    print!(" y is :   {:?}", y);
    println!();
    print!("f is :   {:?}", f);
    println!();

    let plain = SgpPlain { x, y };
    print!(" plain is :   {:?}", plain);
    println!();
    let cipher = sgp.encrypt(&plain);
    print!(" cipher is :   {:?}", cipher);
    println!();

    let dk = sgp.derive_fe_key(&f);
    print!(" dk is :   {:?}", dk);
    println!();
    print!(" dk key is :   {:?}", dk.key.tostring());
    println!();
    let mut tmp = [0u8; 193];
    dk.key.tobytes(&mut tmp[..], true);
    print!(" dk key bytes  is :   {:?}", tmp);
    println!();
    print!(" dk key[0] len  is :   {:?}", tmp.len());
    println!();

    let result = sgp.decrypt(&cipher, &dk, &BigInt::from(bound));
    print!(" result is :   {:?}", result);
    println!();
}
