use miracl_core::bls12381::ecp::ECP;
use num_bigint::{BigInt, ToBigInt};
use ruby::simple_ip::Sip;
use ruby::traits::FunctionalEncryption;
use ruby::utils::rand_utils::{RandUtilsRng, Sample};

fn main() {
    let mut rng = RandUtilsRng::new();
    const L: usize = 2;
    let bound: i32 = 100;
    let low = (-bound).to_bigint().unwrap();
    let high = bound.to_bigint().unwrap();

    let sip = Sip::<L>::new();
    print!(" Sip is :   {:?}", sip);
    println!();

    print!(" mpk is :   {:?}", sip.get_mpk());
    println!();
    let sipv = sip.get_mpk().getv();
    print!(" v is :   {:?}", sipv);
    println!();
    let sipvbytes = sip.get_mpk().getvbytes();
    print!(" v bytes is :   {:?}", sipvbytes);
    println!();
    print!(" v bytes len is :   {:?}", sipvbytes.len());
    println!();
    print!(" v0 bytes len is :   {:?}", sipvbytes[0].len());
    println!();
    print!(" v1 bytes len is :   {:?}", sipvbytes[1].len());
    println!();

    let mut v = [(); L].map(|_| ECP::pnew());
    for i in 0..L {
        let mut tmp = sipv[i].clone();
        print!("{} start{{", i);
        print!("spv {} is {:?}", i, sipv[i].clone());
        println!();
        tmp.remove(0);
        tmp.remove(tmp.len() - 1);
        print!("after remove spv {} is {:?}", i, tmp);
        println!();
        print!("after remove spv length is {:?}", tmp.len());
        println!();
        tmp.remove(96);
        print!("after remove 96 spv {} is {:?}", i, tmp);
        println!();
        print!("after remove 96 spv length is {:?}", tmp.len());
        println!();
        print!("removed spv  bytes {} is {:?}", i, tmp.as_bytes());
        println!();
        v[i] = ECP::frombytes(tmp.as_bytes());
        print!("{}th v is {:?}", i, v[i]);
        print!("{} end}}", i);
        println!();
    }

    print!(" rebuild  from string v  is :   {:?}", v);
    println!();

    let mut v1 = [(); L].map(|_| ECP::pnew());
    for i in 0..L {
        let tmp = sipvbytes[i];
        print!("{} start{{", i);
        print!("spv {} is {:?}", i, sipvbytes[i]);
        println!();
        v1[i] = ECP::frombytes(&tmp[..]);
        print!("{}th v is {:?}", i, v1[i]);
        print!("{} end}}", i);
        println!();
    }

    print!(" rebuild from bytes v  is :   {:?}", v1);
    println!();

    let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    print!(" x is :   {:?}", x);
    println!();
    print!(" y is :   {:?}", y);
    println!();

    let cipher = sip.encrypt(&x);
    print!(" Cipher is :   {:?}", cipher);
    println!();

    let dk = sip.derive_fe_key(&y);
    print!(" dk is :   {:?}", dk);
    println!();

    let result = sip.decrypt(&cipher, &dk, &BigInt::from(bound));
    print!("result is {:?}", result);
}
