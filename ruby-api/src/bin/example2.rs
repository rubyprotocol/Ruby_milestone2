use num_bigint::{BigInt, ToBigInt};
use ruby::math::matrix::{BigIntMatrix};
use ruby::utils::rand_utils::{RandUtilsRng, Sample};
use ruby::quadratic_sgp::{Sgp, SgpPlain};
use ruby::traits::FunctionalEncryption;

fn main() {

    let mut rng = RandUtilsRng::new(); 
    const L: usize = 2;
    let bound: i32 = 100;
    let low = (-bound).to_bigint().unwrap();
    let high = bound.to_bigint().unwrap();

    let sgp = Sgp::<L>::new();
    print!(" Sgp is :   {:?}",sgp);
    print!("\n");
    print!(" mpk is :   {:?}",sgp.get_mpk());
    print!("\n");
    let tmp = sgp.get_mpk().getg1s().clone();
    print!(" g1s  is :   {:?}",tmp);
    print!("\n");
    print!(" g1s len is :   {:?}",tmp[0].len());
    print!("\n");
    
    let tmpbytes = sgp.get_mpk().getg1sbytes().clone();
    print!(" g1s bytes is :   {:?}",tmpbytes);
    print!("\n");
    print!(" g1sbytes len is :   {:?}",tmpbytes.len());
    print!("\n");
    print!(" g1s0 bytes  is :   {:?}",tmpbytes[0]);
    print!("\n");
    print!(" g1s0 bytes len is :   {:?}",tmpbytes[0].len());
    print!("\n");
    
    let tmp1  =sgp.get_mpk().getg2t().clone();
    print!(" g2t  is :   {:?}",tmp1);
    print!("\n");
    print!(" g2t len is :   {:?}",tmp1.len());
    print!("\n");
    let tmp1vbytes = sgp.get_mpk().getg2tbytes().clone();
    print!(" g2t bytes is :   {:?}",tmp1vbytes);
    print!("\n");
    print!(" g2tbytes len is :   {:?}",tmp1vbytes.len());
    print!("\n");
    


    let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high); 
    let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    let f = BigIntMatrix::new_random(L, L, &low, &high);
    print!(" x is :   {:?}",x);
    print!("\n");
    print!(" y is :   {:?}",y);
    print!("\n");
    print!("f is :   {:?}",f);
    print!("\n");

    let plain = SgpPlain {x, y};
    print!(" plain is :   {:?}",plain);
    print!("\n");
    let cipher = sgp.encrypt(&plain);
    print!(" cipher is :   {:?}",cipher);
    print!("\n");

    let dk = sgp.derive_fe_key(&f);
    print!(" dk is :   {:?}",dk);
    print!("\n");
    print!(" dk key is :   {:?}",dk.key.tostring());
    print!("\n");
    let mut tmp =[0u8;193];
    dk.key.tobytes(&mut tmp[..],true);
    print!(" dk key bytes  is :   {:?}",tmp);
    print!("\n");
    print!(" dk key[0] len  is :   {:?}",tmp.len());
    print!("\n");

    let result = sgp.decrypt(&cipher, &dk, &BigInt::from(bound)); 
    print!(" result is :   {:?}",result);
    print!("\n");

}
