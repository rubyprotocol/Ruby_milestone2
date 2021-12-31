use num_bigint::{BigInt, ToBigInt};
use ruby::utils::rand_utils::{RandUtilsRng, Sample};
use ruby::simple_ip::Sip;
use ruby::traits::FunctionalEncryption;
use miracl_core::bls12381::ecp::ECP;

fn main() {
    let mut rng = RandUtilsRng::new(); 
    const L: usize = 2;
    let bound: i32 = 100;
    let low = (-bound).to_bigint().unwrap();
    let high = bound.to_bigint().unwrap();

    let sip = Sip::<L>::new();
    print!(" Sip is :   {:?}",sip);
    print!("\n");

    print!(" mpk is :   {:?}",sip.get_mpk());
    print!("\n");
    let sipv = sip.get_mpk().getv();
    print!(" v is :   {:?}",sipv);
    print!("\n");
    let sipvbytes = sip.get_mpk().getvbytes();
    print!(" v bytes is :   {:?}",sipvbytes);
    print!("\n");
    print!(" v bytes len is :   {:?}",sipvbytes.len());
    print!("\n");
    print!(" v0 bytes len is :   {:?}",sipvbytes[0].len());
    print!("\n");
    print!(" v1 bytes len is :   {:?}",sipvbytes[1].len());
    print!("\n");

    let mut v = [();L].map(|_| ECP::pnew());
    for i in 0..L{
        let mut tmp =sipv[i].clone();
        print!("{} start{}",i,"{");
        print!("spv {} is {:?}",i,sipv[i].clone());
        print!("\n");
        tmp.remove(0);
        tmp.remove(tmp.len()-1);
        print!("after remove spv {} is {:?}",i,tmp);
        print!("\n");
        print!("after remove spv length is {:?}",tmp.len());
        print!("\n");
        tmp.remove(96);
        print!("after remove 96 spv {} is {:?}",i,tmp);
        print!("\n");
        print!("after remove 96 spv length is {:?}",tmp.len());
        print!("\n");
        print!("removed spv  bytes {} is {:?}",i,tmp.as_bytes());
        print!("\n");
        v[i]=ECP::frombytes(tmp.as_bytes());
        print!("{}th v is {:?}",i,v[i]);
        print!("{} end{}",i,"}");
        print!("\n");
    }
  
    print!(" rebuild  from string v  is :   {:?}",v);
    print!("\n");

    let mut v1 = [();L].map(|_| ECP::pnew());
    for i in 0..L{
        let mut tmp =sipvbytes[i];
        print!("{} start{}",i,"{");
        print!("spv {} is {:?}",i,sipvbytes[i]);
        print!("\n");
        v1[i]=ECP::frombytes(&mut tmp[..]);
        print!("{}th v is {:?}",i,v1[i]);
        print!("{} end{}",i,"}");
        print!("\n");
    }
  
    print!(" rebuild from bytes v  is :   {:?}",v1);
    print!("\n");

    let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high); 
    let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    print!(" x is :   {:?}",x);
    print!("\n");
    print!(" y is :   {:?}",y);
    print!("\n");

    let cipher = sip.encrypt(&x);
    print!(" Cipher is :   {:?}",cipher);
    print!("\n");

    let dk = sip.derive_fe_key(&y);
    print!(" dk is :   {:?}",dk);
    print!("\n");
    
    let result = sip.decrypt(&cipher, &dk, &BigInt::from(bound));
    print!("result is {:?}",result);
}


