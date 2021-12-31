use warp::{http,Filter};
use serde::{Serialize, Deserialize};
use num_bigint::BigInt;
use miracl_core::bn254::ecp::ECP;
use miracl_core::bn254::ecp2::ECP2;
use ruby::simple_ip::{Sip, SipCipher, SipDk};
use ruby::quadratic_sgp::{Sgp, SgpCipher, SgpDecKey};
use ruby::define::{G1, G2, BigNum};
use ruby::math::matrix::BigNumMatrix;
use ruby::traits::FunctionalEncryption;
use std::collections::HashMap;
use fawkes_crypto::{
    engines::bn256::{JubJubBN256},
    native::ecc::*,
    rand::{thread_rng, Rng},
    ff_uint::{Num},

};

pub type Bn256Fr = fawkes_crypto::engines::bn256::Fr;
pub type Bn12381Fr = fawkes_crypto::engines::bls12_381::Fr;
const L:usize = 2;

#[derive(Debug, Deserialize, Serialize, Clone)]
struct IpInputItem {
    ciphers: IpCipherItem,
    dks: IpDkItem,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct IpCipherItem {
    c: Vec<Vec<u8>>,
    c0: Vec<Vec<u8>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct IpDkItem {
    dk: Vec<String>,
    y: Vec<String>,
}



#[derive(Debug, Deserialize, Serialize, Clone)]
struct QuaInputItem {
    ciphers: QuaCipherItem,
    dks: QuaDkItem,
}
 
#[derive(Debug, Deserialize, Serialize, Clone)]
struct QuaCipherItem {
    g1_mul_gamma: Vec<Vec<u8>>,
    a: Vec<Vec<u8>>,
    b: Vec<Vec<u8>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct QuaDkItem {
    key: Vec<Vec<u8>>,
    data: Vec<Vec<String>>,
    modulus: Vec<String>,
    n_rows: usize,
    n_cols: usize,
}


async fn returng_h() -> Result<impl warp::Reply, warp::Rejection>{

    let mut g_result = HashMap::<String,String>::new();
    let mut h_result = HashMap::<String,String>::new();
    let mut rng = thread_rng();
    let jubjub_params = JubJubBN256::new();
    let g = EdwardsPoint::<Bn256Fr>::rand(&mut rng, &jubjub_params)
    .mul(Num::from(8), &jubjub_params);
    let sk: Num<Bn256Fr> = rng.gen();
    let h = g.mul(sk.to_other_reduced(), &jubjub_params);
    g_result.insert("g".to_owned(), serde_json::to_string(&g).unwrap());
    h_result.insert("h".to_owned(), serde_json::to_string(&h).unwrap());

    let json = warp::reply::json(&format!("{:?}",&(g_result,h_result)));
        Ok(warp::reply::with_status(
            json,
            http::StatusCode::OK,
        ))
}


async fn decrypt_wrapperip(ipitem: IpInputItem) -> Result<impl warp::Reply, warp::Rejection>{
        let bound = 100;

        // SipCipher
        let c0 :G1 = ECP::frombytes(&ipitem.ciphers.c0[0]);
        let mut c:[G1;L] =[();L].map(|_| ECP::new());
        for i in 0..L{
            c[i] = ECP::frombytes(&ipitem.ciphers.c[i]);
        }
        let sip_cipher = SipCipher::new(c0,c);

        // SipDk
        let mut y :[BigNum;L] = [();L].map(|_| BigNum::new());
        for i in 0..ipitem.dks.y.len(){
            y[i] = BigNum::fromstring(ipitem.dks.y[i].to_owned())
        }
        let dk0 = &ipitem.dks.dk[0];

        let sip_dk = SipDk {
            y,
            dk: BigNum::fromstring(dk0.to_owned()),
        };

        
        // Create an instance of the scheme
        let sip = Sip::<L>::new();
        

        // Purchaser evaluates the inner product
        let result = sip.decrypt(&sip_cipher, &sip_dk, &BigInt::from(bound));
        let json = warp::reply::json(&format!("{:?}",result));
        Ok(warp::reply::with_status(
            json,
            http::StatusCode::OK,
        ))
}

async fn decrypt_wrapperqua(quaitem: QuaInputItem) -> Result<impl warp::Reply, warp::Rejection>{
        let bound = 100;

        // SgpCipher
        let g1_mul_gamma :G1 = ECP::frombytes(&quaitem.ciphers.g1_mul_gamma[0]);
        let mut a:Vec<G1> =vec![];
        let mut b:Vec<G2> =vec![];
        println!("cipher a len is {}",quaitem.ciphers.a.len());
        for i in 0..quaitem.ciphers.a.len() {
            a.push(ECP::frombytes(&quaitem.ciphers.a[i]));
        }
        println!("a len is {}",a.len());
        for i in 0..quaitem.ciphers.b.len() {
            b.push(ECP2::frombytes(&quaitem.ciphers.b[i]));
        }
        println!("b len is {}",b.len());
        let sgp_cipher = SgpCipher {
            g1_mul_gamma,
            a,
            b,
        };

        // SgpDecKey
        let key: G2 = ECP2::frombytes(&quaitem.dks.key[0]);
        let a = quaitem.dks.data[0].clone();
        let mut data =[();L*2].map(|_| BigNum::new());
        for i in 0.. a.len(){
            data[i] = BigNum::fromstring(a[i].clone());
        }
        let m0 = quaitem.dks.modulus[0].clone();
        let f: BigNumMatrix = BigNumMatrix::new_bigints(&data,quaitem.dks.n_rows, quaitem.dks.n_cols, &BigNum::fromstring(m0.to_owned()));
        let sgp_dk = SgpDecKey {
            key,
            f,
        };

        
        
        // Create an instance of the scheme.
        let sgp = Sgp::<L>::new();
        
        // Purchaser evaluates the quadratic polynomial
        let result = sgp.decrypt(&sgp_cipher, &sgp_dk, &BigInt::from(bound));
        let json = warp::reply::json(&format!("{:?}",result));
        Ok(warp::reply::with_status(
            json,
            http::StatusCode::OK,
        ))
}

fn ip_postjson() -> impl Filter<Extract = (IpInputItem, ), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

fn qua_postjson() -> impl Filter<Extract = (QuaInputItem, ), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

#[tokio::main]
async fn main() {
    
    let decrypt_ip_datas = warp::post()
        .and(warp::path("ip"))
        .and(warp::path("decrypt"))
        .and(warp::path::end())
        .and(ip_postjson())
        .and_then(decrypt_wrapperip);

    let decrypt_qua_datas = warp::post()
        .and(warp::path("qua"))
        .and(warp::path("decrypt"))
        .and(warp::path::end())
        .and(qua_postjson())
        .and_then(decrypt_wrapperqua);
    
    let get_g_h = warp::get()
        .and(warp::path("g_h"))
        .and(warp::path::end())
        .and_then(returng_h);

    let routes = decrypt_ip_datas.or(decrypt_qua_datas).or(get_g_h);

    warp::serve(routes)
        .run(([127, 0, 0, 1], 3032))
        .await;
}