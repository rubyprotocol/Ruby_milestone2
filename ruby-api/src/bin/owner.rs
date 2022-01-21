use miracl_core::bn254::ecp::ECP;
use miracl_core::bn254::ecp2::ECP2;
use num_bigint::{BigInt, Sign, ToBigInt};
use ruby::define::{G1, G2};
use ruby::quadratic_sgp::{Sgp, SgpPlain, SgpPubKey};
use ruby::simple_ip::{Sip, SipMpk};
use ruby::traits::FunctionalEncryption;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use warp::{http, Filter};

const L: usize = 4;

#[derive(Debug, Deserialize, Serialize, Clone)]
struct IpInputItem {
    rawdata: IpRawData,
    pk: IpMpkItem,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct IpMpkItem {
    v: Vec<Vec<u8>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct IpRawData {
    d: Vec<i32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct QuaInputItem {
    rawdata: QuaRawData,
    pk: QuaPkItem,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct QuaPkItem {
    g1s: Vec<Vec<u8>>,
    g2t: Vec<Vec<u8>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct QuaRawData {
    x: Vec<i32>,
    y: Vec<i32>,
}

async fn encrypt_wrapperip(ipitem: IpInputItem) -> Result<impl warp::Reply, warp::Rejection> {
    //rawdata
    let mut raw = [(); L].map(|_| BigInt::new(Sign::Plus, vec![0]));
    let i_raw = ipitem.rawdata.d;
    for i in 0..i_raw.len() {
        raw[i] = i_raw[i].to_bigint().unwrap();
    }

    // SipMpk
    let mut v: [G1; L] = [(); L].map(|_| ECP::new());
    for i in 0..L {
        v[i] = ECP::frombytes(&ipitem.pk.v[i]);
    }
    let sip_mpk = SipMpk { v };

    // Create an instance of the scheme
    let mut sip = Sip::<L>::new();
    sip.set_mpk(sip_mpk);
    //encrypt
    let cipher = sip.encrypt(&raw);

    //return cipher in bytes
    let mut c0 = HashMap::<String, Vec<Vec<u8>>>::new();
    c0.insert("c0".to_owned(), vec![cipher.getc0bytes().to_vec()]);
    let mut c = HashMap::<String, Vec<Vec<u8>>>::new();
    let mut cresult: Vec<Vec<u8>> = Vec::new();
    let cbytes = cipher.getcbytes();
    for item in &cbytes {
        cresult.push(item.to_vec());
    }
    c.insert("c".to_owned(), cresult);

    let json = warp::reply::json(&(c0, c));
    Ok(warp::reply::with_status(json, http::StatusCode::OK))
}

async fn encrypt_wrapperqua(quaitem: QuaInputItem) -> Result<impl warp::Reply, warp::Rejection> {
    //rawdata
    let mut rawx = [(); L].map(|_| BigInt::new(Sign::Plus, vec![0]));
    let mut rawy = [(); L].map(|_| BigInt::new(Sign::Plus, vec![0]));
    let x_raw = quaitem.rawdata.x;
    let y_raw = quaitem.rawdata.y;
    for i in 0..x_raw.len() {
        rawx[i] = x_raw[i].to_bigint().unwrap();
    }
    for j in 0..y_raw.len() {
        rawy[j] = y_raw[j].to_bigint().unwrap();
    }
    let plandata = SgpPlain { x: rawx, y: rawy };

    // SgpPubKey
    let mut g1s: Vec<G1> = vec![];
    let mut g2t: Vec<G2> = vec![];
    for i in 0..quaitem.pk.g1s.len() {
        g1s.push(ECP::frombytes(&quaitem.pk.g1s[i]));
    }
    for i in 0..quaitem.pk.g2t.len() {
        g2t.push(ECP2::frombytes(&quaitem.pk.g2t[i]));
    }
    let qua_pk = SgpPubKey { g1s, g2t };

    // Create an instance of the scheme.
    let mut sgp = Sgp::<L>::new();
    sgp.set_mpk(qua_pk);
    // encrypt
    let cipher = sgp.encrypt(&plandata);

    //return cipher in bytes
    let mut result = HashMap::<String, Vec<Vec<u8>>>::new();
    let g1byte = cipher.getg1_mul_gammabytes();
    let abyte = cipher.getabytes();
    let bbyte = cipher.getbbytes();
    let mut g1result: Vec<Vec<u8>> = Vec::new();
    let mut aresult: Vec<Vec<u8>> = Vec::new();
    let mut bresult: Vec<Vec<u8>> = Vec::new();
    g1result.push(g1byte.to_vec());
    for item in &abyte {
        aresult.push(item.to_vec());
    }
    for item in &bbyte {
        bresult.push(item.to_vec());
    }
    result.insert("g1_mul_gamma".to_owned(), g1result);
    result.insert("a".to_owned(), aresult);
    result.insert("b".to_owned(), bresult);

    let json = warp::reply::json(&result);
    Ok(warp::reply::with_status(json, http::StatusCode::OK))
}

fn ip_postjson() -> impl Filter<Extract = (IpInputItem,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

fn qua_postjson() -> impl Filter<Extract = (QuaInputItem,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

#[tokio::main]
async fn main() {
    let encrypt_ip_datas = warp::post()
        .and(warp::path("ip"))
        .and(warp::path("encrypt"))
        .and(warp::path::end())
        .and(ip_postjson())
        .and_then(encrypt_wrapperip);

    let encrypt_qua_datas = warp::post()
        .and(warp::path("qua"))
        .and(warp::path("encrypt"))
        .and(warp::path::end())
        .and(qua_postjson())
        .and_then(encrypt_wrapperqua);

    let routes = encrypt_ip_datas.or(encrypt_qua_datas);

    warp::serve(routes).run(([127, 0, 0, 1], 3035)).await;
}
