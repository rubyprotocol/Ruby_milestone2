use warp::{http,Filter};
use ruby::simple_ip::Sip;
use parking_lot::RwLock;
use std::sync::Arc;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use num_bigint::{BigInt, ToBigInt, Sign};
use ruby::traits::FunctionalEncryption;
use ruby::simple_ip::{SipCipher,SipDk,SipMpk,SipMsk};
use ruby::quadratic_sgp::SgpCipher as SipCipherqua;
use ruby::quadratic_sgp::{Sgp,SgpDecKey,SgpPubKey,SgpSecKey};
use miracl_core::bn254::ecp::ECP;
use miracl_core::bn254::ecp2::ECP2;
use ruby::define::{G1,G2,BigNum,MODULUS};
use ruby::math::matrix::BigIntMatrix;
use std::str::FromStr;
use std::iter::FromIterator;
use ruby::utils::{baby_step_giant_step_g1, reduce};
use ruby::zk::sip::{ZkSip};
use ruby::zk::ToEncoding;
use ruby::zk::qp::{ZkQp};
use ruby::zk::types::{Fr, E, JjParams};
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

const L:usize = 2;
//owner upload cipher with id, and receive account. 
//now the id is no use in fact,since no access control
type UserIpCiphers = HashMap<i32, SipCipher<L>>;
type UserReceiveAccount = HashMap<i32, String>;
type UserQuaCiphers = HashMap<i32, SipCipherqua<L>>;

//buyer upload fe with own id
type IpFekeydata = HashMap<i32, [BigInt;L]>;
type QuaFekeydata = HashMap<i32, BigIntMatrix>;

//authrity derive key for buyer_id
type QuaEvaluationKey = HashMap<i32, SgpDecKey>;
type IpEvaluationKey=  HashMap<i32, SipDk<L>>;

type IpMpk = SipMpk<L>;
type QuaMpk = SgpPubKey;
type IpSk = SipMsk<L>;
type QuaSK = Vec<Vec<String>>;

pub type Bn256Fr = fawkes_crypto::engines::bn256::Fr;

#[derive(Debug, Deserialize, Serialize, Clone)]
struct IpItem {
    ciphers: SipCipherHoleder,
    number: i32,
    receiver:String
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct SipCipherHoleder {
    c: Vec<Vec<u8>>,
    c0: Vec<Vec<u8>>
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct QuaItem {
    ciphers: QuaCipherHoleder,
    number: i32,
    receiver:String
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct QuaCipherHoleder {
    g1_mul_gamma: Vec<Vec<u8>>,
    a: Vec<Vec<u8>>,
    b: Vec<Vec<u8>> 
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct IpFEkey {
    y: Vec<i32>,
    buyernumber: i32,
    ciphernum:i32,

}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct QuaFEkey {
    matrix: QuaFEkeyHoleder,
    buyernumber: i32,
    ciphernum:i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct QuaFEkeyHoleder {
    data: Vec<i64>,
    n_rows: usize,
    n_cols: usize,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct GHHoleder{
    g: String,
    h: String,
    buyernumber: i32,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct EvKeyforN {
    buyernumber: i32,
    ciphernumber:i32
}

#[derive(Clone)]
struct Store {
  ipciphers: Arc<RwLock<UserIpCiphers>>,
  quaciphers: Arc<RwLock<UserQuaCiphers>>,
  ipevkey:Arc<RwLock<IpEvaluationKey>>,
  quaevkey:Arc<RwLock<QuaEvaluationKey>>,
  ip_pk:Arc<RwLock<IpMpk>>,
  qua_pk:Arc<RwLock<QuaMpk>>,
  ipfe:Arc<RwLock<IpFekeydata>>,
  quafe:Arc<RwLock<QuaFekeydata>>,
  ipsk:Arc<RwLock<IpSk>>,
  quask:Arc<RwLock<QuaSK>>,
  receiveaccount:Arc<RwLock<UserReceiveAccount>>,
  sip:Arc<RwLock<Sip<L>>>,
  qua:Arc<RwLock<Sgp<L>>>,
  ippk:Arc<RwLock<HashMap<i32,String>>>,
  g:Arc<RwLock<HashMap<i32,EdwardsPoint<Bn256Fr>>>>,
  h:Arc<RwLock<HashMap<i32,EdwardsPoint<Bn256Fr>>>>
}

impl Store {
    fn new() -> Self {
        Store {
            ipciphers: Arc::new(RwLock::new(HashMap::new())),
            quaciphers: Arc::new(RwLock::new(HashMap::new())),
            ipevkey:Arc::new(RwLock::new(HashMap::new())),
            quaevkey:Arc::new(RwLock::new(HashMap::new())),
            ip_pk:Arc::new(RwLock::new(SipMpk{ v:[();L].map(|_| ECP::pnew())})),
            qua_pk:Arc::new(RwLock::new(SgpPubKey{ g1s:vec![],g2t:vec![]})),
            ipfe:Arc::new(RwLock::new(HashMap::new())),
            quafe:Arc::new(RwLock::new(HashMap::new())),
            ipsk:Arc::new(RwLock::new(SipMsk::new([();L].map(|_| BigNum::new())))),
            quask:Arc::new(RwLock::new(Vec::new())),
            receiveaccount:Arc::new(RwLock::new(HashMap::new())),
            sip:Arc::new(RwLock::new(Sip::new())),
            qua:Arc::new(RwLock::new(Sgp::new())),
            ippk:Arc::new(RwLock::new(HashMap::new())),
            g:Arc::new(RwLock::new(HashMap::new())),
            h:Arc::new(RwLock::new(HashMap::new()))
        }
    }
}

async fn input_ip_cipher_data(
    ipitem: IpItem,
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        

        let c0 :G1 = ECP::frombytes(&ipitem.ciphers.c0[0]);
        let mut c:[G1;L] =[();L].map(|_| ECP::new());
        for i in 0..L{
            c[i] = ECP::frombytes(&ipitem.ciphers.c[i]);
        }
        let cipher_tmp = SipCipher::new(c0,c);
        store.ipciphers.write().insert(ipitem.number,cipher_tmp);
        store.receiveaccount.write().insert(ipitem.number,ipitem.receiver);

        Ok(warp::reply::with_status(
            "Added ip cipher success",
            http::StatusCode::CREATED,
        ))
}

async fn input_qua_cipher_data(
    quaitem: QuaItem,
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        
        let g1_mul_gamma :G1 = ECP::frombytes(&quaitem.ciphers.g1_mul_gamma[0]);
        let mut a:Vec<G1> =vec![];
        let mut b:Vec<G2> =vec![];
        for i in 0..quaitem.ciphers.a.len(){
            a.push(ECP::frombytes(&quaitem.ciphers.a[i]));
        }
        println!("a len is {}",a.len());
        for i in 0..quaitem.ciphers.b.len(){
            b.push(ECP2::frombytes(&quaitem.ciphers.b[i]));
        }
        println!("b len is {}",b.len());
        let cipher_tmp = SipCipherqua{
            g1_mul_gamma,
            a,
            b
        };
        store.quaciphers.write().insert(quaitem.number,cipher_tmp);
        store.receiveaccount.write().insert(quaitem.number,quaitem.receiver);

        Ok(warp::reply::with_status(
            "Added qua cipher success",
            http::StatusCode::CREATED,
        ))
}

async fn initip(
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let mut cur =  store.ip_pk.write();
        let mut e_sip = store.sip.write();
        let sip = Sip::<L>::new();
        *cur = sip.get_mpk();
        *e_sip= sip;
        
        Ok(warp::reply::with_status(
            "Init success, you can get ip mpk through api",
            http::StatusCode::CREATED,
        ))
}


async fn initqua(
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let mut cur =  store.qua_pk.write();
        let mut e_sgp = store.qua.write();
        let sgp = Sgp::<L>::new();
        *cur = sgp.get_mpk();
        *e_sgp= sgp;
        Ok(warp::reply::with_status(
            "Init success, you can get qua mpk through api",
            http::StatusCode::CREATED,
        ))
}

async fn get_ip_mpk(
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let mut result = HashMap::<String,Vec<Vec<u8>>>::new();
        let r = store.ip_pk.read().getvbytes();
        let mut bytes: Vec<Vec<u8>> = Vec::new();
        for i in 0..r.len(){
            bytes.push(r[i].to_vec());
        }
        result.insert("v".to_owned(), bytes);


        Ok(warp::reply::json(
            &result
        ))
}

async fn get_ip_sk(
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let sip = store.sip.read();
        let mut result = HashMap::<String,Vec<String>>::new();
        
        result.insert("v".to_owned(), sip.get_mskstring());


        Ok(warp::reply::json(
            &result
        ))
}

async fn get_qua_mpk(
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let mut result = HashMap::<String,Vec<Vec<u8>>>::new();
        let g1sbyte_all = store.qua_pk.read().getg1sbytes();
        let g2tbyte_all = store.qua_pk.read().getg2tbytes();

        let mut g1sbyte: Vec<Vec<u8>> = Vec::new();
        for i in 0..g1sbyte_all.len(){
            g1sbyte.push(g1sbyte_all[i].to_vec());
        }
        let mut g2tbyte: Vec<Vec<u8>> = Vec::new();
        for j in 0..g2tbyte_all.len(){
            g2tbyte.push(g2tbyte_all[j].to_vec());
        }


        result.insert("g1s".to_owned(), g1sbyte);
        result.insert("g2t".to_owned(), g2tbyte);

        Ok(warp::reply::json(
            &result
        ))
}

async fn get_qua_sk(
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let sgp = store.qua.read();
        let mut result = HashMap::<String,Vec<String>>::new();
        let (s,t) = sgp.get_msk();

        result.insert("s".to_owned(),s );
        result.insert("t".to_owned(),t );


        Ok(warp::reply::json(
            &result
        ))
}


async fn input_ip_fekey(
    _ipfekey: IpFEkey,
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        
        let mut cur = store.ipfe.write();
        let buyerk = store.ippk.write();
        let mut _y = [();L].map(|_| BigInt::new(Sign::Plus, vec![0]));
        for i in 0.._ipfekey.y.len(){
            _y[i] = _ipfekey.y[i].to_bigint().unwrap();
        }
        cur.insert(_ipfekey.buyernumber,_y);
        // buyerk.insert(_ipfekey.buyernumber,_ipfekey.pk);
        Ok(warp::reply::with_status(
            "Added ip fe  success",
            http::StatusCode::CREATED,
        ))
}

async fn input_qua_fekey(
    _quafe: QuaFEkey,
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let mut cur = store.quafe.write();
        // let mut _data:Vec<BigInt> = vec![];
        // for i in 0.._quafe.matrix.data.len(){
        //     _data.push(_quafe.matrix.data[i].to_bigint().unwrap());
        // }
        let _matrix = BigIntMatrix::new_ints(&_quafe.matrix.data,_quafe.matrix.n_rows,_quafe.matrix.n_cols);
        
        cur.insert(_quafe.buyernumber,_matrix);
        

        Ok(warp::reply::with_status(
            "Added qua fe success",
            http::StatusCode::CREATED,
        ))
}

async fn get_ip_dk(
    n:EvKeyforN,
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let ipevkey = store.ipevkey.read();
        let mut result = HashMap::<String,Vec<String>>::new();
        let y = ipevkey.get(&n.buyernumber).unwrap().get_y();
        let dk = ipevkey.get(&n.buyernumber).unwrap().get_dk();

        result.insert("y".to_owned(), y);
        result.insert("dk".to_owned(), vec![dk]);

        Ok(warp::reply::json(
            &result
        ))
}

async fn addgh(
    gh:GHHoleder,
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        
        let g:EdwardsPoint<Bn256Fr> =serde_json::from_str(&gh.g).unwrap();
        let h:EdwardsPoint<Bn256Fr> =serde_json::from_str(&gh.h).unwrap();
        let buyrer = gh.buyernumber;
        store.g.write().insert(buyrer,g);
        store.h.write().insert(buyrer,h);

        Ok(warp::reply::with_status(
            "g h add success",
            http::StatusCode::CREATED,
        ))
}



async fn get_qua_dk(
    n:EvKeyforN,
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let dk = store.quaevkey.read();
        let mut resul1t = HashMap::<String,Vec<String>>::new();
        let mut result = HashMap::<String,Vec<u8>>::new();
        let mut resul2t = HashMap::<String,usize>::new();

        let mut data :Vec<String>=Vec::new();
        for o in 0..dk.get(&n.buyernumber).unwrap().f.data.len(){
            data.push(dk.get(&n.buyernumber).unwrap().f.data[o].tostring());
        }

        result.insert("key".to_owned(),dk.get(&n.buyernumber).unwrap().getkeybytes());
        resul1t.insert("data".to_owned(),data);
        resul1t.insert("modulus".to_owned(),vec![dk.get(&n.buyernumber).unwrap().f.modulus.tostring()]);
        resul2t.insert("n_rows".to_owned(),dk.get(&n.buyernumber).unwrap().f.n_rows);
        resul2t.insert("n_cols".to_owned(),dk.get(&n.buyernumber).unwrap().f.n_cols);


        Ok(warp::reply::json(
            &(result,resul1t,resul2t)
        ))
}

async fn input_n_and_deriveip(
    n: EvKeyforN,
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let mut result = HashMap::<String,Vec<String>>::new();
        let  _ipfe = store.ipfe.read();
        let y = _ipfe.get(&n.buyernumber).unwrap();
        let sip = store.sip.read();
        let accounts = store.receiveaccount.read();
        let g_r = store.g.read();
        let g = g_r.get(&n.buyernumber).unwrap();
        let h_r = store.h.read();
        let h = h_r.get(&n.buyernumber).unwrap();
        let mut _ipevk = store.ipevkey.write();
        let dk = sip.derive_fe_key(y);
        let sbytes=sip.get_msk();
        let mut r=[();L].map(|_| String::new());
        for i in 0..sbytes.len(){
            let tmp = BigInt::from_bytes_be(Sign::Plus, &sbytes[i]);
            r[i]=tmp.to_str_radix(10);
        }
        let mut t_v:Vec<Num<Fr>> = vec![];
        const N :usize=1;
        for i in 0..r.len(){
            t_v.push(Num::from_str(&r[i]).unwrap());
        }
        let s : SizedVec<Num<Fr>, N>= SizedVec::from_iter(t_v);
        let mut y_tmp = [();L].map(|_| String::new());
        for i in 0..y.len(){
            let yi = reduce(&y[i], &MODULUS);
            y_tmp[i] = yi.to_str_radix(10);
        }
        let mut y_str :Vec<Num<Fr>> = vec![];
        for i in 0..y.len(){
            y_str.push(Num::from_str(&y_tmp[i]).unwrap())
        }
        let y_zk : SizedVec<Num<Fr>, N>= SizedVec::from_iter(y_str);
        println!("start generate ipzkproof, please wait");
        let snark = ZkSip::<N>::generate(&g, &h, &s, &y_zk);

        let mut tmp =Vec::new();
        for i in 0..dk.y.len(){
            tmp.push(dk.y[i].tostring());
        }
        result.insert("y".to_owned(),tmp);
        result.insert("dk".to_owned(),vec![dk.dk.tostring()]);
        result.insert("owner account".to_owned(), vec![accounts.get(&n.ciphernumber).unwrap().clone()]);
        let mut zkproof =HashMap::<String,String>::new();
        zkproof.insert("substrate proof:".to_owned(),snark.to_substrate_proof() );
        // zkproof.insert("Proof:".to_owned(),snark.proof.encode() );
        zkproof.insert("vk:".to_owned(),snark.vk.encode() );
        _ipevk.insert(n.buyernumber,dk);
        // let zkproof = format!("Inputs:{} \n Proof:{}\n,vk:{}\n",snark.inputs.encode(),snark.proof.encode(),snark.vk.encode());
        Ok(warp::reply::json(
            &(result,zkproof)
        ))
}

async fn input_n_and_derivequa(
    n: EvKeyforN,
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let mut result = HashMap::<String,Vec<Vec<u8>>>::new();
        let mut resul1t = HashMap::<String,Vec<String>>::new();
        let mut resul2t = HashMap::<String,usize>::new();
        let  _quafe = store.quafe.read();
        let  sgp = store.qua.read();
        let accounts = store.receiveaccount.read();
        let mut _quaevk = store.quaevkey.write();
        let f = _quafe.get(&n.buyernumber).unwrap();

        let g_r = store.g.read();
        let g1 = g_r.get(&n.buyernumber).unwrap();
        let h_r = store.h.read();
        let h1 = h_r.get(&n.buyernumber).unwrap();
        let dk = sgp.derive_fe_key(&f);
        let sbytes=sgp.get_sbytes();
        let tbytes=sgp.get_tbytes();
        let mut s_bignum_str=[();L].map(|_| String::new());
        for i in 0..sbytes.len(){
                let tmp = BigInt::from_bytes_be(Sign::Plus, &sbytes[i]);
                s_bignum_str[i]=tmp.to_str_radix(10);
        }
        println!("sbytes is {}",sbytes.len());
        let mut t_bignum_str=[();L].map(|_| String::new());
        for i in 0..tbytes.len(){
                    let tmp = BigInt::from_bytes_be(Sign::Plus, &tbytes[i]);
                    t_bignum_str[i]=tmp.to_str_radix(10);
        }
        const N :usize=2;
        let mut s_v:Vec<Num<Fr>> = vec![];
        for i in 0..s_bignum_str.len(){
            s_v.push(Num::from_str(&s_bignum_str[i]).unwrap());
        }
        println!("s_v is {}",s_v.len());
        let s_zk : SizedVec<Num<Fr>, N>= SizedVec::from_iter(s_v);
        let mut t_v:Vec<Num<Fr>> = vec![];
        for i in 0..t_bignum_str.len(){
            t_v.push(Num::from_str(&t_bignum_str[i]).unwrap());
        }
        let t_zk : SizedVec<Num<Fr>, N>= SizedVec::from_iter(t_v);
        println!("start generate quazkproof, please wait");
        let snark = ZkQp::<N>::generate(&g1, &h1, &s_zk, &t_zk, &f);
        
        let mut data :Vec<String>=Vec::new();
        for o in 0..dk.f.data.len(){
            data.push(dk.f.data[o].tostring());
        }
        
        result.insert("key".to_owned(),vec![dk.getkeybytes()]);
        resul1t.insert("data".to_owned(),data);
        resul1t.insert("modulus".to_owned(),vec![dk.f.modulus.tostring()]);
        resul1t.insert("owner account".to_owned(), vec![accounts.get(&n.ciphernumber).unwrap().clone()]); 
        resul2t.insert("n_rows".to_owned(),dk.f.n_rows);
        resul2t.insert("n_cols".to_owned(),dk.f.n_cols);
        _quaevk.insert(n.buyernumber,dk);
        let mut zkproof =HashMap::<String,String>::new();
        zkproof.insert("substrate proof:".to_owned(),snark.to_substrate_proof() );
        // zkproof.insert("Proof:".to_owned(),snark.proof.encode() );
        zkproof.insert("vk:".to_owned(),snark.vk.encode() );
        //let zkproof = format!("Inputs:{} \n Proof:{}\n,vk:{}\n",snark.inputs.encode(),snark.proof.encode(),snark.vk.encode());

        Ok(warp::reply::json(
            &(result,resul1t,resul2t,zkproof)
            
        ))
}


async fn get_ip_cipher(
    n: EvKeyforN,
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let mut result = HashMap::<String,Vec<Vec<u8>>>::new();
        let cipher = store.ipciphers.read();
        let c0byte = cipher.get(&n.ciphernumber).unwrap().getc0bytes();
        let cbyte = cipher.get(&n.ciphernumber).unwrap().getcbytes();
        let mut c0result :Vec<Vec<u8>>= Vec::new();
        let mut cresult:Vec<Vec<u8>>= Vec::new();
        c0result.push(c0byte.to_vec());
        for i in 0..cbyte.len(){
            cresult.push(cbyte[i].to_vec());
        }

        result.insert("c0".to_owned(), c0result );
        result.insert("c".to_owned(), cresult);
        
        Ok(warp::reply::json(
            &result
        ))
}

async fn get_qua_cipher(
    n: EvKeyforN,
    store: Store
    ) -> Result<impl warp::Reply, warp::Rejection> {
        let mut result = HashMap::<String,Vec<Vec<u8>>>::new();
        let cipher = store.quaciphers.read();
        let g1byte = cipher.get(&n.ciphernumber).unwrap().getg1_mul_gammabytes();
        let abyte  = cipher.get(&n.ciphernumber).unwrap().getabytes();
        let bbyte  = cipher.get(&n.ciphernumber).unwrap().getbbytes();
        let mut g1result :Vec<Vec<u8>>= Vec::new();
        let mut aresult:Vec<Vec<u8>>= Vec::new();
        let mut bresult :Vec<Vec<u8>>= Vec::new();
        g1result.push(g1byte.to_vec());
        for i in 0..abyte.len(){
            aresult.push(abyte[i].to_vec());
        }
        for j in 0..bbyte.len(){
            bresult.push(bbyte[j].to_vec());
        }

        result.insert("g1_mul_gamma".to_owned(), g1result);
        result.insert("a".to_owned(),aresult);
        result.insert("b".to_owned(), bresult);
        
        Ok(warp::reply::json(
            &result
        ))
}



fn ip_post_json() -> impl Filter<Extract = (IpItem,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

fn qua_post_json() -> impl Filter<Extract = (QuaItem,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

fn ip_buyer_json() -> impl Filter<Extract = (IpFEkey,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

fn qua_buyer_json() -> impl Filter<Extract = (QuaFEkey,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

fn get_who_json() -> impl Filter<Extract = (EvKeyforN,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

fn get_gh_json() -> impl Filter<Extract = (GHHoleder,), Error = warp::Rejection> + Clone {
    // When accepting a body, we want a JSON body
    // (and to reject huge payloads)...
    warp::body::content_length_limit(1024 * 16).and(warp::body::json())
}

#[tokio::main]
async fn main() {
    let store = Store::new();
    let store_filter = warp::any().map(move || store.clone());
    
    
    let init_ip = warp::get()
        .and(warp::path("ip"))
        .and(warp::path("init"))
        .and(warp::path::end())
        .and(store_filter.clone())
        .and_then(initip);
    
    let init_qua = warp::get()
        .and(warp::path("qua"))
        .and(warp::path("init"))
        .and(warp::path::end())
        .and(store_filter.clone())
        .and_then(initqua);

    let getipcipher = warp::post()
        .and(warp::path("ip"))
        .and(warp::path("cipher"))
        .and(warp::path::end())
        .and(get_who_json())
        .and(store_filter.clone())
        .and_then(get_ip_cipher);

    let getquacipher = warp::post()
        .and(warp::path("qua"))
        .and(warp::path("cipher"))
        .and(warp::path::end())
        .and(get_who_json())
        .and(store_filter.clone())
        .and_then(get_qua_cipher);

    let getquadk= warp::post()
        .and(warp::path("qua"))
        .and(warp::path("dk"))
        .and(warp::path::end())
        .and(get_who_json())
        .and(store_filter.clone())
        .and_then(get_qua_dk);

    let getipdk= warp::post()
        .and(warp::path("ip"))
        .and(warp::path("dk"))
        .and(warp::path::end())
        .and(get_who_json())
        .and(store_filter.clone())
        .and_then(get_ip_dk);

    let add_ip_cipherdatas = warp::post()
        .and(warp::path("ip"))
        .and(warp::path("input"))
        .and(warp::path::end())
        .and(ip_post_json())
        .and(store_filter.clone())
        .and_then(input_ip_cipher_data);
    
    let choose_derive_ip = warp::post()
        .and(warp::path("ip"))
        .and(warp::path("derive"))
        .and(warp::path::end())
        .and(get_who_json())
        .and(store_filter.clone())
        .and_then(input_n_and_deriveip);
    
    let choose_derive_qua = warp::post()
        .and(warp::path("qua"))
        .and(warp::path("derive"))
        .and(warp::path::end())
        .and(get_who_json())
        .and(store_filter.clone())
        .and_then(input_n_and_derivequa);

    let add_qua_cipherdatas = warp::post()
        .and(warp::path("qua"))
        .and(warp::path("input"))
        .and(warp::path::end())
        .and(qua_post_json())
        .and(store_filter.clone())
        .and_then(input_qua_cipher_data);

    let get_ip_pk = warp::get()
        .and(warp::path("ip"))
        .and(warp::path("mpk"))
        .and(warp::path::end())
        .and(store_filter.clone())
        .and_then(get_ip_mpk);
    let get_ip_sks = warp::get()
        .and(warp::path("ip"))
        .and(warp::path("sk"))
        .and(warp::path::end())
        .and(store_filter.clone())
        .and_then(get_ip_sk);

    let get_qua_pk = warp::get()
        .and(warp::path("qua"))
        .and(warp::path("mpk"))
        .and(warp::path::end())
        .and(store_filter.clone())
        .and_then(get_qua_mpk);
    let get_qua_sks = warp::get()
        .and(warp::path("qua"))
        .and(warp::path("sk"))
        .and(warp::path::end())
        .and(store_filter.clone())
        .and_then(get_qua_sk);

    let add_ip_fekey= warp::post()
        .and(warp::path("ip"))
        .and(warp::path("fe"))
        .and(warp::path::end())
        .and(ip_buyer_json())
        .and(store_filter.clone())
        .and_then(input_ip_fekey);
    
    let add_qua_fekey= warp::post()
        .and(warp::path("qua"))
        .and(warp::path("fe"))
        .and(warp::path::end())
        .and(qua_buyer_json())
        .and(store_filter.clone())
        .and_then(input_qua_fekey);
    let add_gh= warp::post()
        .and(warp::path("add"))
        .and(warp::path("gh"))
        .and(warp::path::end())
        .and(get_gh_json())
        .and(store_filter.clone())
        .and_then(addgh);
    

    let routes = add_ip_cipherdatas
    .or(add_qua_cipherdatas)
    .or(get_ip_pk)
    .or(get_qua_pk)
    .or(init_ip)
    .or(init_qua)
    .or(add_ip_fekey)
    .or(add_qua_fekey)
    .or(choose_derive_ip)
    .or(choose_derive_qua)
    .or(getipcipher)
    .or(getquacipher)
    .or(getipdk)
    .or(getquadk)
    .or(get_ip_sks)
    .or(get_qua_sks)
    .or(add_gh);

    warp::serve(routes)
        .run(([127, 0, 0, 1], 3030))
        .await;
}

