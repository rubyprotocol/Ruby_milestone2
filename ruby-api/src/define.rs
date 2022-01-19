use lazy_static::lazy_static;
use miracl_core::bn254::big;
use miracl_core::bn254::big::BIG;
use miracl_core::bn254::dbig::DBIG;
use miracl_core::bn254::ecp::ECP;
use miracl_core::bn254::ecp2::ECP2;
use miracl_core::bn254::fp12::FP12;
use miracl_core::bn254::rom;
use num_bigint::{BigInt, Sign};

pub const MODBYTES: usize = 48;
pub const BASEBITS: usize = 58;

pub const NLEN: usize = 1 + ((8 * MODBYTES - 1) / BASEBITS);

pub use miracl_core::bn254::pair;

pub type BigNum = BIG;
pub type DBigNum = DBIG;
pub type G1 = ECP;
pub type G2 = ECP2;
pub type Gt = FP12;

pub const MB: usize = big::MODBYTES as usize;

pub type G1Vector = Vec<G1>;
pub type G2Vector = Vec<G2>;

lazy_static! {
    // CURVE_ORDER is a 255-bit prime
    // It equals: 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001  (https://github.com/zkcrypto/bls12_381)
    // The presentation in rom::CURVE_ORDER seems a little different because it only uses 58 bits in each CHUNK (set in big::BASEBITS),
    // hence there is some bit shifting, but the number is the same.
    pub static ref CURVE_ORDER: BigNum = BigNum::new_ints(&rom::CURVE_ORDER);
    static ref BUF: [u8; MB] = {
        let mut m = [0; MB];
        CURVE_ORDER.tobytes(&mut m);
        m
    };
    pub static ref MODULUS: BigInt = BigInt::from_bytes_be(Sign::Plus, &BUF[..]);
    pub static ref DBIG_ZERO: DBigNum = DBigNum::new();
}
