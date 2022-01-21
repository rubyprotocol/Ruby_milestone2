use crate::define::{BigNum, CURVE_ORDER, G1, MB, MODULUS};
use crate::traits::FunctionalEncryption;
use crate::utils::rand_utils::{RandUtilsRand, Sample};
use crate::utils::{baby_step_giant_step_g1, reduce};
use miracl_core::bn254::ecp::ECP;
use num_bigint::BigInt;

/// Michel Abdalla, Florian Bourse, Angelo De Caro, and David Pointcheval, "Simple Functional Encryption Schemes for Inner Products", PKC 2015.
///
/// `L` is the length of input vectors for the inner product.
///
/// # Examples
///
/// ```
/// use ruby::ruby::traits::FunctionalEncryption;
/// use ruby::simple_ip::Sip;
/// const L: usize = 20;
/// let sip = Sip::<L>::new();
/// ```
#[derive(Debug)]
pub struct Sip<const L: usize> {
    /// Master secret key
    msk: SipMsk<L>,
    /// Master public key
    mpk: SipMpk<L>,
}

impl<const L: usize> Sip<L> {
    pub fn set_mpk(&mut self, mpk: SipMpk<L>) {
        self.mpk = mpk;
    }

    pub fn set_msk(&mut self, msk: SipMsk<L>) {
        self.msk = msk;
    }

    pub fn get_mpk(&self) -> SipMpk<L> {
        let mut v: [G1; L] = [(); L].map(|_| ECP::pnew());
        for i in 0..L {
            let mut new_tmp = ECP::pnew();
            new_tmp.copy(&self.mpk.v[i]);
            v[i] = new_tmp;
        }

        SipMpk { v }
    }

    pub fn get_msk(&self) -> Vec<[u8; MB]> {
        let mut _result = Vec::new();
        for big in self.msk.s {
            let mut tmp = [0u8; MB];
            big.tobytes(&mut tmp[..]);
            _result.push(tmp)
        }
        _result
    }
    pub fn get_mskstring(&self) -> Vec<String> {
        let mut _result = Vec::new();
        for big in self.msk.s {
            _result.push(big.tostring());
        }
        _result
    }
}

/// Master secret key: a secret of length L.
#[derive(Debug)]
pub struct SipMsk<const L: usize> {
    pub s: [BigNum; L],
}
impl<const L: usize> SipMsk<L> {
    pub fn new(s: [BigNum; L]) -> Self {
        SipMsk { s }
    }
}

/// Master public key
#[derive(Debug)]
pub struct SipMpk<const L: usize> {
    pub v: [G1; L],
}

impl<const L: usize> SipMpk<L> {
    pub fn getv(&self) -> Vec<String> {
        let result: Vec<String> = self.v.iter().map(|g| g.tostring()).collect();
        result
    }

    //193 no related to L. every G1 to_bytes is 193 long
    pub fn getvbytes(&self) -> Vec<[u8; 193]> {
        let mut result: Vec<[u8; 193]> = vec![];
        for i in self.v.iter() {
            let mut tmp = [0u8; 193];
            i.tobytes(&mut tmp[..], true);
            result.push(tmp);
        }
        result
    }
}

/// Functional encryption ciphertext
#[derive(Debug, Clone)]
pub struct SipCipher<const L: usize> {
    c0: G1,
    c: [G1; L],
}

impl<const L: usize> SipCipher<L> {
    pub fn getc0(&self) -> String {
        self.c0.tostring()
    }

    pub fn getc0bytes(&self) -> [u8; 193] {
        let mut tmp = [0u8; 193];
        self.c0.tobytes(&mut tmp[..], true);
        tmp
    }

    pub fn getc(&self) -> Vec<String> {
        let result: Vec<String> = self.c.iter().map(|g| g.tostring()).collect();
        result
    }
    pub fn getcbytes(&self) -> Vec<[u8; 193]> {
        let mut result: Vec<[u8; 193]> = vec![];
        for i in self.c.iter() {
            let mut tmp = [0u8; 193];
            i.tobytes(&mut tmp[..], true);
            result.push(tmp);
        }
        result
    }

    pub fn new(c0: G1, c: [G1; L]) -> Self {
        SipCipher { c0, c }
    }
}

/// Functional evaluation key
#[derive(Debug)]
pub struct SipDk<const L: usize> {
    pub y: [BigNum; L],
    pub dk: BigNum,
}

impl<const L: usize> SipDk<L> {
    pub fn get_dk(&self) -> String {
        self.dk.tostring()
    }

    pub fn get_y(&self) -> Vec<String> {
        let result: Vec<String> = self.y.iter().map(|g| g.tostring()).collect();
        result
    }
}

impl<const L: usize> FunctionalEncryption for Sip<L> {
    type CipherText = SipCipher<L>;
    type PlainData = [BigInt; L];
    type FEKeyData = [BigInt; L];
    type EvaluationKey = SipDk<L>;

    /// Constructs a new `Sip<L>`.
    ///
    /// # Examples
    ///
    /// ```
    /// use ruby::ruby::traits::FunctionalEncryption;
    /// use ruby::simple_ip::Sip;
    /// const L: usize = 20;
    /// let sip = Sip::<L>::new();
    /// ```
    fn new() -> Sip<L> {
        let (msk, mpk) = Sip::generate_sec_key();
        Sip { msk, mpk }
    }

    /// Encrypt a vector of numbers.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut rng = RandUtilsRng::new();
    /// const L: usize = 20;
    /// let bound: i32 = 100;
    /// let low = (-bound).to_bigint().unwrap();
    /// let high = bound.to_bigint().unwrap();
    /// let sip = Sip::<L>::new();
    /// let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    /// let cipher = sip.encrypt(&x);
    /// ```
    fn encrypt(&self, x: &Self::PlainData) -> Self::CipherText {
        let mut rng = RandUtilsRand::new();

        let r = rng.sample(&(CURVE_ORDER));
        let c0 = G1::generator().mul(&r);
        let mut c: [G1; L] = array_init::array_init(|_| G1::generator());
        for i in 0..L {
            let xi = reduce(&x[i], &MODULUS);
            let xi = BigNum::fromstring(xi.to_str_radix(16));

            c[i] = c[i].mul(&xi);
            c[i].add(&(self.mpk.v[i].mul(&r)));
        }
        SipCipher { c0, c }
    }

    /// Derive functional evaluation key for a vector of numbers.
    ///
    /// # Examples
    /// ```ignore
    /// // Following the example of `encrypt`
    /// let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    /// let dk = sip.derive_fe_key(&y);
    /// ```
    fn derive_fe_key(&self, y: &Self::FEKeyData) -> Self::EvaluationKey {
        let mut new_y: [BigNum; L] = [BigNum::new(); L];
        let mut dk: BigNum = BigNum::new();
        for i in 0..L {
            let yi = reduce(&y[i], &MODULUS);
            let yi = BigNum::fromstring(yi.to_str_radix(16));
            dk.add(&BigNum::modmul(&yi, &self.msk.s[i], &CURVE_ORDER));
            dk.rmod(&CURVE_ORDER);
            new_y[i] = yi;
        }
        SipDk { y: new_y, dk }
    }

    /// Decrypt a ciphertext with the functional evaluation key.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Following the example of `derive_fe_key`
    /// let result = sip.decrypt(&cipher, &y, &dk, &BigInt::from(bound));
    /// ```
    //fn decrypt(&self, ct: &Self::CipherText, y: &Self::FEKeyData, dk: &Self::EvaluationKey, bound: &BigInt) -> Option<BigInt> {
    fn decrypt(
        &self,
        ct: &Self::CipherText,
        dk: &Self::EvaluationKey,
        bound: &BigInt,
    ) -> Option<BigInt> {
        let mut res = G1::new();
        for i in 0..L {
            //let yi = reduce(&dk.y[i], &MODULUS);
            //let yi = BigNum::fromstring(yi.to_str_radix(16));

            //res.add(&ct.c[i].mul(&yi));
            res.add(&ct.c[i].mul(&(dk.y[i])));
        }
        res.sub(&ct.c0.mul(&dk.dk));

        //dlog
        let mut result_bound = BigNum::fromstring(bound.to_str_radix(16));
        result_bound = result_bound.powmod(&BigNum::new_int(2), &CURVE_ORDER);
        result_bound = BigNum::modmul(&result_bound, &BigNum::new_int(L as isize), &CURVE_ORDER);

        baby_step_giant_step_g1(&res, &G1::generator(), &result_bound)
    }
}

impl<const L: usize> Sip<L> {
    /// Generate a pair of master secret key and master public key.
    pub fn generate_sec_key() -> (SipMsk<L>, SipMpk<L>) {
        let mut rng = RandUtilsRand::new();
        let msk = SipMsk {
            s: rng.sample_array::<L>(&(CURVE_ORDER)),
        };
        let mut mpk = SipMpk::<L> {
            v: array_init::array_init(|_| G1::generator()),
        };
        for i in 0..L {
            mpk.v[i] = mpk.v[i].mul(&(msk.s[i]));
        }
        (msk, mpk)
    }
}
