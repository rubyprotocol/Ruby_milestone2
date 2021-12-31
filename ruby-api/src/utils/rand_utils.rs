use miracl_core::rand::{RAND, RAND_impl};
use rand::{Rng, RngCore, SeedableRng};
use rand::rngs::StdRng;
use rand::distributions::Uniform;
use num_bigint::{BigInt, RandBigInt};
use num_traits::Zero;
use crate::define::BigNum;

pub trait Sample<T> {
    fn sample(&mut self, modulus: &T) -> T; 
    fn sample_range(&mut self, low: &T, high: &T) -> T;
    fn sample_vec(&mut self, len: usize, modulus: &T) -> Vec<T>; 
    fn sample_range_vec(&mut self, len: usize, low: &T, high: &T) -> Vec<T>;
    fn sample_array<const L: usize>(&mut self, modulus: &T) -> [T; L];
    fn sample_range_array<const L: usize>(&mut self, low: &T, high: &T) -> [T; L];
}

trait RandUtils {
    type Kernel;
    
    fn get_rng() -> Self::Kernel;
    fn get_seeded_rng(seed: &[u8; 32]) -> Self::Kernel;
}


pub struct RandUtilsRand {
    // Keep an internal RNG member to avoid having to initiate a new one in every functionality call 
    pub rng: RAND_impl
}

impl Default for RandUtilsRand {
    fn default() -> Self {
        Self::new()
    }
}

impl RandUtilsRand {
    pub fn new() -> Self {
        Self {
            rng: Self::get_rng()
        }
    }
}

impl RandUtils for RandUtilsRand {
    type Kernel = RAND_impl;

    
    fn get_rng() -> Self::Kernel {
        let mut seed: [u8; 32] = [0; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Self::get_seeded_rng(&seed)
    }

    fn get_seeded_rng(seed: &[u8; 32]) -> Self::Kernel {
        let mut rng = RAND_impl::new();
        rng.clean();
        rng.seed(seed.len(), seed);
        rng
    }

}

impl Sample<BigNum> for RandUtilsRand {
    fn sample(&mut self, modulus: &BigNum) -> BigNum {
        BigNum::randomnum(modulus, &mut self.rng)
    }

    fn sample_vec(&mut self, len: usize, modulus: &BigNum) -> Vec<BigNum> {
        (0..len).map(|_| self.sample(modulus)).collect()
    }

    fn sample_range(&mut self, low: &BigNum, high: &BigNum) -> BigNum {
        let modulus = high.minus(low);
        let s = self.sample(&modulus); 
        s.plus(low)
    }

    fn sample_range_vec(&mut self, len: usize, low: &BigNum, high: &BigNum) -> Vec<BigNum> {
        let modulus = high.minus(low); 
        (0..len).map(|_| self.sample(&modulus).plus(low)).collect()
    }

    fn sample_array<const L: usize>(&mut self, modulus: &BigNum) -> [BigNum; L] {
        array_init::array_init(|_| self.sample(modulus))
    }

    fn sample_range_array<const L: usize>(&mut self, low: &BigNum, high: &BigNum) -> [BigNum; L] {
        array_init::array_init(|_| self.sample_range(low, high))
    }

}

#[derive(Debug)]
pub struct RandUtilsRng {
    // Keep an internal RNG member to avoid having to initiate a new one in every functionality call 
    pub rng: StdRng 
}

impl Default for RandUtilsRng {
    fn default() -> Self {
        Self::new()
    }
}

impl RandUtilsRng {
    pub fn new() -> Self {
        Self {
            rng: Self::get_rng()
        }
    }
}

impl RandUtils for RandUtilsRng {
    type Kernel = StdRng;

    fn get_rng() -> Self::Kernel {
        StdRng::from_entropy()
    }

    fn get_seeded_rng(seed: &[u8; 32]) -> Self::Kernel {
        StdRng::from_seed(*seed)
    }

}

impl Sample<BigInt> for RandUtilsRng {
    fn sample(&mut self, modulus: &BigInt) -> BigInt {
        self.rng.gen_bigint_range(&BigInt::zero(), modulus)
    }

    fn sample_range(&mut self, low: &BigInt, high: &BigInt) -> BigInt {
        self.rng.gen_bigint_range(low, high)
    }

    fn sample_vec(&mut self, len: usize, modulus: &BigInt) -> Vec<BigInt> {
        let range = Uniform::from(BigInt::zero()..modulus.clone());
        /*
          The grammar '(&mut self.rng).sample_iter(...)' might seem a little difficult to understand. Check the following 3 links:
          https://rust-random.github.io/rand/rand/trait.Rng.html#method.sample_iter
          https://rust-random.github.io/rand/rand/trait.RngCore.html#impl-RngCore-for-%26%27a%20mut%20R
          https://stackoverflow.com/questions/28005134/how-do-i-implement-the-add-trait-for-a-reference-to-a-struct

          Basically, it is because RngCore is also implemented for the REFERENCE of any type that implements RngCore + Sized.
          Hence here we are taking the reference by value, which is just a simple copy of the reference, but not moving the ownership.
        */
        (&mut self.rng).sample_iter(&range).take(len).collect()
    }

    fn sample_range_vec(&mut self, len: usize, low: &BigInt, high: &BigInt) -> Vec<BigInt> {
        let range = Uniform::from(low.clone()..high.clone());
        (&mut self.rng).sample_iter(&range).take(len).collect()
    }

    fn sample_array<const L: usize>(&mut self, modulus: &BigInt) -> [BigInt; L] {
        array_init::array_init(|_| self.sample(modulus))
    }

    fn sample_range_array<const L: usize>(&mut self, low: &BigInt, high: &BigInt) -> [BigInt; L] {
        array_init::array_init(|_| self.sample_range(low, high))
    }
}
