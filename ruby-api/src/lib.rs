#![allow(clippy::needless_range_loop)]
#![allow(clippy::many_single_char_names)]
#![allow(clippy::ptr_arg)]
#![allow(clippy::to_string_in_display)]
#![allow(dead_code)]

extern crate lazy_static;
extern crate miracl_core;
extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
extern crate rand;
extern crate rand_chacha;

pub mod define;
pub mod dmcfe_ip;
pub mod math;
pub mod ml;
pub mod quadratic_sgp;
pub mod simple_ip;
pub mod traits;
pub mod utils;
pub mod zk;
