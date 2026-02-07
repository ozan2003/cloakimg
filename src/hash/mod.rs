//! Hashing routines for integrity check of the payload
//! before embedding into the image and after extraction.

mod hasher;

pub use hasher::{DEFAULT_DIGEST_LEN, Hasher, hash};
