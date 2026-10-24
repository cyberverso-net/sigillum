//! A deterministic source of bytes for test keys and signature salts.
//!
//! The output is SHA-256 in counter mode over a fixed label: block `i` is
//! `SHA-256(seed || i)`, with `seed = SHA-256("sigillum-testpki" || label)`
//! and `i` a 64-bit big-endian counter. Anyone can recompute it from the
//! label, which is the point: the test PKI is reproducible, and its keys
//! are public test keys with no value.

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

/// A deterministic generator seeded from a label.
///
/// It implements [`CryptoRng`] only because the key generation and
/// signing interfaces of the RustCrypto crates require it. Its output is
/// predictable by design and must never protect anything.
pub struct TestRng {
    seed: [u8; 32],
    counter: u64,
    block: [u8; 32],
    used: usize,
}

impl TestRng {
    /// Returns the generator for a label.
    pub fn new(label: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(b"sigillum-testpki");
        hash.update(label);
        Self {
            seed: hash.finalize().into(),
            counter: 0,
            block: [0; 32],
            used: 32,
        }
    }

    fn refill(&mut self) {
        let mut hash = Sha256::new();
        hash.update(self.seed);
        hash.update(self.counter.to_be_bytes());
        self.block = hash.finalize().into();
        self.counter = self.counter.wrapping_add(1);
        self.used = 0;
    }
}

impl RngCore for TestRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_be_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_be_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            if self.used == self.block.len() {
                self.refill();
            }
            *byte = self.block[self.used];
            self.used += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for TestRng {}
