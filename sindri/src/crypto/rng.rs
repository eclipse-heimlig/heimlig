use core::cmp::min;
use rand::Rng as RandRng;
use rand_chacha::rand_core::{impls, CryptoRng, SeedableRng};
use rand_chacha::ChaCha20Rng;

/// Entropy source from which a random number generator can be seeded.
pub trait EntropySource {
    fn random_seed(&mut self) -> [u8; 32];
}

/// Random number generator based on the ChaCha20 stream cipher.
pub struct Rng<E>
where
    E: EntropySource,
{
    rng: ChaCha20Rng,
    source: E,
    reseed_threshold: u128,
}

impl<E: EntropySource> Rng<E> {
    /// Number of bytes after which this random number generator cycles and must be reseeded.
    const CYCLE_LENGTH: u128 = 1 << 70; // 1 ZiB (zebibyte)

    /// Create a new random number generator instance.
    ///
    /// # Arguments
    ///
    /// * `source`: The entropy source from which the generator is seeded and reseeded if
    /// `reseed_threshold` is set.
    /// * `reseed_threshold`: Optional number of bytes after which the generator will reseed itself.
    /// Reseeding the generator is an additional defense in depth measure in case an attacker gets
    /// access to the internal state of the generator.
    pub fn new(mut source: E, reseed_threshold: Option<u128>) -> Self {
        Rng {
            rng: ChaCha20Rng::from_seed(source.random_seed()),
            source,
            reseed_threshold: reseed_threshold.unwrap_or(Rng::<E>::CYCLE_LENGTH),
        }
    }

    /// Reseeds the random number generator. Without reseeding, the generator cycles after
    /// generating 1 ZiB (zebibyte) of pseudorandom data.
    pub fn reseed(&mut self) {
        self.rng = ChaCha20Rng::from_seed(self.source.random_seed());
    }
}

impl<E: EntropySource> CryptoRng for Rng<E> {}

impl<E: EntropySource> rand::RngCore for Rng<E> {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // Reseed as many times as needed to fill the output buffer
        let mut rem_dest = dest;
        while !rem_dest.is_empty() {
            let bytes_until_reseed = self
                .reseed_threshold
                .saturating_sub(4 * self.rng.get_word_pos());
            let bytes_to_write: usize = min(bytes_until_reseed, rem_dest.len() as u128) as usize;
            let (fill_now, fill_later) = rem_dest.split_at_mut(bytes_to_write);
            self.rng.fill(fill_now);
            if bytes_to_write as u128 >= bytes_until_reseed {
                self.reseed();
            }
            rem_dest = fill_later;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test {
    use crate::crypto::rng::{EntropySource, Rng};
    use rand::RngCore;

    #[derive(Default)]
    pub struct TestEntropySource {
        counter: u64,
    }

    impl EntropySource for TestEntropySource {
        fn random_seed(&mut self) -> [u8; 32] {
            let mut dest = [0u8; 32];
            for byte in &mut dest {
                *byte = self.counter as u8;
                self.counter = self.counter + 1
            }
            dest
        }
    }

    #[test]
    fn create_rng() {
        let source = TestEntropySource::default();
        assert_eq!(source.counter, 0);
        let rng = Rng::new(source, Some(256));
        assert_eq!(rng.source.counter, 32);
    }

    #[test]
    fn no_reseed() {
        let source = TestEntropySource::default();
        let mut data = [0u8; 255];
        let mut rng = Rng::new(source, Some(256));
        rng.fill_bytes(&mut data);
        assert_eq!(rng.source.counter, 32);
    }

    #[test]
    fn one_reseed() {
        let source = TestEntropySource::default();
        let mut data = [0u8; 256];
        let mut rng = Rng::new(source, Some(256));
        rng.fill_bytes(&mut data);
        assert_eq!(rng.source.counter, 64);
    }

    #[test]
    fn multiple_reseeds() {
        let source = TestEntropySource::default();
        let mut data = [0u8; 4 * 256];
        let mut rng = Rng::new(source, Some(256));
        rng.fill_bytes(&mut data);
        assert_eq!(rng.source.counter, 32 + 4 * 32);
    }
}
