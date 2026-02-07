use blake3::Hasher as Blake3Hasher;

/// Default length of the hash digest in bytes.
pub const DEFAULT_DIGEST_LEN: usize = 10; // 80 bits

/// A stateful hasher that allows for incremental updates and fixed output
/// length.
pub struct Hasher
{
    inner: Blake3Hasher,
}

impl Hasher
{
    /// Creates a new hasher with the default output length.
    ///
    /// # Returns
    /// A new instance of `Hasher` with the default output length.
    #[must_use]
    pub fn new() -> Self
    {
        Self {
            inner: Blake3Hasher::new(),
        }
    }

    /// Updates the hasher state with the provided input data.
    ///
    /// # Arguments
    /// * `input` - A byte slice containing the data to be hashed.
    pub fn update(&mut self, input: &[u8])
    {
        self.inner.update(input);
    }

    /// Finalizes the hashing process and returns the output digest as an array
    /// of bytes.
    ///
    /// # Returns
    /// An array of bytes containing the computed hash digest of the input data.
    #[must_use]
    pub fn finalize(self) -> [u8; DEFAULT_DIGEST_LEN]
    {
        let mut digest = [0; DEFAULT_DIGEST_LEN];

        let mut output_reader = self.inner.finalize_xof();
        output_reader.fill(&mut digest);

        digest
    }
}

impl Default for Hasher
{
    fn default() -> Self
    {
        Self::new()
    }
}

/// A convenience function for hashing data in a single step without needing to
/// manage the hasher state manually.
///
/// # Arguments
/// * `input` - A slice of bytes containing the data to be hashed.
///
/// # Returns
/// A array of bytes containing the computed hash digest of the input data.
#[must_use]
pub fn hash(input: &[u8]) -> [u8; DEFAULT_DIGEST_LEN]
{
    let mut hasher = Hasher::new();
    hasher.update(input);
    hasher.finalize()
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn hashes_with_fixed_length()
    {
        let digest = hash(b"cloakimg");
        assert_eq!(digest.len(), DEFAULT_DIGEST_LEN);
    }

    #[test]
    fn hasher_is_deterministic()
    {
        let mut hasher_a = Hasher::new();
        hasher_a.update(b"payload");
        let digest_a = hasher_a.finalize();

        let mut hasher_b = Hasher::new();
        hasher_b.update(b"payload");
        let digest_b = hasher_b.finalize();

        assert_eq!(digest_a, digest_b);
    }
}
