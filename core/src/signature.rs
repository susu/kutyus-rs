
use std::fmt;
use ::errors::Result;

/// An Ed25519 signature
///
/// Size of Ed25519 signature is 64 bytes (twice of the public key)
pub struct Signature(pub [u8; 64]);

impl Signature {
    pub fn new(slice: &[u8]) -> Result<Signature> {
        if slice.len() != 64 {
            bail!("Signature bytes length should be 64, but it is {}", slice.len())
        } else {
            let mut bytes = [0u8; 64];
            bytes.copy_from_slice(slice);
            Ok(Signature(bytes))
        }
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for byte in self.0.iter() {
            write!(f, "{:x} ", byte)?;
        }
        Ok(())
    }
}

impl PartialEq for Signature {
    fn eq(&self, rhs: &Signature) -> bool {
        for (x1, x2) in self.0.iter().zip(rhs.0.iter())
        {
            if x1 != x2 {
                return false;
            }
        }
        true
    }
}

