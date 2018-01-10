extern crate untrusted;
extern crate ring;
extern crate rmp;


#[macro_use]
extern crate error_chain;

pub mod message;
pub mod frame;
pub mod signature;
// pub mod errors;

pub mod errors {
    error_chain!{
        foreign_links {
            // TODO separate error chain for msgpack/codec errors
            NumValueReadError(::rmp::decode::NumValueReadError);
            ValueReadError(::rmp::decode::ValueReadError);
            ValueWriteError(::rmp::encode::ValueWriteError);

            Io(::std::io::Error);
        }
    }
}

use errors::Result;
use errors::ResultExt;


// use ring::signature;

pub type PrivKeyBytes = [u8; 85];

pub fn load_key(bytes: &[u8]) -> Result<ring::signature::Ed25519KeyPair>
{
    let key_pair = ring::signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(bytes))
        .chain_err(|| "Could not load Ed25519 key from PKCS8 bytes")?;
    Ok(key_pair)
}

pub fn generate_private_key() -> Result<PrivKeyBytes>
{
    let randgen = ring::rand::SystemRandom::new();
    let key_bytes = ring::signature::Ed25519KeyPair::generate_pkcs8(&randgen)
        .chain_err(|| "Could not generate Ed25519 key!")?;

    Ok(key_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_key_can_be_loaded_as_keypair() {
        let privkey = generate_private_key().unwrap();
        let _keypair: ring::signature::Ed25519KeyPair = load_key(&privkey).unwrap();
    }

    #[test]
    fn loading_invalid_key_results_error() {
        let invalid = [0u8, 0u8];
        let result = load_key(&invalid);
        assert!(result.is_err());
        match result {
            Err(Error::KeyLoadError) => (),
            _ => panic!("Unexpected result")
        }
    }
}
