extern crate kutyus_core;

use kutyus_core::{generate_private_key, PrivKeyBytes, load_key};
use kutyus_core::Error;

use std::io::Write;
use std::fs::File;

fn main()
{
    // TODO get path from CLI arg
    let path: &str = "your.key";
    match generate_and_write(&path) {
        Ok(_) => println!("Generated and written to '{}'", &path),
        Err(e) => println!("Error: {:?}", e),
    };
}

fn generate_and_write(path: &str) -> Result<(), Error>
{
    let privkey: PrivKeyBytes = generate_private_key()?;
    let keypair = load_key(&privkey)?;

    let mut file = File::create(path)?;
    file.write_all(&privkey)?;

    let mut pubfile = File::create(path.to_string() + ".pub")?;
    pubfile.write_all(keypair.public_key_bytes())?;
    Ok(())
}
