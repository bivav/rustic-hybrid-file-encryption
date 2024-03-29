use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::Path;

use anyhow::{Context, Result};
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};

pub fn rsa_implementation() -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let mut rng = OsRng;
    let bits = 2048;

    let private_key: RsaPrivateKey;
    let public_key: RsaPublicKey;

    if Path::new("keys").exists()
        && Path::new("keys/private_key.pem").exists()
        && Path::new("keys/public_key.pem").exists()
    {
        println!("Keys already exist. Loading keys..");
        let private_key_pem = fs::read_to_string("keys/private_key.pem")?;
        // let public_key_pem = fs::read_to_string("keys/public_key.pem")?;

        private_key = RsaPrivateKey::from_pkcs1_pem(&private_key_pem)?;
        public_key = RsaPublicKey::from(&private_key);

    } else {
        println!("Keys don't exist. Generating keys.. Please wait..");

        private_key = RsaPrivateKey::new(&mut rng, bits)?;
        public_key = RsaPublicKey::from(&private_key);

        let private_key_pem = private_key.to_pkcs1_pem(LineEnding::LF)?;
        let public_key_pem = public_key.to_pkcs1_pem(LineEnding::default())?;

        fs::create_dir_all("keys").context("Couldn't create directory.")?;

        let mut private_file = File::create("keys/private_key.pem")?;
        private_file.write_all(&private_key_pem.as_bytes())?;
        
        let mut public_file = File::create("keys/public_key.pem")?;
        public_file.write_all(&public_key_pem.as_bytes())?;

        println!("Keys generated and saved in 'keys' directory");
    }

    Ok((private_key, public_key))
}
