use std::cmp::min;
// use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::process::exit;

use anyhow::{anyhow, bail, Result};
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, digest, pbkdf2};
use rsa::rand_core::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};

pub struct Config {
    pub command: String,
    pub file_path: String,
}

impl Config {
    pub fn build(args: &[String]) -> Result<Config> {
        if args.len() < 3 {
            bail!("Not enough arguments!");
        }

        let command = args[1].clone();
        let file_path = args[2].clone();

        Ok(Config { command, file_path })
    }

    pub fn read_file(config: Config) -> Result<Vec<u8>> {
        let mut file = File::open(config.file_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    pub fn read_file_base64(config: Config) -> Result<Vec<u8>> {
        let file_content = fs::read_to_string(config.file_path)?;

        let decoded_data = base64::engine::general_purpose::STANDARD
            .decode(&file_content)
            .unwrap_or_else(|e| {
                println!("Decoding Error: {:?}\nAre you sure it's the encrypted file?", e);
                exit(1);
            });

        Ok(decoded_data)
    }

    pub fn save_as_base64_encoded_file(data: Vec<u8>, filename: &str) -> Result<bool> {
        let mut file = File::create(filename)?;
        let encoded_data = base64::engine::general_purpose::STANDARD.encode(&data);
        file.write_all(encoded_data.as_bytes())?;
        Ok(true)
    }

    pub fn save_file(data: String, filename: &str) -> Result<bool> {
        let mut file = File::create(filename)?;
        file.write(&data.into_bytes())?;
        Ok(true)
    }
}

pub struct FileEncryptDecrypt {}

impl FileEncryptDecrypt {
    // one-shot hashing instead of Context API
    pub fn get_hash(file_content: &[u8]) -> Vec<u8> {
        let digest_value = digest::digest(&digest::SHA256, file_content);
        digest_value.as_ref().to_vec()
    }

    pub fn verify_hash(encrypted_file_content: &[u8], decrypted_file_content: &[u8]) -> bool {
        let decrypted_hash = FileEncryptDecrypt::get_hash(decrypted_file_content);
        let encrypted_hash = &encrypted_file_content[..32];
        println!("Decrypted hash: {:?}", hex::encode(&decrypted_hash));
        println!("Expected hash: {:?}", hex::encode(&encrypted_hash));
        decrypted_hash == encrypted_hash
    }

    pub fn encrypt<'a>(
        file_content: &'a mut Vec<u8>,
        password: String,
        public_key: &'a RsaPublicKey,
        mut os_rng: OsRng,
    ) -> Result<([u8; 12], &'a mut Vec<u8>, [u8; 32], Vec<u8>)> {
        let rng = SystemRandom::new(); // Random Number Generator

        // let mut encryption_key = [0u8; 32]; // Creating list of 256 bits of 0s (Encryption Key)
        // rng.fill(&mut encryption_key).unwrap(); // Generating Encryption key

        let mut salt = [0u8; 32]; // Creating list of 256 bits of 0s (Salt)
        rng.fill(&mut salt).unwrap(); // Generating salt

        let mut iv = [0u8; 12]; // Initialization Vector
        rng.fill(&mut iv).unwrap(); // Generating unique IV

        let nonce = Nonce::assume_unique_for_key(iv);
        let password_as_bytes = password.into_bytes();

        let mut encryption_key = [0u8; digest::SHA256_OUTPUT_LEN];

        println!("Generated salt snippet: {:?}", &salt[..6]);
        println!("Generated IV snippet: {:?}", iv);

        let non_zero_iterations = NonZeroU32::new(100_000).unwrap();
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            non_zero_iterations,
            &salt,
            &password_as_bytes,
            &mut encryption_key,
        );
        println!(
            "Derived encryption key snippet: {:?}",
            &encryption_key[..min(encryption_key.len(), 4)]
        );

        let encrypt_symmetric_key = public_key.encrypt(&mut os_rng, Pkcs1v15Encrypt, &encryption_key)?;

        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &encryption_key)
            .map_err(|e| anyhow!("Failed to create unbound key {}", e))?;

        let aead_key = LessSafeKey::new(unbound_key);

        aead_key
            .seal_in_place_append_tag(nonce, Aad::from(&[]), file_content)
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

        println!("Final encrypted data length: {}", file_content.len());

        Ok((iv, file_content, salt, encrypt_symmetric_key))
    }

    pub fn decrypt(file_content: &mut Vec<u8>, key: &[u8]) -> Result<String> {
        println!("File content length before decrypting: {}", file_content.len());

        let salt = &file_content[32..64];
        let iv = &file_content[64..76];

        println!("Extracted Salt snippet: {:?}", &salt[..6]);
        println!("Extracted IV snipped: {:?}", &iv);

        let mut encryption_key = [0u8; digest::SHA256_OUTPUT_LEN];

        let non_zero_iterations = NonZeroU32::new(100_000).unwrap();

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            non_zero_iterations,
            &salt,
            &key,
            &mut encryption_key,
        );

        println!(
            "Encryption key snippet: {:?}",
            &encryption_key[..min(encryption_key.len(), 4)]
        );

        let nonce = Nonce::assume_unique_for_key(iv.try_into()?);

        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &encryption_key)
            .map_err(|e| anyhow!("Failed to create unbound key: {:?}", e))?;

        let aead_key = LessSafeKey::new(unbound_key);

        println!("Data to decrypt length: {}", file_content[76..].len());
        println!("Data to decrypt snippet: {:?}", &file_content[76..88]);

        let decrypted_data = aead_key
            .open_in_place(nonce, Aad::empty(), &mut file_content[76..])
            .map_err(|e| anyhow!("Decryption failed: Issue with the key {}", e))?;

        let result = String::from_utf8(decrypted_data.to_vec())
            .map_err(|e| anyhow!("UTF-8 conversion failed: {:?}", e))?;

        Ok(result)
    }
}
