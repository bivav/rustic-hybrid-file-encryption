use std::cmp::min;
use std::fs;
use std::fs::File;
use std::io::{Read, Write};
use std::num::NonZeroU32;
use std::process::exit;

use anyhow::{anyhow, Result};
use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, digest, pbkdf2};
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::rand_core::OsRng;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

pub use aes_impl::*;
pub use rsa_impl::*;

mod aes_impl;
mod rsa_impl;

pub struct FileIoOperation {
    pub key: String,
    pub file_path: String,
}

impl FileIoOperation {
    pub fn from_matches(command: &str, matches: &clap::ArgMatches) -> Self {
        let file_path = matches.get_one::<String>("file path").unwrap().to_string();

        if command == "encrypt" {
            return Self {
                key: "default".to_string(),
                file_path,
            };
        } else {
            let key = if let Some(key_path) = matches.get_one::<String>("key") {
                key_path
            } else {
                "default"
            };

            Self {
                key: key.to_string(),
                file_path,
            }
        }
    }

    pub fn read_file(config: FileIoOperation) -> Result<Vec<u8>> {
        let mut file = File::open(config.file_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;
        Ok(buffer)
    }

    pub fn read_file_base64(config: FileIoOperation) -> Result<Vec<u8>> {
        let file_content = fs::read_to_string(config.file_path)?;

        let decoded_data = base64::engine::general_purpose::STANDARD
            .decode(&file_content)
            .unwrap_or_else(|e| {
                println!("Decoding Error: {:?}\nAre you sure it's the encrypted file?", e);
                exit(1);
            });

        Ok(decoded_data)
    }

    pub fn read_pri_key(config: &FileIoOperation) -> Result<RsaPrivateKey> {
        let file_content = fs::read_to_string(&config.key)?;

        let private_key = RsaPrivateKey::from_pkcs1_pem(&file_content)?;

        Ok(private_key)
    }

    pub fn save_as_base64_encoded(data: Vec<u8>, filename: &str) -> Result<()> {
        let mut file = File::create(filename)?;
        let encoded_data = base64::engine::general_purpose::STANDARD.encode(&data);
        file.write_all(encoded_data.as_bytes())?;
        Ok(())
    }

    pub fn save_file(data: &String, filename: &str) -> Result<()> {
        let mut file = File::create(filename)?;
        file.write(data.as_bytes())?;
        Ok(())
    }
}

pub struct FileEncryptDecrypt {}

impl FileEncryptDecrypt {
    // one-shot hashing instead of Context API
    pub fn get_hash(file_content: &[u8]) -> Vec<u8> {
        let digest_value = digest::digest(&digest::SHA256, file_content);
        digest_value.as_ref().to_vec()
    }

    pub fn verify_hash(
        encrypted_content: &[u8],
        decrypted_content: &[u8],
        hash_start: usize,
        hash_len: usize,
    ) -> Result<bool> {
        let decrypted_hash = FileEncryptDecrypt::get_hash(decrypted_content);
        let encrypted_hash = &encrypted_content[hash_start..hash_start + hash_len];
        println!("Decrypted hash: {:?}", hex::encode(&decrypted_hash));
        println!("Expected hash: {:?}", hex::encode(&encrypted_hash));
        Ok(decrypted_hash == encrypted_hash)
    }

    pub fn encrypt(
        file_content: &mut Vec<u8>,
        password: Option<String>,
        public_key: Option<RsaPublicKey>,
    ) -> Result<EncryptDecryptResult> {
        // Used for encryption using public key
        let mut os_rng = OsRng;

        // Used for generating random values for AES encryption
        let rng = SystemRandom::new();

        let mut salt = [0u8; 32]; // Creating list of 256 bits of 0s (Salt)
        rng.fill(&mut salt).unwrap(); // Generating salt

        let mut iv = [0u8; 12]; // Initialization Vector
        rng.fill(&mut iv).unwrap(); // Generating unique IV

        let nonce = Nonce::assume_unique_for_key(iv);

        // let mut password_as_bytes = None;

        let password_as_bytes = match password {
            Some(pass_key) => {
                println!("Password provided. Generating encryption key..");
                println!("Password: {:?}", pass_key);
                pass_key.into_bytes()
            }
            None => {
                println!("No password required. Generating encryption key..");
                let mut encryption_key = [0u8; 32]; // Creating list of 256 bits of 0s (Encryption Key)
                rng.fill(&mut encryption_key).unwrap(); // Generating Encryption key
                encryption_key.to_vec()
            }
        };

        // let mut password_slice: &[u8] = &[];

        // if let Some(ref vec) = password_as_bytes {
        //     password_slice = vec.as_slice();
        // }

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

        let mut rsa_encrypted_symmetric_key = None;

        if let Some(pub_key) = public_key {
            let encrypted_key = pub_key.encrypt(&mut os_rng, Pkcs1v15Encrypt, &encryption_key)?;
            rsa_encrypted_symmetric_key = Some(encrypted_key);
        }

        println!(
            "\nRSA encrypted symmetric key: {:?}\n",
            rsa_encrypted_symmetric_key
        );

        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &encryption_key)
            .map_err(|e| anyhow!("Failed to create unbound key {}", e))?;

        let aead_key = LessSafeKey::new(unbound_key);

        aead_key
            .seal_in_place_append_tag(nonce, Aad::from(&[]), file_content)
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;

        println!("Final encrypted data length: {}", file_content.len());

        Ok(EncryptDecryptResult {
            iv,
            cipher_text: file_content,
            salt,
            rsa_encrypted_symmetric_key,
        })
    }

    pub fn decrypt(file_content: &mut Vec<u8>, user_password: &[u8]) -> Result<String> {
        println!("File content length before decrypting: {}", file_content.len());

        // First 4 bytes of symmetric key, then 4 bytes of hash, then 4 bytes of salt, then 4 bytes of iv then the cipher text
        let rsa_encrypted_key_len = u32::from_be_bytes(file_content[..4].try_into()?) as usize;
        let hash_len = u32::from_be_bytes(file_content[4..8].try_into()?) as usize;
        let salt_len = u32::from_be_bytes(file_content[8..12].try_into()?) as usize;
        let iv_len = u32::from_be_bytes(file_content[12..16].try_into()?) as usize;

        let rsa_encrypted_key_start = 16;
        let hash_start = rsa_encrypted_key_start + rsa_encrypted_key_len;
        let salt_start = hash_start + hash_len;
        let iv_start = salt_start + salt_len;
        let cipher_text_start = iv_start + iv_len;

        let salt = &file_content[salt_start..iv_start];
        let iv = &file_content[iv_start..cipher_text_start];

        let mut cipher_data = &mut file_content[cipher_text_start..].to_vec();

        println!("Extracted Salt snippet: {:?}", &salt[..6]);
        println!("Extracted IV snipped: {:?}", &iv);

        let mut encryption_key = [0u8; digest::SHA256_OUTPUT_LEN];

        let non_zero_iterations = NonZeroU32::new(100_000).unwrap();

        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            non_zero_iterations,
            &salt,
            &user_password,
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

        println!("Data to decrypt length: {}", &cipher_data.len());
        println!("Data to decrypt snippet: {:?}", &cipher_data);

        let decrypted_data = aead_key
            .open_in_place(nonce, Aad::empty(), &mut cipher_data)
            .map_err(|e| anyhow!("Decryption failed: Issue with the key {}", e))?;

        let result = String::from_utf8(decrypted_data.to_vec())
            .map_err(|e| anyhow!("UTF-8 conversion failed: {:?}", e))?;

        if let Ok(verify) =
            FileEncryptDecrypt::verify_hash(&file_content, result.as_bytes(), hash_start, hash_len)
        {
            if verify {
                println!("Hashes match!");
                if let Ok(_) = FileIoOperation::save_file(&result, "decrypted.txt") {
                    println!("File decrypted as decrypted.txt")
                } else {
                    println!("Error saving file")
                }
            } else {
                println!("Hashes don't match! File is corrupted!")
            }
        }

        Ok(result)
    }
}
