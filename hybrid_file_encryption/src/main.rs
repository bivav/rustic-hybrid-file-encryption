use std::fs::File;
use std::io::{stdin, Write};
use std::{env, fs};

use anyhow::{anyhow, Context, Result};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey, LineEnding};
use rsa::rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};

use file_encrypt_decrypt_aes::{Config, FileEncryptDecrypt};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let config: Config = Config::build(&args)?;

    let mut rng = OsRng;
    let bits = 2048;

    let private_key: RsaPrivateKey = RsaPrivateKey::new(&mut rng, bits)?;
    let public_key = RsaPublicKey::from(&private_key);

    let private_key_pem = private_key.to_pkcs1_pem(LineEnding::LF)?;
    let public_key_pem = public_key.to_pkcs1_pem(LineEnding::default())?;

    // println!("Private Key: {:?}", private_key_pem.to_string());
    // println!("Public Key: {:?}", public_key_pem.to_string());

    fs::create_dir_all("keys").context("Couldn't create directory: ")?;

    let mut private_file = File::create("keys/private_key.pem")?;
    private_file.write_all(&private_key_pem.as_bytes())?;
    let mut public_file = File::create("keys/public_key.pem")?;
    public_file.write_all(&public_key_pem.as_bytes())?;

    println!("Keys generated and saved in 'keys' directory");

    if config.command == "encrypt" {
        let mut file_content_buffer = Config::read_file(config)?;

        // Hash value before encryption
        let before_encrypt_hash = FileEncryptDecrypt::get_hash(file_content_buffer.as_slice());
        println!("Hash before encryption: {:?}", hex::encode(&before_encrypt_hash));

        println!("Enter a password to encrypt the file:");
        let mut password = String::new();
        stdin().read_line(&mut password).context("Input valid password")?;
        let password = password.trim().to_string();

        let (iv, cipher_text, salt, encrypted_symmetric_key) =
            FileEncryptDecrypt::encrypt(&mut file_content_buffer, password, &public_key, rng)?;

        let mut encrypted_data = Vec::new();

        // pre pend len of all data
        let symmetric_key_len_bytes = (encrypted_symmetric_key.len() as u32).to_be_bytes();
        let hash_len_bytes = (before_encrypt_hash.len() as u32).to_be_bytes();
        let salt_len_bytes = (salt.len() as u32).to_be_bytes();
        let iv_len_bytes = (iv.len() as u32).to_be_bytes();

        // prepend len of all of 16 bytes
        encrypted_data.extend_from_slice(&symmetric_key_len_bytes); // 4 bytes
        encrypted_data.extend_from_slice(&hash_len_bytes); // 4 bytes
        encrypted_data.extend_from_slice(&salt_len_bytes); // 4 bytes
        encrypted_data.extend_from_slice(&iv_len_bytes); // 4 bytes

        // prepend all data
        encrypted_data.extend_from_slice(&encrypted_symmetric_key);
        encrypted_data.extend_from_slice(&before_encrypt_hash);
        encrypted_data.extend_from_slice(&salt);
        encrypted_data.extend_from_slice(&iv);
        encrypted_data.extend_from_slice(&cipher_text);
        println!("File content length after encrypting: {}", encrypted_data.len());

        let after_encrypt_hash = FileEncryptDecrypt::get_hash(encrypted_data.as_slice());
        println!("Hash after encryption: {:?}", hex::encode(&after_encrypt_hash));

        let saved = Config::save_as_base64_encoded_file(encrypted_data, "encrypted.txt")?;
        if saved {
            println!("File encrypted as encrypted.txt");
        }
    } else if config.command == "decrypt" {
        // TODO: Think about how to handle the password and private key

        let password = rpassword::prompt_password("Enter your password: ").unwrap();
        if password.is_empty() {
            return Err(anyhow!("Invalid Password!"));
        }

        let mut file_content_as_buffer = Config::read_file_base64(config)?;
        let before_decryption_hash = FileEncryptDecrypt::get_hash(file_content_as_buffer.as_slice());
        let decrypted_text =
            FileEncryptDecrypt::decrypt(&mut file_content_as_buffer, password.trim().as_bytes())?;
        println!("Encrypted Hash: {:?}", hex::encode(before_decryption_hash));

        let verify =
            FileEncryptDecrypt::verify_hash(file_content_as_buffer.as_slice(), decrypted_text.as_bytes());
        if verify {
            println!("Hashes match!");
            let saved = Config::save_file(decrypted_text, "decrypted.txt")?;
            if saved {
                println!("File decrypted as decrypted.txt");
            } else {
                println!("Error saving file");
            }
        } else {
            println!("Hashes don't match! File is corrupted!");
        }
    } else {
        eprintln!("Error: Invalid command. Usage: cargo run -- [command] [file_path]");
        return Err(anyhow!("The [command] should be either 'encrypt' or 'decrypt', and [file_path] should be the path to the file you want to encrypt or decrypt"));
    }

    Ok(())
}
