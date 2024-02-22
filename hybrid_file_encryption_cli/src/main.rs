use std::io::stdin;

use anyhow::{anyhow, Context, Result};
use clap::{Arg, Command};

use hybrid_file_encryption_lib::{FileIoOperation, FileEncryptDecrypt, rsa_implementation, aes_implementation};

const APP_NAME: &str = "Hybrid File Encryption";
const VERSION: &str = "0.1.0";
const APP_ABOUT: &str =
    "This CLI tool allows you to encrypt and decrypt files using a hybrid encryption scheme. \
            Please specify a subcommand ('encrypt' or 'decrypt') followed by the filename.";
const AUTHOR: &str = "Bivav R Satyal";

fn main() -> Result<()> {
    let matches = Command::new(APP_NAME)
        .version(VERSION)
        .long_about(APP_ABOUT)
        .author(AUTHOR)
        .subcommand(
            Command::new("encrypt").about("Encrypts a file").arg(
                Arg::new("file")
                    .help("The file to encrypt")
                    .required(true)
                    .index(1),
            ),
        )
        .subcommand(
            Command::new("decrypt").about("Decrypts a file").arg(
                Arg::new("file")
                    .help("The file to decrypt")
                    .required(true)
                    .index(1),
            ),
        )
        .arg_required_else_help(true)
        .get_matches();

    // Ask for user input if they want to encrypt using RSA or AES (password) or both (hybrid)
    let mut input = String::new();
    println!("What do you want to use for encryption?");
    println!("1. RSA (Public Key)");
    println!("2. AES (Password using KDF - PBKDF2)");
    println!("3. Hybrid (RSA + AES)");
    stdin().read_line(&mut input).context("Input valid option")?;
    let input = input.trim().parse::<u32>().context("Input valid option")?;

    println!("You chose: {}", input);

    match input {
        1 => {
            // Generate RSA keys
            unimplemented!("RSA encryption not implemented yet")
            // rsa_implementation()?
        }
        2 => {
            // Encrypt using AES
        }
        3 => {
            // Encrypt using RSA and AES
            unimplemented!("Hybrid encryption not implemented yet")
        }
        _ => {
            return Err(anyhow!("Invalid option"));
        }
    }

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let config = FileIoOperation::from_matches(sub_matches);

            let mut file_content_buffer = FileIoOperation::read_file(config)?;

            println!("Enter a password to encrypt the file:");
            let mut password = String::new();
            stdin().read_line(&mut password).context("Input valid password")?;
            let password = password.trim().to_string();
            
            
            let aes_temp = aes_implementation(password, &mut file_content_buffer);
            

            // // Hash value before encryption
            // let before_encrypt_hash = FileEncryptDecrypt::get_hash(file_content_buffer.as_slice());
            // println!("Hash before encryption: {:?}", hex::encode(&before_encrypt_hash));
            // 
            // let (iv, cipher_text, salt, encrypted_symmetric_key) =
            //     FileEncryptDecrypt::encrypt(&mut file_content_buffer, password, &public_key, rng)?;
            // 
            // let mut encrypted_data = Vec::new();
            // 
            // // prepend length of all data
            // let symmetric_key_len_bytes = (encrypted_symmetric_key.len() as u32).to_be_bytes();
            // let hash_len_bytes = (before_encrypt_hash.len() as u32).to_be_bytes();
            // let salt_len_bytes = (salt.len() as u32).to_be_bytes();
            // let iv_len_bytes = (iv.len() as u32).to_be_bytes();
            // 
            // // prepend len of all of 16 bytes
            // encrypted_data.extend_from_slice(&symmetric_key_len_bytes); // 4 bytes
            // encrypted_data.extend_from_slice(&hash_len_bytes); // 4 bytes
            // encrypted_data.extend_from_slice(&salt_len_bytes); // 4 bytes
            // encrypted_data.extend_from_slice(&iv_len_bytes); // 4 bytes
            // 
            // // prepend all data
            // encrypted_data.extend_from_slice(&encrypted_symmetric_key);
            // encrypted_data.extend_from_slice(&before_encrypt_hash);
            // encrypted_data.extend_from_slice(&salt);
            // encrypted_data.extend_from_slice(&iv);
            // encrypted_data.extend_from_slice(&cipher_text);
            // println!("File content length after encrypting: {}", encrypted_data.len());
            // 
            // let after_encrypt_hash = FileEncryptDecrypt::get_hash(encrypted_data.as_slice());
            // println!("Hash after encryption: {:?}", hex::encode(&after_encrypt_hash));
            // 
            // let saved = FileIoOperation::save_as_base64_encoded_file(encrypted_data, "encrypted.txt")?;
            // if saved {
            //     println!("File encrypted as encrypted.txt");
            // }
        }
        Some(("decrypt", sub_matches)) => {
            let config = FileIoOperation::from_matches(sub_matches);
            // println!("{:?}", config.file_path);

            // TODO: Think about how to handle the password and private key

            let password = rpassword::prompt_password("Enter your password: ").unwrap();
            if password.is_empty() {
                return Err(anyhow!("Invalid Password!"));
            }

            let mut file_content_as_buffer = FileIoOperation::read_file_base64(config)?;
            let before_decryption_hash = FileEncryptDecrypt::get_hash(file_content_as_buffer.as_slice());
            let decrypted_text =
                FileEncryptDecrypt::decrypt(&mut file_content_as_buffer, password.trim().as_bytes())?;
            println!("Encrypted Hash: {:?}", hex::encode(before_decryption_hash));

            let verify =
                FileEncryptDecrypt::verify_hash(file_content_as_buffer.as_slice(), decrypted_text.as_bytes());
            if verify {
                println!("Hashes match!");
                let saved = FileIoOperation::save_file(decrypted_text, "decrypted.txt")?;
                if saved {
                    println!("File decrypted as decrypted.txt");
                } else {
                    println!("Error saving file");
                }
            } else {
                println!("Hashes don't match! File is corrupted!");
            }
        }
        _ => unreachable!("Invalid subcommand"),
    }
    //
    // if config.command == "encrypt" {
    //     let mut file_content_buffer = Configs::read_file(config)?;
    //
    //     // Hash value before encryption
    //     let before_encrypt_hash = FileEncryptDecrypt::get_hash(file_content_buffer.as_slice());
    //     println!("Hash before encryption: {:?}", hex::encode(&before_encrypt_hash));
    //
    //     println!("Enter a password to encrypt the file:");
    //     let mut password = String::new();
    //     stdin().read_line(&mut password).context("Input valid password")?;
    //     let password = password.trim().to_string();
    //
    //     let (iv, cipher_text, salt, encrypted_symmetric_key) =
    //         FileEncryptDecrypt::encrypt(&mut file_content_buffer, password, &public_key, rng)?;
    //
    //     let mut encrypted_data = Vec::new();
    //
    //     // pre pend len of all data
    //     let symmetric_key_len_bytes = (encrypted_symmetric_key.len() as u32).to_be_bytes();
    //     let hash_len_bytes = (before_encrypt_hash.len() as u32).to_be_bytes();
    //     let salt_len_bytes = (salt.len() as u32).to_be_bytes();
    //     let iv_len_bytes = (iv.len() as u32).to_be_bytes();
    //
    //     // prepend len of all of 16 bytes
    //     encrypted_data.extend_from_slice(&symmetric_key_len_bytes); // 4 bytes
    //     encrypted_data.extend_from_slice(&hash_len_bytes); // 4 bytes
    //     encrypted_data.extend_from_slice(&salt_len_bytes); // 4 bytes
    //     encrypted_data.extend_from_slice(&iv_len_bytes); // 4 bytes
    //
    //     // prepend all data
    //     encrypted_data.extend_from_slice(&encrypted_symmetric_key);
    //     encrypted_data.extend_from_slice(&before_encrypt_hash);
    //     encrypted_data.extend_from_slice(&salt);
    //     encrypted_data.extend_from_slice(&iv);
    //     encrypted_data.extend_from_slice(&cipher_text);
    //     println!("File content length after encrypting: {}", encrypted_data.len());
    //
    //     let after_encrypt_hash = FileEncryptDecrypt::get_hash(encrypted_data.as_slice());
    //     println!("Hash after encryption: {:?}", hex::encode(&after_encrypt_hash));
    //
    //     let saved = Configs::save_as_base64_encoded_file(encrypted_data, "encrypted.txt")?;
    //     if saved {
    //         println!("File encrypted as encrypted.txt");
    //     }
    // } else if config.command == "decrypt" {
    //     // TODO: Think about how to handle the password and private key
    //
    //     let password = rpassword::prompt_password("Enter your password: ").unwrap();
    //     if password.is_empty() {
    //         return Err(anyhow!("Invalid Password!"));
    //     }
    //
    //     let mut file_content_as_buffer = Configs::read_file_base64(config)?;
    //     let before_decryption_hash = FileEncryptDecrypt::get_hash(file_content_as_buffer.as_slice());
    //     let decrypted_text =
    //         FileEncryptDecrypt::decrypt(&mut file_content_as_buffer, password.trim().as_bytes())?;
    //     println!("Encrypted Hash: {:?}", hex::encode(before_decryption_hash));
    //
    //     let verify =
    //         FileEncryptDecrypt::verify_hash(file_content_as_buffer.as_slice(), decrypted_text.as_bytes());
    //     if verify {
    //         println!("Hashes match!");
    //         let saved = Configs::save_file(decrypted_text, "decrypted.txt")?;
    //         if saved {
    //             println!("File decrypted as decrypted.txt");
    //         } else {
    //             println!("Error saving file");
    //         }
    //     } else {
    //         println!("Hashes don't match! File is corrupted!");
    //     }
    // } else {
    //     eprintln!("Error: Invalid command. Usage: cargo run -- [command] [file_path]");
    //     return Err(anyhow!("The [command] should be either 'encrypt' or 'decrypt', and [file_path] should be the path to the file you want to encrypt or decrypt"));
    // }

    Ok(())
}
