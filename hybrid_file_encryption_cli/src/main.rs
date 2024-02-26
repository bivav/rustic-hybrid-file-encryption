use std::io::stdin;
use std::process::exit;

use anyhow::{anyhow, Context, Result};
use clap::{Arg, Command};
use rsa::rand_core::OsRng;
use rsa::Pkcs1v15Encrypt;

use hybrid_file_encryption_lib::{aes_decryption, aes_encryption, rsa_implementation, FileIoOperation};

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
                Arg::new("file path")
                    .help("The file to encrypt")
                    .required(true)
                    .index(1),
            ),
        )
        .subcommand(
            Command::new("decrypt")
                .about("Decrypts a file")
                .arg(
                    Arg::new("file path")
                        .help("The file to decrypt")
                        .required(true)
                        .index(1),
                )
                .arg(
                    // Optional argument for the private key file
                    Arg::new("key")
                        .short('k')
                        .long("key")
                        .help("The private key file for RSA decryption")
                        .required(false),
                ),
        )
        .arg_required_else_help(true)
        .get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let config = FileIoOperation::from_matches("encrypt", sub_matches);
            let input = get_input("Encryption")?;

            match input {
                1 => {
                    println!("\nEncrypting using AES..");
                    // Encrypt using AES
                    let mut file_content_buffer = FileIoOperation::read_file(config)?;

                    println!("Enter a password to encrypt the file:");
                    let mut password = String::new();
                    stdin().read_line(&mut password).context("Input valid password")?;
                    let password = password.trim().to_string();

                    let encrypted = aes_encryption(&mut file_content_buffer, Option::from(password), None)
                        .context("AES encryption failed")?;

                    if let Ok(_) = FileIoOperation::save_as_base64_encoded(encrypted, "encrypted.txt") {
                        println!("File encrypted and saved as encrypted.txt");
                    }
                }
                2 => {
                    // Generate RSA keys
                    println!("\nEncrypting using RSA..");
                    let mut rng = OsRng;
                    let file_content_buffer = FileIoOperation::read_file(config)?;

                    let (_, pub_key) = rsa_implementation().context("RSA key generation failed")?;

                    let encrypted_data = pub_key
                        .encrypt(&mut rng, Pkcs1v15Encrypt, &file_content_buffer)
                        .context("RSA encryption failed")?;

                    println!("Length of encryption {:?}", &encrypted_data.len());

                    // save the encrypted data to a file
                    if let Ok(_) =
                        FileIoOperation::save_as_base64_encoded(encrypted_data, "rsa_encrypted.txt")
                    {
                        println!("File encrypted and saved as rsa_encrypted.txt");
                    }
                }
                3 => {
                    // Encrypt using AES and then RSA
                    println!("Encrypting using AES and then RSA..");
                    let mut file_content_buffer = FileIoOperation::read_file(config)?;

                    let (_, pub_key) = rsa_implementation().context("RSA key generation failed")?;

                    let encrypted_data =
                        aes_encryption(&mut file_content_buffer, None, Option::from(pub_key.clone()))
                            .context("AES encryption failed")?;

                    // save the encrypted data to a file
                    if let Ok(_) =
                        FileIoOperation::save_as_base64_encoded(encrypted_data, "aes_rsa_encrypted.txt")
                    {
                        println!("File encrypted and saved as aes_rsa_encrypted.txt");
                    }
                }
                _ => {
                    return Err(anyhow!("Invalid option"));
                }
            }
        }
        Some(("decrypt", sub_matches)) => {
            let config = FileIoOperation::from_matches("decrypt", sub_matches);

            let input = get_input("Decryption")?;

            match input {
                1 => {
                    // Decrypt using AES
                    println!(
                        "Decrypting '{}' using AES using password method..",
                        config.file_path
                    );

                    let password = rpassword::prompt_password("Enter your password: ").unwrap();
                    if password.is_empty() {
                        return Err(anyhow!("Invalid Password!"));
                    }

                    let mut file_content_as_buffer = FileIoOperation::read_file_base64(config)?;

                    aes_decryption(
                        &mut file_content_as_buffer,
                        Option::from(password.trim().as_bytes()),
                        None,
                    )
                    .context("AES decryption failed")?;
                }
                2 => {
                    if config.key == "default" {
                        eprintln!(
                            "Error: Please provide a private key file for RSA decryption.\nUse the -k option."
                        );
                        exit(1);
                    } else {
                        println!(
                            "Decrypting '{}' using RSA with private key '{}'",
                            config.file_path, config.key
                        );
                        let private_key = FileIoOperation::read_pri_key(&config)?;

                        let file_content_as_buffer = FileIoOperation::read_file_base64(config)?;

                        let decrypted_data = private_key
                            .decrypt(Pkcs1v15Encrypt, &file_content_as_buffer)
                            .context("RSA decryption failed")?;

                        println!("Decrypted Data: {:?}\n", String::from_utf8_lossy(&decrypted_data),);
                    }
                }
                3 => {
                    // Decrypt using RSA and AES

                    if config.key == "default" {
                        eprintln!(
                            "Error: Please provide a private key file for RSA decryption.\nUse the -k option."
                        );
                        exit(1);
                    } else {
                        println!(
                            "Decrypting '{}' using RSA with private key '{}'",
                            config.file_path, config.key
                        );

                        let private_key = FileIoOperation::read_pri_key(&config)?;

                        let mut file_content_as_buffer = FileIoOperation::read_file_base64(config)?;

                        aes_decryption(&mut file_content_as_buffer, None, Option::from(private_key))
                            .context("AES decryption failed")?;
                    }
                }
                _ => {
                    return Err(anyhow!("Invalid option"));
                }
            }
        }
        _ => unreachable!("Invalid subcommand"),
    }

    Ok(())
}

fn get_input(method: &str) -> Result<u32> {
    // Ask for user input if they want to encrypt or decrypt using RSA or AES (password) or both (hybrid)
    let mut input = String::new();
    println!("What do you want to use for {method}?");
    println!("1. {method} using AES (Password using KDF - PBKDF2)");
    println!("2. {method} using RSA (Public Key)");
    println!("3. {method} using Hybrid (RSA + AES)");
    stdin().read_line(&mut input).context("Input valid option")?;
    let input = input.trim().parse::<u32>().context("Input valid option")?;

    Ok(input)
}
