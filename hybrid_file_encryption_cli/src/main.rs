use std::io::stdin;

use anyhow::{anyhow, Context, Result};
use clap::{Arg, Command};

use hybrid_file_encryption_lib::{aes_decryption, aes_encryption, FileIoOperation};

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
            Command::new("decrypt").about("Decrypts a file").arg(
                Arg::new("file path")
                    .help("The file to decrypt")
                    .required(true)
                    .index(1),
            ),
        )
        .arg_required_else_help(true)
        .get_matches();

    match matches.subcommand() {
        Some(("encrypt", sub_matches)) => {
            let config = FileIoOperation::from_matches(sub_matches);
            let input = get_input("Encryption")?;

            match input {
                1 => {
                    // Encrypt using AES
                    let mut file_content_buffer = FileIoOperation::read_file(config)?;

                    println!("Enter a password to encrypt the file:");
                    let mut password = String::new();
                    stdin().read_line(&mut password).context("Input valid password")?;
                    let password = password.trim().to_string();

                    aes_encryption(password, &mut file_content_buffer).context("AES encryption failed")?;
                }
                2 => {
                    // Generate RSA keys
                    unimplemented!("RSA encryption not implemented yet")
                }
                3 => {
                    // Encrypt using RSA and AES
                    unimplemented!("Hybrid encryption not implemented yet")
                }
                _ => {
                    return Err(anyhow!("Invalid option"));
                }
            }
        }
        Some(("decrypt", sub_matches)) => {
            let config = FileIoOperation::from_matches(sub_matches);

            let input = get_input("Decryption")?;

            match input {
                1 => {

                    // TODO: Think about how to handle the password and private key

                    // Decrypt using AES
                    let password = rpassword::prompt_password("Enter your password: ").unwrap();
                    if password.is_empty() {
                        return Err(anyhow!("Invalid Password!"));
                    }

                    let mut file_content_as_buffer = FileIoOperation::read_file_base64(config)?;

                    aes_decryption(&mut file_content_as_buffer, password).context("AES decryption failed")?;
                }
                2 => {
                    // Generate RSA keys
                    unimplemented!("RSA encryption not implemented yet")
                }
                3 => {
                    // Decrypt using RSA and AES
                    unimplemented!("Hybrid encryption not implemented yet")
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

    println!("You chose: {}", input);
    Ok(input)
}
