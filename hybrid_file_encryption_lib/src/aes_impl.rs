use anyhow::Result;

use crate::{FileEncryptDecrypt, FileIoOperation};

pub fn aes_implementation(password: String, file_content_buffer: &mut Vec<u8>) -> Result<()> {
    // Hash value before encryption
    let before_encrypt_hash = FileEncryptDecrypt::get_hash(file_content_buffer.as_slice());
    println!("Hash before encryption: {:?}", hex::encode(&before_encrypt_hash));

    let (
        iv,
        cipher_text,
        salt, // , encrypted_symmetric_key
    ) = FileEncryptDecrypt::encrypt(file_content_buffer, password)?;

    let mut encrypted_data = Vec::new();

    // prepend length of all data
    // let symmetric_key_len_bytes = (encrypted_symmetric_key.len() as u32).to_be_bytes();
    let hash_len_bytes = (before_encrypt_hash.len() as u32).to_be_bytes();
    let salt_len_bytes = (salt.len() as u32).to_be_bytes();
    let iv_len_bytes = (iv.len() as u32).to_be_bytes();

    // prepend len of all of 16 bytes
    // encrypted_data.extend_from_slice(&symmetric_key_len_bytes); // 4 bytes
    encrypted_data.extend_from_slice(&hash_len_bytes); // 4 bytes
    encrypted_data.extend_from_slice(&salt_len_bytes); // 4 bytes
    encrypted_data.extend_from_slice(&iv_len_bytes); // 4 bytes

    // prepend all data
    // encrypted_data.extend_from_slice(&encrypted_symmetric_key);
    encrypted_data.extend_from_slice(&before_encrypt_hash);
    encrypted_data.extend_from_slice(&salt);
    encrypted_data.extend_from_slice(&iv);
    encrypted_data.extend_from_slice(&cipher_text);
    println!("File content length after encrypting: {}", encrypted_data.len());

    let after_encrypt_hash = FileEncryptDecrypt::get_hash(encrypted_data.as_slice());
    println!("Hash after encryption: {:?}", hex::encode(&after_encrypt_hash));

    if let Ok(_) = FileIoOperation::save_as_base64_encoded_file(encrypted_data, "encrypted.txt") {
        println!("File encrypted as encrypted.txt");
    }

    Ok(())
}
