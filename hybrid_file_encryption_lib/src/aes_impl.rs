use anyhow::Result;

use crate::{FileEncryptDecrypt, FileIoOperation};

pub struct EncryptDecryptResult<'a> {
    pub(crate) iv: [u8; 12],
    pub(crate) cipher_text: &'a mut Vec<u8>,
    pub(crate) salt: [u8; 32],
    pub(crate) encrypted_symmetric_key: Option<Vec<u8>>,
}

pub fn aes_implementation(password: String, file_content_buffer: &mut Vec<u8>) -> Result<()> {
    // Hash value before encryption
    let before_encrypt_hash = FileEncryptDecrypt::get_hash(file_content_buffer.as_slice());
    println!("Hash before encryption: {:?}", hex::encode(&before_encrypt_hash));

    let result: EncryptDecryptResult = FileEncryptDecrypt::encrypt(file_content_buffer, password, None)?;
    let encrypted_symmetric_key = result.encrypted_symmetric_key.unwrap_or_default();

    let mut encrypted_data = Vec::new();

    // prepend length of all data
    let symmetric_key_len_bytes = (encrypted_symmetric_key.len() as u32).to_be_bytes();
    let hash_len_bytes = (before_encrypt_hash.len() as u32).to_be_bytes();
    let salt_len_bytes = (result.salt.len() as u32).to_be_bytes();
    let iv_len_bytes = (result.iv.len() as u32).to_be_bytes();

    // len of data - total 16 bytes
    encrypted_data.extend_from_slice(&symmetric_key_len_bytes); // 4 bytes of symmetric key
    encrypted_data.extend_from_slice(&hash_len_bytes); // 4 bytes of hash
    encrypted_data.extend_from_slice(&salt_len_bytes); // 4 bytes of salt
    encrypted_data.extend_from_slice(&iv_len_bytes); // 4 bytes of iv

    // prepend all data
    encrypted_data.extend_from_slice(&encrypted_symmetric_key);
    encrypted_data.extend_from_slice(&before_encrypt_hash);
    encrypted_data.extend_from_slice(&result.salt);
    encrypted_data.extend_from_slice(&result.iv);
    encrypted_data.extend_from_slice(&result.cipher_text);
    println!("File content length after encrypting: {}", encrypted_data.len());

    let after_encrypt_hash = FileEncryptDecrypt::get_hash(encrypted_data.as_slice());
    println!("Hash after encryption: {:?}", hex::encode(&after_encrypt_hash));

    if let Ok(_) = FileIoOperation::save_as_base64_encoded_file(encrypted_data, "encrypted.txt") {
        println!("File encrypted and saved as encrypted.txt");
    }

    Ok(())
}
