use anyhow::Result;
use rsa::RsaPublicKey;

use crate::FileEncryptDecrypt;

pub struct EncryptDecryptResult<'a> {
    pub(crate) iv: [u8; 12],
    pub(crate) cipher_text: &'a mut Vec<u8>,
    pub(crate) salt: [u8; 32],
    pub(crate) rsa_encrypted_symmetric_key: Option<Vec<u8>>,
}

pub fn aes_encryption(
    file_content_buffer: &mut Vec<u8>,
    password: Option<String>,
    public_key: Option<RsaPublicKey>,
) -> Result<Vec<u8>> {
    // Hash value before encryption
    let before_encrypt_hash = FileEncryptDecrypt::get_hash(file_content_buffer.as_slice());
    println!("Hash before encryption: {:?}", hex::encode(&before_encrypt_hash));

    let result: EncryptDecryptResult =
        FileEncryptDecrypt::encrypt(file_content_buffer, password, public_key)?;
    let rsa_encrypted_symmetric_key = result.rsa_encrypted_symmetric_key.unwrap_or_default();

    let mut encrypted_data = Vec::new();

    // Length of all data as bytes
    let rsa_encrypted_key_len_bytes = (rsa_encrypted_symmetric_key.len() as u32).to_be_bytes();
    let hash_len_bytes = (before_encrypt_hash.len() as u32).to_be_bytes();
    let salt_len_bytes = (result.salt.len() as u32).to_be_bytes();
    let iv_len_bytes = (result.iv.len() as u32).to_be_bytes();

    // Prepend len of each data for better extraction = total 16 bytes
    // Extract these lengths in 'ORDER' during decryption which then can be used as indexes to extract the data
    // 4 bytes of rsa encrypted key, 4 bytes of hash, 4 bytes of salt, 4 bytes of iv
    encrypted_data.extend_from_slice(&rsa_encrypted_key_len_bytes); // 4 bytes of symmetric key
    encrypted_data.extend_from_slice(&hash_len_bytes); // 4 bytes of hash
    encrypted_data.extend_from_slice(&salt_len_bytes); // 4 bytes of salt
    encrypted_data.extend_from_slice(&iv_len_bytes); // 4 bytes of iv

    // Concatenate the data in the same order that was used to create the lengths above
    encrypted_data.extend_from_slice(&rsa_encrypted_symmetric_key);
    encrypted_data.extend_from_slice(&before_encrypt_hash);
    encrypted_data.extend_from_slice(&result.salt);
    encrypted_data.extend_from_slice(&result.iv);
    encrypted_data.extend_from_slice(&result.cipher_text);
    println!("File content length after encrypting: {}", encrypted_data.len());

    let after_encrypt_hash = FileEncryptDecrypt::get_hash(encrypted_data.as_slice());
    println!("Hash after encryption: {:?}", hex::encode(&after_encrypt_hash));

    Ok(encrypted_data)
}

pub fn aes_decryption(file_content_buffer: &mut Vec<u8>, password: String) -> Result<()> {
    // Hash value before decryption.
    // It should match with the hash value after encryption of the file
    let before_decryption_hash = FileEncryptDecrypt::get_hash(&file_content_buffer);
    println!("Encrypted Hash: {:?}", hex::encode(before_decryption_hash));

    let decrypted_text = FileEncryptDecrypt::decrypt(file_content_buffer, password.trim().as_bytes())?;

    println!("Decrypted text: {:?}", &decrypted_text);

    Ok(())
}
