### File Encryption and Decryption using AES and Hash Function Utility (SHA256)
___

### File Encrypt Decrypt AES

This is a Rust project that provides functionality for file encryption and decryption using AES (Advanced Encryption
Standard) with a 256-bit key.

### Usage

From the root directory, you can run the program with the following command:

```
cargo run -- [command] [file_path]

The [command] should be either "encrypt" or "decrypt", and [file_path] should be the path to the file you want to encrypt or decrypt.
```

The `file_encrypt_decrypt_aes` workspace is a Rust project that provides functionality for file encryption and
decryption using AES (Advanced Encryption Standard) with a 256-bit key. It contains two main files: `main.rs`
and `lib.rs` located in the `src` directory.

The `main.rs` file contains the main function that drives the program. It reads command-line arguments to determine
whether to encrypt or decrypt a file. If the command is "encrypt", it reads the file, generates a **hash** of the file
content, asks the user for a password, and then encrypts the file content using the password. The encrypted data, along
with the hash, salt, and initialization vector (IV), are then saved to a new file in base64 format. If the command is "
decrypt", it asks the user for a password, reads the encrypted file, and then decrypts the file content using the
password. It also verifies the hash of the decrypted content against the hash stored in the encrypted file to ensure the
integrity of the data.

The `lib.rs` file contains the definition of the `Config` struct and the `FileEncryptDecrypt` struct. The `Config`
struct is used to parse and store the command-line arguments. It also provides methods for reading a file, reading a
base64 encoded file, saving data to a file in base64 format, and saving a string to a file. The `FileEncryptDecrypt`
struct provides methods for hashing file content, verifying a hash, encrypting file content, and decrypting file
content.

The `Cargo.toml` file in the root directory of the workspace specifies the dependencies of the project, which include
the `ring` crate for cryptographic operations, the `hex` crate for encoding and decoding hexadecimal strings,
the `base64` crate for encoding and decoding base64 strings, and the `rpassword` crate for securely reading passwords
from the standard input.

### Dependencies

The project uses the following crates:

- `ring` for cryptographic operations
- `hex` for encoding and decoding hexadecimal strings
- `base64` for encoding and decoding base64 strings
- `rpassword` for securely reading passwords from the standard input
