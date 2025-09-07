pub mod crypto;

use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};

use crate::crypto::crypto::CryptoTrait;
use crate::crypto::crypto_native::Crypt;

pub fn client() {
    println!("Client logic");
    let mut stream = TcpStream::connect("127.0.1.1:9090").unwrap();

    // Generate client key pair
    let (cli_pri, cli_pub) = Crypt::gen_x25519().unwrap();

    // Send the client's public key to the server
    stream.write(&cli_pub).unwrap();

    // Receive wrapped key, server's public key, and encrypted message
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();

    // Extract server's public key, wrapped key, and cipher text
    let server_pub = &buffer[0..32];
    let wrapped_key = &buffer[32..72];
    let cipher = &buffer[72..];

    // Unwrap the symmetric key using the client's private key
    let cli_kek_bytes: [u8; 32] = 
        Crypt::derive_x25519(&cli_pri, server_pub.try_into().unwrap())
        .unwrap().try_into().unwrap();
    let sym_key = Crypt::key_unwrap(&cli_kek_bytes, &wrapped_key[0..40].try_into().unwrap()).unwrap();

    // Decrypt the received message
    let iv = [0u8; 16];
    let plain = Crypt::aes_ctr_encrypt(&sym_key, &iv, cipher).unwrap();

    // Cut off garbage
    if let Some(pos) = String::from_utf8_lossy(&plain).find("[end]") {
        let message = &plain[..pos];
        println!("{:?}", String::from_utf8(message.to_vec()).unwrap());
    } else {
    // If no end tag just print including garbage
    println!("Client decrypted message: {:?}", String::from_utf8_lossy(&plain));
    }
}


pub fn server() {
    println!("Server logic");
    let listener = TcpListener::bind("127.0.1.1:9090").unwrap();

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                // Read the client's public key
                let mut buffer = [0; 32];
                stream.read(&mut buffer).unwrap();
                let cli_pub = buffer.to_vec();

                // Generate symmetric random key
                let sym_key = Crypt::sym_key_gen().unwrap();

                // Encrypt a message with the symmetric key
                let data = b"Pre-encrypted message[end]".to_vec();
                let iv = [0u8; 16];
                let cipher = Crypt::aes_ctr_encrypt(&sym_key, &iv, &data).unwrap();

                // Wrap the symmetric key
                let (ser_pri, ser_pub) = Crypt::gen_x25519().unwrap();
                let ser_kek_bytes: [u8; 32] = Crypt::derive_x25519(&ser_pri, &cli_pub.try_into().unwrap()).unwrap().try_into().unwrap();
                let wrapped = Crypt::key_upwrap(&ser_kek_bytes, &sym_key).unwrap();

                // Send server's public key, wrapped key, and encrypted message back to the client
                let response = [ser_pub.as_slice(), wrapped.as_slice(), cipher.as_slice()].concat();
                stream.write(&response).unwrap();
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}
