use std::net::{TcpListener, TcpStream};
use std::io::{Read, Write};

use zeroize::Zeroize;

pub mod crypto;
use crate::crypto::crypto::CryptoTrait;
use crate::crypto::crypto_native::Crypt;

pub async fn client() {
    println!("Client logic");
    let cry = Crypt::new(b"Client".to_vec());
    let mut stream = TcpStream::connect("127.0.1.1:9090").unwrap();

    // Receive servers's public key, and (non-encrypted) message
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();

    // Extract server's public key, wrapped key, and cipher text...
    let ser_sig_pub = &buffer[0..44];
    let ser_sig = &buffer[44..108];
    let data = &buffer[108..];



    // Cut off garbage
    if let Some(pos) = String::from_utf8_lossy(&data).find("[end]") {
        let message = &data[..pos + 5];


        // Verify signature
        let ver = cry.ver_ed25519(&ser_sig_pub.to_vec(), ser_sig.try_into().unwrap(), &message.to_vec()).await.unwrap();
        println!("{:?}", ver);

        println!("{:?}", String::from_utf8(message.to_vec()).unwrap());
    } else {
        //
    // If no end tag just print including garbage
    println!("Client decrypted message: {:?}", String::from_utf8_lossy(&data));
    }
}


pub async fn server() {
    println!("Server logic");
    let cry = Crypt::new(b"Server".to_vec());

    // Generate signature key
    let (pub_key, pri_key) = cry.gen_ed25519().await.unwrap();

    // Encrypt a message with the symmetric key
    let data = b"Pre-encrypted message[end]".to_vec();

    // Wait for connection
    let listener = TcpListener::bind("127.0.1.1:9090").unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                //
                // Sign ephemeral public key
                let sig = cry.sig_ed25519(&pri_key, &data.to_vec()).await.unwrap();

                // Send server's ephemeral public key, wrapped key, and encrypted message back to the client
                let response = [
                    pub_key.as_slice(),
                    sig.as_slice(),
                    data.as_slice()
                ]
                .concat();

                stream.write(&response).unwrap();
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

pub async fn sig_cry_client() {
    println!("Client logic");
    let cry = Crypt::new(b"Client".to_vec());
    let mut stream = TcpStream::connect("127.0.1.1:9090").unwrap();

    // Generate client key pair
    let (cli_pri, cli_pub) = Crypt::gen_x25519().unwrap();

    // Send the client's public key to the server
    stream.write(&cli_pub).unwrap();

    // Receive wrapped key, server's public key, and encrypted message
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();

    // Extract server's public key, wrapped key, and cipher text...
    let ser_sig_pub = &buffer[0..44];
    let ser_sig = &buffer[44..108];
    let server_pub = &buffer[108..140];
    let wrapped_key = &buffer[140..180];
    let cipher = &buffer[180..];


    // Verify signature
    let ver = cry.ver_ed25519(&ser_sig_pub.to_vec(), ser_sig.try_into().unwrap(), &server_pub.to_vec()).await.unwrap();

    println!("{:?}", ver);

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


pub async fn sig_cry_server() {
    println!("Server logic");
    let cry = Crypt::new(b"Server".to_vec());

    // Generate signature key
    let (pub_key, pri_key) = cry.gen_ed25519().await.unwrap();

    // Generate symmetric random key
    let sym_key = Crypt::sym_key_gen().unwrap();

    // Encrypt a message with the symmetric key
    let data = b"Pre-encrypted message[end]".to_vec();
    let iv = [0u8; 16];
    let cipher = Crypt::aes_ctr_encrypt(&sym_key, &iv, &data).unwrap();


    // Wait for connection
    let listener = TcpListener::bind("127.0.1.1:9090").unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                // Receive the client's public key
                let mut buffer = [0; 32];
                stream.read(&mut buffer).unwrap();
                let cli_pub = buffer.to_vec();

                // Wrap the symmetric key
                let (mut ser_pri, ser_pub) = Crypt::gen_x25519().unwrap();
                let ser_kek_bytes: [u8; 32] = Crypt::derive_x25519(&ser_pri, &cli_pub.try_into().unwrap()).unwrap().try_into().unwrap();
                let wrapped = Crypt::key_upwrap(&ser_kek_bytes, &sym_key).unwrap();

                // Zeroize ephemeral key (at least the private one...)
                ser_pri.zeroize();

                // Sign ephemeral public key
                let sig = cry.sig_ed25519(&pri_key, &ser_pub.to_vec()).await.unwrap();

                // Send server's ephemeral public key, wrapped key, and encrypted message back to the client
                let response = [
                    pub_key.as_slice(),
                    sig.as_slice(),
                    ser_pub.as_slice(), 
                    wrapped.as_slice(), 
                    cipher.as_slice()
                ]
                .concat();

                stream.write(&response).unwrap();
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}

pub fn crypto_client() {
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


pub fn crypto_server() {
    println!("Server logic");
    // Generate symmetric random key
    let sym_key = Crypt::sym_key_gen().unwrap();

    // Encrypt a message with the symmetric key
    let data = b"Pre-encrypted message[end]".to_vec();
    let iv = [0u8; 16];
    let cipher = Crypt::aes_ctr_encrypt(&sym_key, &iv, &data).unwrap();

    // Wait for connection
    let listener = TcpListener::bind("127.0.1.1:9090").unwrap();
    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                // Receive the client's public key
                let mut buffer = [0; 32];
                stream.read(&mut buffer).unwrap();
                let cli_pub = buffer.to_vec();

                // Wrap the symmetric key
                let (mut ser_pri, ser_pub) = Crypt::gen_x25519().unwrap();
                let ser_kek_bytes: [u8; 32] = Crypt::derive_x25519(&ser_pri, &cli_pub.try_into().unwrap()).unwrap().try_into().unwrap();
                let wrapped = Crypt::key_upwrap(&ser_kek_bytes, &sym_key).unwrap();

                // Zeroize ephemeral key (at least the private one...)
                ser_pri.zeroize();

                // Send server's ephemeral public key, wrapped key, and encrypted message back to the client
                let response = [ser_pub.as_slice(), wrapped.as_slice(), cipher.as_slice()].concat();
                stream.write(&response).unwrap();
            }
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
}
