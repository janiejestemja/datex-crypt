use openssl::error::ErrorStack;
use openssl::pkey::PKey;
use openssl::rand::rand_priv_bytes;

use datex_crypt::{
    derive_key_iv,
    server_generate_key,
    client_derive_key,
    server_derive_key,
    ossl_aes_gcm_enc,
    ossl_aes_gcm_dec,
    generate_ecdsa_keypair,
    sign_ecdsa,
    verify_ecdsa,

};

fn main() -> Result<(), ErrorStack> {
    let data = b"Hello world!";
    let server_pkey = generate_ecdsa_keypair().unwrap();
    let server_pub_pem = server_pkey.public_key_to_pem()?;
    let server_pub_key = PKey::public_key_from_pem(&server_pub_pem);

    let sig = sign_ecdsa(&server_pkey, data).unwrap();
    let verified = verify_ecdsa(&server_pub_key.unwrap(), data, &sig);
    println!("{:?}", verified);


    // Key agreement (ECDH)
    let (server_pkey, server_pub) = server_generate_key()?;
    // Send server_pub to client
    let (client_pub, client_sec) = client_derive_key(&server_pub)?;
    // Send client_pub to server
    let server_sec = server_derive_key(&client_pub, &server_pkey)?;

    assert_eq!(client_sec, server_sec);


    // Key and salt derivation (PKCS5 PBKDF2 HMAC)
    let pass_a = &server_sec;
    let pass_b = &client_sec;

    // let pass_a = b"password_of_alice";
    // let pass_b = b"password_of_bob";

    // Generate salt
    let mut salt: [u8; 32] = [0; 32];
    rand_priv_bytes(&mut salt).unwrap();

    let iter: usize = 100;

    let key_iv_a = derive_key_iv(pass_a, &salt, iter);
    let key_iv_b = derive_key_iv(pass_b, &salt, iter);

    // Decryption/Encryption (AES-CTR)
    let data_a = b"Hey, i'm Alice.";
    let data_b = b"Hey, i'm Bob.";

    // Decryption/Encryption (AES-GCM)
    let key_a: [u8; 32] = key_iv_a.0.try_into().expect("Key expects 32 bytes");
    let nonce_a: [u8; 16] = key_iv_a.1.try_into().expect("Nonce expects 16 bytes");

    let key_b: [u8; 32] = key_iv_b.0.try_into().expect("Key expects 32 bytes");
    let nonce_b: [u8; 16] = key_iv_b.1.try_into().expect("Nonce expects 16 bytes");

    assert_eq!(key_a, key_b);

    let aad: [u8; 16] = [64; 16];

    let encrypted_a = ossl_aes_gcm_enc(&key_a, &nonce_a, data_a, &aad).unwrap();
    let encrypted_b = ossl_aes_gcm_enc(&key_b, &nonce_b, data_b, &aad).unwrap();

    let decrypted_a = ossl_aes_gcm_dec(&key_a, &encrypted_a, &aad).unwrap();
    let decrypted_b = ossl_aes_gcm_dec(&key_b, &encrypted_b, &aad).unwrap();

    println!("Decrypted alice: {:?}", String::from_utf8(decrypted_a).unwrap());
    println!("Decrypted bob: {:?}", String::from_utf8(decrypted_b).unwrap());

    Ok(())
}
