use datex_crypt::crypto::crypto::CryptoTrait;
use datex_crypt::crypto::crypto_native::Crypt;

fn main() {
    let kek: [u8; 32] = 
    [176, 213,  29, 202, 131,  45, 220,
    153, 250, 120, 219,  65, 177, 117,
    244, 172,  38, 107, 221, 109, 160,
    134,  15, 195,  23,  22, 143, 238,
    242, 222,  38, 248];


    let web_wrapped: [u8; 40] = 
    [140, 223, 207,  46,   9, 105, 205,  24, 174,
    238, 109,   5,  96,   4,  51, 132,  54, 187,
    251, 167, 105, 131, 109, 246, 123, 238, 160,
    139, 180,  59, 185,   8, 191,  57, 139, 133,
     19,  40,  15, 210];

    let wrapped = Crypt::key_upwrap(&kek, &kek).unwrap();

    let unwrapped = Crypt::key_unwrap(&kek, &wrapped).unwrap();
    let web_unwrapped = Crypt::key_unwrap(&kek, &web_wrapped).unwrap();

    println!("{:?}", wrapped);
    println!("{:?}", wrapped.len());

    println!("{:?}", kek);
    println!("{:?}", kek.len());

    println!("{:?}", unwrapped);
    println!("{:?}", unwrapped.len());

    println!("{:?}", web_unwrapped);
    println!("{:?}", web_unwrapped.len());

}
fn legacy_main() {
    // Given
    let mut client_list = Vec::new();

    // Generate symmetric random key
    let sym_key = Crypt::sym_key_gen().unwrap();

    for _ in 0..10 {
        let (cli_pri, cli_pub) = Crypt::gen_x25519().unwrap();
        client_list.push((cli_pri, cli_pub));
    }

    // Encrypt data with symmetric key
    let data = b"Some message to encrypt".to_vec();
    let iv = [0u8; 16];
    let cipher = Crypt::aes_ctr_encrypt(&sym_key, &iv, &data).unwrap();

    // Sender (server)
    let mut payloads = Vec::new();
    for i in 0..10 {
        let (ser_pri, ser_pub) = Crypt::gen_x25519().unwrap();
        let ser_kek_bytes: [u8; 32] = Crypt::derive_x25519(&ser_pri, &client_list[i].1)
            .unwrap().try_into().unwrap();

        let wrapped = Crypt::key_upwrap(&ser_kek_bytes, &sym_key)
            .unwrap();

        payloads.push((ser_pub, wrapped));
    }

    // Receiver (client)
    for i in 0..10 {
        // Unwraps key and decrypts
        let cli_kek_bytes: [u8; 32] = Crypt::derive_x25519(&client_list[i].0, &payloads[i].0)
            .unwrap().try_into().unwrap();
        let unwrapped = Crypt::key_unwrap(&cli_kek_bytes, &payloads[i].1)
            .unwrap();
        let plain = Crypt::aes_ctr_encrypt(&unwrapped, &iv, &cipher).unwrap();

        // Check key wraps
        assert_eq!(sym_key, unwrapped);
        assert_ne!(payloads[i].1.to_vec(), unwrapped.to_vec());
        assert_eq!(payloads[i].1.len(), unwrapped.len() + 8);

        // Check data, cipher and deciphered
        assert_ne!(data, cipher);
        assert_eq!(plain, data);
    }
}
