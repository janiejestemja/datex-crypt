use datex_crypt::crypto::crypto::CryptoTrait;
use datex_crypt::crypto::crypto_native::Crypt;

fn main() {
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
