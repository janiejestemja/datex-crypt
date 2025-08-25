use datex_crypt::utils::datex_crypt::{
    hkdf, aes_gcm_decrypt, IV_LEN
};

fn main() {
    const INFO: &[u8] = b"ECIES|X25519|HKDF-SHA256|AES-256-GCM";
    let ikm = vec![0u8; 32];
    let salt = vec![0u8; 16];

    let hash: [u8; 32] = hkdf(&ikm, &salt, &INFO, 32).unwrap().try_into().unwrap();
    println!("{:?}", hash);
    let iv: [u8; IV_LEN] = [0u8; IV_LEN];

    let ciphertext: [u8; 12] = [214, 118, 152, 21, 233, 142, 165, 151, 160, 118, 4, 40,];
    let tag: [u8; 16] = [117, 43, 223, 29, 220, 186, 45, 65, 130, 219, 130, 110, 160, 116, 217, 54];
    let test_case = vec![83, 111, 109, 101, 32, 109, 101, 115, 115, 97, 103, 101];

    let deciphered = aes_gcm_decrypt(&hash, &iv, &INFO, &ciphertext, &tag).unwrap();

    let test_case = vec![83, 111, 109, 101, 32, 109, 101, 115, 115, 97, 103, 101];


    let result: String = deciphered.iter().map(|&c| c as char).collect();
    println!("{}", result);

    assert_eq!(test_case, deciphered);

}
