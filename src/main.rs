use datex_crypt::crypto::crypto_native::Crypt;

fn main() {
    let crypta: Crypt = Crypt::new("RsCipher".to_string());
    println!("{:?}", crypta.name());
}
