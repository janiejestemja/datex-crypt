use datex_crypt::crypto::crypto_native::Crypt;

fn main() {
    let crypta: Crypt = Crypt::new("RsCrypt".to_string());
    println!("{:?}", crypta.name());
}
