use datex_crypt::Crypt;

fn main() {
    let crypta: Crypt = Crypt::new("RsCipher".to_string());
    println!("{:?}", crypta.name());
}
