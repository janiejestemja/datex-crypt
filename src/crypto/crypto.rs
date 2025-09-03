use std::pin::Pin;

pub const PUB_KEY_LEN: usize = 48;
pub const PRI_KEY_LEN: usize = 44;

pub trait CryptoTrait {
    // EdDSA
    fn gen_ed25519(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(Vec<u8>, Vec<u8>), CryptoError>> + 'static>>;

    fn sig_ed25519<'a>(
        &self,
        pri_key: &'a Vec<u8>,
        digest: &'a Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, CryptoError>> + 'a>>;

    fn ver_ed25519<'a>(
        &self,
        pub_key: &'a Vec<u8>,
        sig: &'a [u8; 64],
        data: &'a Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, CryptoError>> + 'a>>;

    fn hkdf(ikm: &[u8], salt: &[u8]) -> Result<Vec<u8>, CryptoError>;

    // AES
    fn aes_ctr_encrypt(
        key: &[u8; 32],
        iv: &[u8; 16],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;
}

#[derive(Debug, Clone)]
pub enum CryptoError {
    Other(String),
    KeyGeneratorFailed,
    KeyExportFailed,
    KeyImportFailed,
    KeyDerivationFailed,
    EncryptionError,
    DecryptionError,
    SigningError,
    VerificationError,
}
