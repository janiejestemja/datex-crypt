use super::crypto::{CryptoError, CryptoTrait, PRI_KEY_LEN, PUB_KEY_LEN, SIG_LEN};
use std::pin::Pin;

#[cfg(not(target_arch = "wasm32"))]
pub struct Crypt {
    name: Vec<u8>,
}

#[cfg(not(target_arch = "wasm32"))]
impl Crypt {
    pub fn new(name: Vec<u8>) -> Crypt {
        Crypt { name }
    }
    pub fn name(&self) -> Vec<u8>{
        self.name.clone()
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl CryptoTrait for Crypt {
    // EdDSA
    fn gen_ed25519() -> Pin<Box<dyn Future<Output = Result<([u8; PRI_KEY_LEN], [u8; PUB_KEY_LEN]), CryptoError>> + 'static>> {
        todo!();
    }

    fn sig_ed25519<'a>(
        pri_key: &'a [u8; PRI_KEY_LEN],
        digest: &'a Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<[u8; 64], CryptoError>> + 'a>> {
        todo!();
    }

    fn ver_ed25519<'a>(
        pub_key: &'a [u8; PUB_KEY_LEN],
        sig: &'a [u8; SIG_LEN],
        data: &'a Vec<u8>,
    ) -> Pin<Box<dyn Future<Output = Result<bool, CryptoError>> + 'a>> {
        todo!();
    }
}
