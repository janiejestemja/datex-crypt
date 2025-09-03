use std::pin::Pin;
use super::crypto::{
    CryptoTrait, CryptoError,
    PUB_KEY_LEN, PRI_KEY_LEN, SIG_LEN,
};

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
pub struct Crypt {
    name: String,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
impl Crypt {
    #[wasm_bindgen(constructor)]
    pub fn new(name: String) -> Crypt {
        Crypt { name }
    }
    pub fn name(&self) -> String {
        self.name.clone()
    }
}

#[cfg(target_arch = "wasm32")]
impl CryptoTrait for Crypt {
    // EdDSA
    fn gen_ed25519(
    ) -> Pin<Box<dyn Future<Output = Result<([u8; PRI_KEY_LEN], [u8; PUB_KEY_LEN]), CryptoError>> + 'static>> {
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
