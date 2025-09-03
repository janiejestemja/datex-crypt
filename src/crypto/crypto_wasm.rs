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
