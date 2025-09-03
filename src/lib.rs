#[cfg(target_arch = "wasm32")]
#[allow(unused)]
use wasm_bindgen::prelude::*;

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
#[allow(unused)]
pub struct Crypt {
    name: String,
}

#[cfg(target_arch = "wasm32")]
#[wasm_bindgen]
#[allow(unused)]
impl Crypt {
    #[wasm_bindgen(constructor)]
    pub fn new(name: String) -> Crypt {
        Crypt { name }
    }
    pub fn name(&self) -> String {
        self.name.clone()
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub struct Crypt {
    name: String,
}

#[cfg(not(target_arch = "wasm32"))]
impl Crypt {
    pub fn new(name: String) -> Crypt {
        Crypt { name }
    }
    pub fn name(&self) -> String {
        self.name.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let crypta = Crypt::new("RsCipher".to_string());
        assert_eq!(crypta.name(), "RsCipher".to_string());
    }
}
