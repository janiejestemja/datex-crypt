use openssl::{
    derive::Deriver,
    error::ErrorStack,
    pkey::{Id, PKey},
};

pub fn gen_x25519() -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
    let key = PKey::generate_x25519()?;
    let public_key = key.raw_public_key()?;
    let private_key = key.raw_private_key()?;
    Ok((public_key, private_key))
}

pub fn derive_x25519(my_raw: &Vec<u8>, peer_pub: &Vec<u8>) -> Result<Vec<u8>, ErrorStack> {
    let peer_pub = PKey::public_key_from_raw_bytes(peer_pub, Id::X25519).unwrap();
    let my_priv = PKey::private_key_from_raw_bytes(my_raw, Id::X25519).unwrap();

    let mut deriver = Deriver::new(&my_priv)?;
    deriver.set_peer(&peer_pub)?;
    deriver.derive_to_vec()
}
