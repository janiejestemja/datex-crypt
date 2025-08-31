use openssl::{
    ec::{EcGroup, EcKey},
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{Id, PKey, Private, Public},
    sign::{Signer, Verifier},
};

// ECDSA
pub fn gen_keypair() -> Result<PKey<Private>, ErrorStack> {
    let group = EcGroup::from_curve_name(Nid::BRAINPOOL_P384R1)
        .expect("curve missing; consider using another");
    let ec = EcKey::generate(&group)?;
    Ok(PKey::from_ec_key(ec)?)
}

pub fn sign(privkey: &PKey<Private>, data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let mut signer = Signer::new(MessageDigest::sha256(), privkey)?;
    signer.update(data)?;
    Ok(signer.sign_to_vec()?)
}

pub fn verify(pubkey: &PKey<Public>, data: &[u8], sign: &[u8]) -> Result<bool, ErrorStack> {
    let mut verifier = Verifier::new(MessageDigest::sha256(), pubkey)?;
    verifier.update(data)?;
    Ok(verifier.verify(sign)?)
}

pub fn gen_ed25519() -> Result<(Vec<u8>, Vec<u8>), ErrorStack> {
    let key = PKey::generate_ed25519()?;
    let public_key = key.public_key_to_der()?;
    let private_key = key.private_key_to_pkcs8()?;
    Ok((public_key, private_key))
}

pub fn sig_ed25519(pri_key: &Vec<u8>, digest: &Vec<u8>) -> Result<Vec<u8>, ErrorStack> {
    let sig_key = PKey::private_key_from_pkcs8(pri_key).unwrap();

    let mut signer = Signer::new_without_digest(&sig_key)?;
    let signature = signer.sign_oneshot_to_vec(digest)?;
    assert_eq!(signature.len(), 64);
    Ok(signature)
}

pub fn ver_ed25519(pub_key: Vec<u8>, sig: Vec<u8>, data: Vec<u8>) -> Result<bool, ErrorStack> {
    let public_key = PKey::public_key_from_der(&pub_key).unwrap();
    let mut verifier = Verifier::new_without_digest(&public_key).unwrap();
    Ok(verifier.verify_oneshot(&sig, &data).unwrap())
}
