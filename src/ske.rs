use crate::SymmetricKey;
use aes_gcm::aead::{
    consts::*,
    rand_core::{CryptoRng, RngCore},
    Aead,
};
use aes_gcm::aes::cipher::InvalidLength;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SkeError {
    #[error("Invalid key length `{0}`")]
    InvalidKeyLength(InvalidLength),
    #[error("Fail to encrypt a plaintext.")]
    EncryptionError,
}

pub fn ske_gen_key<R: CryptoRng + RngCore>(rng: &mut R) -> SymmetricKey {
    let key = Aes128Gcm::generate_key(rng);
    SymmetricKey(key.to_vec())
}

pub fn ske_encrypt(
    key: &SymmetricKey,
    region_name: &str,
    user_id: usize,
    nonce: usize,
    plaintext: &[u8],
) -> Result<Vec<u8>, SkeError> {
    let cipher = Aes128Gcm::new_from_slice(&key.0).map_err(|e| SkeError::InvalidKeyLength(e))?;
    let nonce = gen_nonce(region_name, user_id, nonce);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| SkeError::EncryptionError)?;
    Ok(ct)
}

pub fn ske_decrypt(
    key: &SymmetricKey,
    region_name: &str,
    user_id: usize,
    nonce: usize,
    ct: &[u8],
) -> Result<Vec<u8>, SkeError> {
    let cipher = Aes128Gcm::new_from_slice(&key.0).map_err(|e| SkeError::InvalidKeyLength(e))?;
    let nonce = gen_nonce(region_name, user_id, nonce);
    let plaintext = cipher
        .decrypt(&nonce, ct)
        .map_err(|_| SkeError::EncryptionError)?;
    Ok(plaintext)
}

fn gen_nonce(region_name: &str, user_id: usize, nonce: usize) -> Nonce<U12> {
    let mut nonce_bytes = region_name.as_bytes().to_vec();
    nonce_bytes.append(&mut user_id.to_be_bytes().to_vec());
    nonce_bytes.append(&mut nonce.to_be_bytes().to_vec());
    Nonce::from_slice(&nonce_bytes).clone()
}
