use crate::SymmetricKey;
use aes_gcm::aead::{
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
    nonce: [u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, SkeError> {
    let cipher = Aes128Gcm::new_from_slice(&key.0).map_err(|e| SkeError::InvalidKeyLength(e))?;
    let nonce = Nonce::from_slice(&nonce);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| SkeError::EncryptionError)?;
    Ok(ct)
}

pub fn ske_decrypt(key: &SymmetricKey, nonce: [u8; 12], ct: &[u8]) -> Result<Vec<u8>, SkeError> {
    let cipher = Aes128Gcm::new_from_slice(&key.0).map_err(|e| SkeError::InvalidKeyLength(e))?;
    let nonce = Nonce::from_slice(&nonce);
    let plaintext = cipher
        .decrypt(&nonce, ct)
        .map_err(|_| SkeError::EncryptionError)?;
    Ok(plaintext)
}
