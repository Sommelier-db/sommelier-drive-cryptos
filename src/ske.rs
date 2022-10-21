use crate::SymmetricKey;
use aes_gcm::aead::{
    rand_core::{CryptoRng, RngCore},
    Aead,
};
use aes_gcm::aes::cipher::InvalidLength;
use aes_gcm::{Aes128Gcm, KeyInit, Nonce};
use thiserror::Error;

pub const NONCE_BYTES_SIZE: usize = 12;

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
    nonce: &[u8; 12],
    plaintext: &[u8],
) -> Result<Vec<u8>, SkeError> {
    let cipher = Aes128Gcm::new_from_slice(&key.0).map_err(|e| SkeError::InvalidKeyLength(e))?;
    let nonce = Nonce::from_slice(nonce);
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| SkeError::EncryptionError)?;
    let ct_with_nonce = vec![nonce.to_vec(), ct].concat();
    Ok(ct_with_nonce)
}

pub fn ske_decrypt(key: &SymmetricKey, ct: &[u8]) -> Result<Vec<u8>, SkeError> {
    let cipher = Aes128Gcm::new_from_slice(&key.0).map_err(|e| SkeError::InvalidKeyLength(e))?;
    let nonce = Nonce::from_slice(&ct[0..NONCE_BYTES_SIZE]);
    let plaintext = cipher
        .decrypt(&nonce, &ct[NONCE_BYTES_SIZE..])
        .map_err(|_| SkeError::EncryptionError)?;
    Ok(plaintext)
}
