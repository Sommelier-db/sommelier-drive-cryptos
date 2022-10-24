use crate::{AuthorizationSeed, PkePublicKey, PkeSecretKey};
use aes_gcm::aead::rand_core::{CryptoRng, RngCore};
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use rsa::{PaddingScheme, PublicKey, RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PkeError {
    #[error("Fail to generate a secret key")]
    SecretKeyGenError,
    #[error("Fail to encrypt a plaintext")]
    EncryptionError,
    #[error("Fail to decrypt a ciphertext")]
    DecryptionError,
}

const BITS: usize = 2048;

pub fn pke_gen_secret_key<R: CryptoRng + RngCore>(rng: &mut R) -> Result<PkeSecretKey, PkeError> {
    let private_key = RsaPrivateKey::new(rng, BITS).map_err(|_| PkeError::SecretKeyGenError)?;
    Ok(PkeSecretKey(private_key))
}

pub fn pke_derive_secret_key_from_seeed(seed: AuthorizationSeed) -> Result<PkeSecretKey, PkeError> {
    let mut rng = ChaCha20Rng::from_seed(seed);
    pke_gen_secret_key(&mut rng)
}

pub fn pke_gen_public_key(sk: &PkeSecretKey) -> PkePublicKey {
    let public_key = RsaPublicKey::from(&sk.0);
    PkePublicKey(public_key)
}

pub fn pke_encrypt<R: CryptoRng + RngCore>(
    pk: &PkePublicKey,
    plaintext: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>, PkeError> {
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let ct =
        pk.0.encrypt(rng, padding, plaintext)
            .map_err(|_| PkeError::EncryptionError)?;
    Ok(ct)
}

pub fn pke_decrypt(sk: &PkeSecretKey, ct: &[u8]) -> Result<Vec<u8>, PkeError> {
    let padding = PaddingScheme::new_oaep::<Sha256>();
    let plaintext =
        sk.0.decrypt(padding, ct)
            .map_err(|_| PkeError::DecryptionError)?;
    Ok(plaintext)
}
