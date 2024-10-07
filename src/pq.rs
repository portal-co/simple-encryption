use std::path::Display;

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, ChaChaPoly1305, KeyInit, Nonce};
use pqc_kyber::{decapsulate, encapsulate, KyberError};
use rand::rngs::OsRng;
use thiserror::Error;
#[derive(Error, Debug)]
pub struct PqError {}
impl std::fmt::Display for PqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        return "pq crypto error".fmt(f);
    }
}
pub fn encrypt(p: pqc_kyber::PublicKey, a: &[u8]) -> Result<Vec<u8>, PqError> {
    let (ci, s) = encapsulate(&p, &mut OsRng).map_err(|_| PqError {})?;
    let mut c = ChaCha20Poly1305::new_from_slice(&s).unwrap();
    let mut v = ci.to_vec();
    v.append(&mut c.encrypt(&Nonce::default(), a).map_err(|_| PqError {})?);
    return Ok(v);
}
pub fn decrypt(s: pqc_kyber::SecretKey, a: &[u8]) -> Result<Vec<u8>, PqError> {
    let (cj, c) = a.split_at(pqc_kyber::KYBER_CIPHERTEXTBYTES);
    let d = decapsulate(cj, &s).map_err(|_| PqError {})?;
    let mut d = ChaCha20Poly1305::new_from_slice(&d).unwrap();
    return Ok(d.decrypt(&Nonce::default(), c).map_err(|_| PqError {})?);
}
