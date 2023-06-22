use crate::common::jobs::{Error, Response};
use crate::common::pool::{Pool, PoolChunk};

pub struct ChachaPolyWorker<'a> {
    pub pool: &'a Pool,
}

impl<'a> ChachaPolyWorker<'a> {
    pub fn encrypt_external_key(
        &mut self,
        key: PoolChunk,
        nonce: PoolChunk,
        aad: Option<PoolChunk>,
        ciphertext: PoolChunk,
    ) -> Response {
        self.encrypt(key.as_slice(), nonce, aad, ciphertext)
    }

    pub fn encrypt(
        &mut self,
        key: &[u8],
        nonce: PoolChunk,
        aad: Option<PoolChunk>,
        mut ciphertext: PoolChunk,
    ) -> Response {
        match self.pool.alloc(crate::crypto::chacha20poly1305::TAG_SIZE) {
            Err(_) => Response::Error(Error::Alloc),
            Ok(mut tag) => {
                let aad = match &aad {
                    Some(aad) => aad.as_slice(),
                    None => &[] as &[u8],
                };
                match crate::crypto::chacha20poly1305::encrypt_in_place_detached(
                    key,
                    nonce.as_slice(),
                    aad,
                    ciphertext.as_slice_mut(),
                ) {
                    Ok(computed_tag) => {
                        if computed_tag.len() != tag.as_slice().len() {
                            return Response::Error(Error::Alloc);
                        }
                        tag.as_slice_mut().copy_from_slice(computed_tag.as_slice());
                        Response::EncryptChaChaPoly { ciphertext, tag }
                    }
                    Err(e) => Response::Error(Error::Crypto(e)),
                }
            }
        }
    }

    pub fn decrypt_external_key(
        &mut self,
        key: PoolChunk,
        nonce: PoolChunk,
        aad: Option<PoolChunk>,
        plaintext: PoolChunk,
        tag: PoolChunk,
    ) -> Response {
        self.decrypt(key.as_slice(), nonce, aad, plaintext, tag)
    }

    pub fn decrypt(
        &mut self,
        key: &[u8],
        nonce: PoolChunk,
        aad: Option<PoolChunk>,
        mut plaintext: PoolChunk,
        tag: PoolChunk,
    ) -> Response {
        let aad = match &aad {
            Some(aad) => aad.as_slice(),
            None => &[] as &[u8],
        };
        match crate::crypto::chacha20poly1305::decrypt_in_place_detached(
            key,
            nonce.as_slice(),
            aad,
            plaintext.as_slice_mut(),
            tag.as_slice(),
        ) {
            Ok(()) => Response::DecryptChaChaPoly { plaintext },
            Err(e) => Response::Error(Error::Crypto(e)),
        }
    }
}