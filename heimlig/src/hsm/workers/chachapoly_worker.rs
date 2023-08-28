use crate::common::jobs::{Error, Response};

pub struct ChachaPolyWorker;

impl ChachaPolyWorker {
    pub fn encrypt_external_key<'a>(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; crate::crypto::chacha20poly1305::TAG_SIZE],
    ) -> Response<'a> {
        self.encrypt(key, nonce, aad, ciphertext, tag)
    }

    pub fn encrypt<'a>(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
        ciphertext: &'a mut [u8],
        tag: &'a mut [u8; crate::crypto::chacha20poly1305::TAG_SIZE],
    ) -> Response<'a> {
        match crate::crypto::chacha20poly1305::encrypt_in_place_detached(
            key,
            nonce,
            aad.unwrap_or_default(),
            ciphertext,
        ) {
            Ok(computed_tag) => {
                if computed_tag.len() != tag.len() {
                    return Response::Error(Error::Crypto(crate::crypto::Error::InvalidTagSize));
                }
                tag.copy_from_slice(computed_tag.as_slice());
                Response::EncryptChaChaPoly { ciphertext, tag }
            }
            Err(e) => Response::Error(Error::Crypto(e)),
        }
    }

    pub fn decrypt_external_key<'a>(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
        plaintext: &'a mut [u8],
        tag: &[u8],
    ) -> Response<'a> {
        self.decrypt(key, nonce, aad, plaintext, tag)
    }

    pub fn decrypt<'a>(
        &mut self,
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
        plaintext: &'a mut [u8],
        tag: &[u8],
    ) -> Response<'a> {
        match crate::crypto::chacha20poly1305::decrypt_in_place_detached(
            key,
            nonce,
            aad.unwrap_or_default(),
            plaintext,
            tag,
        ) {
            Ok(()) => Response::DecryptChaChaPoly { plaintext },
            Err(e) => Response::Error(Error::Crypto(e)),
        }
    }
}
