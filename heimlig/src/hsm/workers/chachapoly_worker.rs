use crate::common::jobs::{Error, InOutParam, InParam, OutParam, Response};
use crate::common::pool::Pool;

pub struct ChachaPolyWorker<'a> {
    pub pool: &'a Pool,
}

impl<'a> ChachaPolyWorker<'a> {
    pub fn encrypt_external_key(
        &mut self,
        key: InParam,
        nonce: InParam,
        aad: Option<InParam>,
        ciphertext: InOutParam,
        tag: OutParam,
    ) -> Response {
        self.encrypt(key.as_slice(), nonce, aad, ciphertext, tag)
    }

    pub fn encrypt(
        &mut self,
        key: &[u8],
        nonce: InParam,
        aad: Option<InParam>,
        mut ciphertext: InOutParam,
        mut tag: OutParam,
    ) -> Response {
        let aad = aad.unwrap_or_default();
        match crate::crypto::chacha20poly1305::encrypt_in_place_detached(
            key,
            nonce.as_slice(),
            aad.as_slice(),
            ciphertext.as_mut_slice(),
        ) {
            Ok(computed_tag) => {
                if computed_tag.len() != tag.as_slice().len() {
                    return Response::Error(Error::Crypto(crate::crypto::Error::InvalidTagSize));
                }

                tag.as_mut_slice().copy_from_slice(computed_tag.as_slice());
                Response::EncryptChaChaPoly { ciphertext, tag }
            }
            Err(e) => Response::Error(Error::Crypto(e)),
        }
    }

    pub fn decrypt_external_key(
        &mut self,
        key: InParam,
        nonce: InParam,
        aad: Option<InParam>,
        plaintext: InOutParam,
        tag: InParam,
    ) -> Response {
        self.decrypt(key.as_slice(), nonce, aad, plaintext, tag)
    }

    pub fn decrypt(
        &mut self,
        key: &[u8],
        nonce: InParam,
        aad: Option<InParam>,
        mut plaintext: InOutParam,
        tag: InParam,
    ) -> Response {
        let aad = aad.unwrap_or_default();
        match crate::crypto::chacha20poly1305::decrypt_in_place_detached(
            key,
            nonce.as_slice(),
            aad.as_slice(),
            plaintext.as_mut_slice(),
            tag.as_slice(),
        ) {
            Ok(()) => Response::DecryptChaChaPoly { plaintext },
            Err(e) => Response::Error(Error::Crypto(e)),
        }
    }
}
