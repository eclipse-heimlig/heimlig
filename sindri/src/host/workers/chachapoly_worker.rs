use crate::common::jobs::Response;
use crate::common::pool::{Pool, PoolChunk};
use crate::host::scheduler::Error;

pub struct ChachaPolyWorker {
    pub pool: &'static Pool,
}

impl ChachaPolyWorker {
    pub fn process_encrypt(
        &mut self,
        key: PoolChunk,
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
                    key.as_slice(),
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
                    Err(_) => Response::Error(Error::Encrypt),
                }
            }
        }
    }

    pub fn process_decrypt(
        &mut self,
        key: PoolChunk,
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
            key.as_slice(),
            nonce.as_slice(),
            aad,
            plaintext.as_slice_mut(),
            tag.as_slice(),
        ) {
            Ok(_) => Response::DecryptChaChaPoly { plaintext },
            Err(_) => Response::Error(Error::Encrypt),
        }
    }
}
