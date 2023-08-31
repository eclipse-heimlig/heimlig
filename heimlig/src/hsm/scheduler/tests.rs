use crate::common::jobs::{Error, Request, Response};
use crate::common::limits::MAX_RANDOM_SIZE;
use crate::config;
use crate::config::keystore::{KEY1, KEY2, KEY3};
use crate::crypto::chacha20poly1305::{KEY_SIZE, NONCE_SIZE};
use crate::crypto::rng::test::TestEntropySource;
use crate::crypto::rng::Rng;
use crate::hsm::keystore::MemoryKeyStore;
use crate::hsm::scheduler::{Job, JobResult, Scheduler};

fn init_scheduler<'a>(
    key_store: MemoryKeyStore<{ config::keystore::TOTAL_SIZE }, { config::keystore::NUM_KEYS }>,
) -> Scheduler<
    TestEntropySource,
    MemoryKeyStore<{ config::keystore::TOTAL_SIZE }, { config::keystore::NUM_KEYS }>,
> {
    let entropy = TestEntropySource::default();
    let rng = Rng::new(entropy, None);

    Scheduler::new(rng, key_store)
}

#[test]
fn get_random() {
    let key_infos = [KEY1, KEY2, KEY3];
    let key_store = MemoryKeyStore::<
        { config::keystore::TOTAL_SIZE },
        { config::keystore::NUM_KEYS },
    >::try_new(&key_infos)
    .expect("failed to create key store");
    let mut scheduler = init_scheduler(key_store);

    const REQUEST_SIZE: usize = 32;
    const REQUEST_ID: usize = 12345;
    let mut random_output = [0u8; REQUEST_SIZE];
    let request = Request::GetRandom {
        output: &mut random_output,
    };
    let job = Job {
        request_id: REQUEST_ID,
        request,
    };
    let response_data = match scheduler.schedule(job) {
        JobResult {
            request_id,
            response: Response::GetRandom {
                data: response_data,
            },
            ..
        } => {
            assert_eq!(request_id, REQUEST_ID);
            response_data
        }
        _ => {
            panic!("Unexpected response type");
        }
    };
    assert_eq!(response_data.len(), REQUEST_SIZE);
}

#[test]
fn get_random_request_too_large() {
    let key_infos = [KEY1, KEY2, KEY3];
    let key_store = MemoryKeyStore::<
        { config::keystore::TOTAL_SIZE },
        { config::keystore::NUM_KEYS },
    >::try_new(&key_infos)
    .expect("failed to create key store");
    let mut scheduler = init_scheduler(key_store);

    const REQUEST_SIZE: usize = MAX_RANDOM_SIZE + 1;
    const REQUEST_ID: usize = 12345;
    let mut random_output = [0u8; REQUEST_SIZE];
    let request = Request::GetRandom {
        output: &mut random_output,
    };
    let job = Job {
        request_id: REQUEST_ID,
        request,
    };
    let result = scheduler.schedule(job);
    assert!(matches!(
        result.response,
        Response::Error(Error::RequestTooLarge)
    ))
}

const PLAINTEXT_SIZE: usize = 36;
const AAD_SIZE: usize = 33;
const TAG_SIZE: usize = 16;

fn alloc_chachapoly_vars(buffer: &mut [u8]) -> (&[u8], &[u8], &[u8], &mut [u8], &mut [u8]) {
    const KEY: &[u8; KEY_SIZE] = b"Fortuna Major or Oddsbodikins???";
    const NONCE: &[u8; NONCE_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    const PLAINTEXT: &[u8; PLAINTEXT_SIZE] = b"I solemnly swear I am up to no good!";
    const AAD: &[u8; AAD_SIZE] = b"When in doubt, go to the library.";
    let (key, buffer) = buffer.split_at_mut(KEY.len());
    key.copy_from_slice(KEY);
    let (nonce, buffer) = buffer.split_at_mut(NONCE.len());
    nonce.copy_from_slice(NONCE);
    let (aad, buffer) = buffer.split_at_mut(AAD.len());
    aad.copy_from_slice(AAD);
    let (plaintext, buffer) = buffer.split_at_mut(PLAINTEXT.len());
    plaintext.copy_from_slice(PLAINTEXT);
    let (tag, _buffer) = buffer.split_at_mut(TAG_SIZE);
    (key, nonce, aad, plaintext, tag)
}

#[test]
fn encrypt_chachapoly() {
    let key_infos = [KEY1, KEY2, KEY3];
    let key_store = MemoryKeyStore::<
        { config::keystore::TOTAL_SIZE },
        { config::keystore::NUM_KEYS },
    >::try_new(&key_infos)
    .expect("failed to create key store");
    let mut scheduler = init_scheduler(key_store);

    // Import key
    let mut memory = [0; KEY_SIZE + NONCE_SIZE + PLAINTEXT_SIZE + AAD_SIZE + TAG_SIZE];
    let (key, nonce, aad, plaintext, tag) = alloc_chachapoly_vars(&mut memory);
    let request = Request::ImportKey {
        id: KEY3.id,
        data: key,
    };
    let job = Job {
        request_id: 0,
        request,
    };
    match scheduler.schedule(job).response {
        Response::ImportKey {} => {}
        _ => {
            panic!("Unexpected response type");
        }
    }

    // Encrypt data
    let request = Request::EncryptChaChaPoly {
        key_id: KEY3.id,
        nonce,
        aad: Some(aad),
        plaintext,
        tag,
    };
    let job = Job {
        request_id: 0,
        request,
    };
    let (ciphertext, tag) = match scheduler.schedule(job).response {
        Response::EncryptChaChaPoly { ciphertext, tag } => (ciphertext, tag),
        _ => {
            panic!("Unexpected response type");
        }
    };

    // Decrypt data
    let mut memory = [0; KEY_SIZE + NONCE_SIZE + PLAINTEXT_SIZE + AAD_SIZE + TAG_SIZE];
    let (_key, nonce, aad, org_plaintext, _tag) = alloc_chachapoly_vars(&mut memory);
    let request = Request::DecryptChaChaPoly {
        key_id: KEY3.id,
        nonce,
        aad: Some(aad),
        ciphertext,
        tag,
    };
    let job = Job {
        request_id: 0,
        request,
    };
    let plaintext = match scheduler.schedule(job).response {
        Response::DecryptChaChaPoly { plaintext } => plaintext,
        resp => {
            panic!("Unexpected response type {:?}", resp);
        }
    };
    assert_eq!(plaintext, org_plaintext);
}

#[test]
fn encrypt_chachapoly_external_key() {
    let key_infos = [KEY1, KEY2, KEY3];
    let key_store = MemoryKeyStore::<
        { config::keystore::TOTAL_SIZE },
        { config::keystore::NUM_KEYS },
    >::try_new(&key_infos)
    .expect("failed to create key store");
    let mut scheduler = init_scheduler(key_store);

    // Encrypt data
    let mut memory = [0; KEY_SIZE + NONCE_SIZE + PLAINTEXT_SIZE + AAD_SIZE + TAG_SIZE];
    let (key, nonce, aad, plaintext, tag) = alloc_chachapoly_vars(&mut memory);
    let request = Request::EncryptChaChaPolyExternalKey {
        key,
        nonce,
        aad: Some(aad),
        plaintext,
        tag,
    };
    let job = Job {
        request_id: 0,
        request,
    };
    let (ciphertext, tag) = match scheduler.schedule(job).response {
        Response::EncryptChaChaPoly { ciphertext, tag } => (ciphertext, tag),
        _ => {
            panic!("Unexpected response type");
        }
    };

    // Decrypt data
    let mut memory = [0; KEY_SIZE + NONCE_SIZE + PLAINTEXT_SIZE + AAD_SIZE + TAG_SIZE];
    let (key, nonce, aad, org_plaintext, _tag) = alloc_chachapoly_vars(&mut memory);
    let request = Request::DecryptChaChaPolyExternalKey {
        key,
        nonce,
        aad: Some(aad),
        ciphertext,
        tag,
    };
    let job = Job {
        request_id: 0,
        request,
    };
    let plaintext = match scheduler.schedule(job).response {
        Response::DecryptChaChaPoly { plaintext } => plaintext,
        _ => {
            panic!("Unexpected response type");
        }
    };
    assert_eq!(plaintext, org_plaintext)
}
