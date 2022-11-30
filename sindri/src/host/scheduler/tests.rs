use crate::common::jobs::{Error, Request, Response};
use crate::common::limits::MAX_RANDOM_SIZE;
use crate::common::pool::{Memory, Pool, PoolChunk};
use crate::config;
use crate::config::keystore::{KEY1, KEY2, KEY3};
use crate::crypto::chacha20poly1305::{KEY_SIZE, NONCE_SIZE};
use crate::crypto::rng::test::TestEntropySource;
use crate::crypto::rng::Rng;
use crate::host::keystore::{KeyStore, MemoryKeyStore};
use crate::host::scheduler::Job;
use crate::host::scheduler::Scheduler;

fn init_scheduler<'a>(
    pool: &'a Pool,
    key_store: &'a mut dyn KeyStore,
) -> Scheduler<'a, TestEntropySource> {
    let entropy = TestEntropySource::default();
    let rng = Rng::new(entropy, None);

    Scheduler::new(pool, rng, Some(key_store))
}

#[test]
fn get_random() {
    static mut MEMORY: Memory = [0; Pool::required_memory()];
    let pool = Pool::try_from(unsafe { &mut MEMORY }).unwrap();
    let key_infos = [KEY1, KEY2, KEY3];
    let mut key_store = MemoryKeyStore::<
        { config::keystore::TOTAL_SIZE },
        { config::keystore::NUM_KEYS },
    >::try_new(&key_infos)
    .expect("failed to create key store");
    let mut scheduler = init_scheduler(&pool, &mut key_store);
    let request = Request::GetRandom { size: 32 };
    let job = Job {
        channel_id: 0,
        request,
    };
    let response_data = match scheduler.schedule(job).response {
        Response::GetRandom {
            data: response_data,
        } => response_data,
        _ => {
            panic!("Unexpected response type");
        }
    };
    assert_eq!(response_data.len(), 32);
}

#[test]
fn get_random_request_too_large() {
    static mut MEMORY: Memory = [0; Pool::required_memory()];
    let pool = Pool::try_from(unsafe { &mut MEMORY }).unwrap();
    let key_infos = [KEY1, KEY2, KEY3];
    let mut key_store = MemoryKeyStore::<
        { config::keystore::TOTAL_SIZE },
        { config::keystore::NUM_KEYS },
    >::try_new(&key_infos)
    .expect("failed to create key store");
    let mut scheduler = init_scheduler(&pool, &mut key_store);
    let request = Request::GetRandom {
        size: MAX_RANDOM_SIZE + 1,
    };
    let job = Job {
        channel_id: 0,
        request,
    };
    let result = scheduler.schedule(job);
    assert!(matches!(
        result.response,
        Response::Error(Error::RequestTooLarge)
    ))
}

fn alloc_chachapoly_vars(pool: &Pool) -> (PoolChunk, PoolChunk, PoolChunk, PoolChunk) {
    const KEY: &[u8; KEY_SIZE] = b"Fortuna Major or Oddsbodikins???";
    const NONCE: &[u8; NONCE_SIZE] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    const PLAINTEXT: &[u8] = b"I solemnly swear I am up to no good!";
    const AAD: &[u8] = b"When in doubt, go to the library.";
    let key = pool.alloc(KEY.len()).unwrap();
    let mut nonce = pool.alloc(NONCE_SIZE).unwrap();
    nonce.as_slice_mut().copy_from_slice(NONCE);
    let mut aad = pool.alloc(AAD.len()).unwrap();
    aad.as_slice_mut().copy_from_slice(AAD);
    let mut plaintext = pool.alloc(PLAINTEXT.len()).unwrap();
    plaintext.as_slice_mut().copy_from_slice(PLAINTEXT);
    (key, nonce, aad, plaintext)
}

#[test]
fn encrypt_chachapoly() {
    static mut MEMORY: Memory = [0; Pool::required_memory()];
    let pool = Pool::try_from(unsafe { &mut MEMORY }).unwrap();
    let key_infos = [KEY1, KEY2, KEY3];
    let mut key_store = MemoryKeyStore::<
        { config::keystore::TOTAL_SIZE },
        { config::keystore::NUM_KEYS },
    >::try_new(&key_infos)
    .expect("failed to create key store");
    let mut scheduler = init_scheduler(&pool, &mut key_store);

    // Import key
    let (key, nonce, aad, plaintext) = alloc_chachapoly_vars(&pool);
    let request = Request::ImportKey {
        id: KEY3.id,
        data: key,
    };
    let job = Job {
        channel_id: 0,
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
    };
    let job = Job {
        channel_id: 0,
        request,
    };
    let (ciphertext, tag) = match scheduler.schedule(job).response {
        Response::EncryptChaChaPoly { ciphertext, tag } => (ciphertext, tag),
        _ => {
            panic!("Unexpected response type");
        }
    };

    // Decrypt data
    let (_key, nonce, aad, org_plaintext) = alloc_chachapoly_vars(&pool);
    let request = Request::DecryptChaChaPoly {
        key_id: KEY3.id,
        nonce,
        aad: Some(aad),
        ciphertext,
        tag,
    };
    let job = Job {
        channel_id: 0,
        request,
    };
    let plaintext = match scheduler.schedule(job).response {
        Response::DecryptChaChaPoly { plaintext } => plaintext,
        _ => {
            panic!("Unexpected response type");
        }
    };
    assert_eq!(plaintext.as_slice(), org_plaintext.as_slice());
}

#[test]
fn encrypt_chachapoly_external_key() {
    static mut MEMORY: Memory = [0; Pool::required_memory()];
    let pool = Pool::try_from(unsafe { &mut MEMORY }).unwrap();
    let key_infos = [KEY1, KEY2, KEY3];
    let mut key_store = MemoryKeyStore::<
        { config::keystore::TOTAL_SIZE },
        { config::keystore::NUM_KEYS },
    >::try_new(&key_infos)
    .expect("failed to create key store");
    let mut scheduler = init_scheduler(&pool, &mut key_store);

    // Encrypt data
    let (key, nonce, aad, plaintext) = alloc_chachapoly_vars(&pool);
    let request = Request::EncryptChaChaPolyExternalKey {
        key,
        nonce,
        aad: Some(aad),
        plaintext,
    };
    let job = Job {
        channel_id: 0,
        request,
    };
    let (ciphertext, tag) = match scheduler.schedule(job).response {
        Response::EncryptChaChaPoly { ciphertext, tag } => (ciphertext, tag),
        _ => {
            panic!("Unexpected response type");
        }
    };

    // Decrypt data
    let (key, nonce, aad, org_plaintext) = alloc_chachapoly_vars(&pool);
    let request = Request::DecryptChaChaPolyExternalKey {
        key,
        nonce,
        aad: Some(aad),
        ciphertext,
        tag,
    };
    let job = Job {
        channel_id: 0,
        request,
    };
    let plaintext = match scheduler.schedule(job).response {
        Response::DecryptChaChaPoly { plaintext } => plaintext,
        _ => {
            panic!("Unexpected response type");
        }
    };
    assert_eq!(plaintext.as_slice(), org_plaintext.as_slice())
}
