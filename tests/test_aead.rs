use testvec::aead::*;
use testvec::*;

// Test ring
use ring::{aead, aead::Algorithm, aead::BoundKey, aead::Tag, error};

struct AEADTestCase(&'static str, usize);

struct OneNonceSequence(Option<aead::Nonce>);

impl OneNonceSequence {
    /// Constructs the sequence allowing `advance()` to be called
    /// `allowed_invocations` times.
    fn new(nonce: aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<aead::Nonce, error::Unspecified> {
        self.0.take().ok_or(error::Unspecified)
    }
}

fn test_ring_aead(
    key: &[u8],
    iv: &[u8],
    aad: &[u8],
    m: &[u8],
    algorithm: &'static Algorithm,
) -> (Vec<u8>, Tag) {
    let iv = aead::Nonce::try_assume_unique_for_key(&iv).unwrap();
    let mut in_out = m.to_vec();
    let key = aead::UnboundKey::new(algorithm, key).unwrap();
    let nonce_sequence = OneNonceSequence::new(iv);
    let mut key = aead::SealingKey::<OneNonceSequence>::new(key, nonce_sequence);
    let aad = aead::Aad::from(aad);
    let c = key.seal_in_place_separate_tag(aad, &mut in_out).unwrap();
    (in_out, c)
}

fn test_aead(tests: &AEADTestVector, algorithm: &'static Algorithm) {
    let mut num_tests = tests.numberOfTests;
    let mut skipped_tests = false;
    for testGroup in tests.testGroups.iter() {
        assert_eq!(testGroup.r#type, "AeadTest");
        // TODO: not cool
        let mut algorithm = algorithm;
        if algorithm == &aead::AES_128_GCM && testGroup.ivSize != 96 {
            // not implemented
            println!("Nonce sizes != 96 are not supported for AES GCM");
            skipped_tests = true;
            continue;
        }
        if algorithm == &aead::AES_128_GCM && testGroup.keySize == 192 {
            // not implemented
            println!("AES 192 is not implemented");
            skipped_tests = true;
            continue;
        }
        if algorithm != &aead::CHACHA20_POLY1305 && testGroup.keySize == 256 {
            algorithm = &aead::AES_256_GCM
        }
        // if algorithm == &aead::AES_128_GCM && testGroup.keySize == 256 {
        //     println!("foooooooooooooooooo");
        //     algorithm = &aead::AES_256_GCM;
        // }
        for test in testGroup.tests.iter() {
            let valid = test.result.eq("valid");
            if test.comment == "invalid nonce size" {
                // ring panicks
                println!("Invalid nonce sizes are not supported");
                skipped_tests = true;
                break;
            }
            num_tests = num_tests - 1;
            println!("Test {:?}: {:?}", test.tcId, test.comment);
            let m = decode_hex(&test.msg).unwrap();
            let key = decode_hex(&test.key).unwrap();
            let iv = decode_hex(&test.iv).unwrap();
            let aad = decode_hex(&test.aad).unwrap();
            let exp_cipher = decode_hex(&test.ct).unwrap();
            let exp_tag = decode_hex(&test.tag).unwrap();
            let r = test_ring_aead(&key, &iv, &aad, &m, algorithm);
            if valid {
                assert_eq!(r.1.as_ref()[..], exp_tag[..]);
            } else {
                assert_ne!(r.1.as_ref()[..], exp_tag[..]);
            }
            assert_eq!(r.0[..], exp_cipher[..]);
        }
    }
    // Check that we ran all tests.
    if !skipped_tests {
        assert_eq!(num_tests, 0);
    }
}

macro_rules! test_aead_gen {
    ($func_name:ident, $test_case:expr, $test_func:ident, $alg:expr) => {
        #[test]
        fn $func_name() {
            println!(" === {:?} Test ===", stringify!($test_case.0));
            let p = AEADTestVector::new(($test_case.0).to_string());
            assert!(p.is_ok());
            let p = p.unwrap();

            // println!("test cases:\n{:?}", p);
            let notes = p.get_notes();
            // println!("notes:\n{:?}", notes);
            assert!(notes.len() == $test_case.1);
            $test_func(&p, $alg);
        }
    };
}

fn noop(tests: &AEADTestVector, algorithm: &'static Algorithm) {}

test_aead_gen!(
    chacha,
    AEADTestCase("tests/chacha20poly1305_wycheproof.json", 0 /*notes*/),
    test_aead,
    &aead::CHACHA20_POLY1305
);
test_aead_gen!(
    aesgcm,
    AEADTestCase("tests/aesgcm_wycheproof.json", 2 /*notes*/),
    test_aead,
    &aead::AES_128_GCM
);
test_aead_gen!(
    aesgcmsiv,
    AEADTestCase("tests/aesgcmsiv_wycheproof.json", 1 /*notes*/),
    noop,
    &aead::AES_128_GCM
);
