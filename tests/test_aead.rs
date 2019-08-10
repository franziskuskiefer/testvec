use testvec::aead::*;

struct AEADTestCase(&'static str, usize);

macro_rules! test_aead_gen {
    ($func_name:ident, $test_case:expr) => {
        #[test]
        fn $func_name() {
            println!(" === {:?} Test ===", stringify!($test_case.0));
            let p = AEADTestVector::new(($test_case.0).to_string());
            assert!(p.is_ok());
            let p = p.unwrap();

            println!("test cases:\n{:?}", p);
            let notes = p.get_notes();
            println!("notes:\n{:?}", notes);
            assert!(notes.len() == $test_case.1);
        }
    };
}

test_aead_gen!(
    chacha,
    AEADTestCase("tests/chacha20poly1305_wycheproof.json", 0 /*notes*/)
);
test_aead_gen!(
    aesgcm,
    AEADTestCase("tests/aesgcm_wycheproof.json", 2 /*notes*/)
);
test_aead_gen!(
    aesgcmsiv,
    AEADTestCase("tests/aesgcmsiv_wycheproof.json", 1 /*notes*/)
);
