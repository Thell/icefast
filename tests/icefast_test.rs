// Testing for fast implmentation of ICE
// use mimalloc::MiMalloc;

// #[global_allocator]
// static GLOBAL: MiMalloc = MiMalloc;

#[path = "../src/icefast.rs"]
mod icefast;

static KEY8: [u8; 8] = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];
static KEY16: [u8; 16] = [
    0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00, 0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00,
];

static EXPECT_TEXT_8: &str = "abcdefgh";
static CIPHER_TEXT_8_LEVEL0: [u8; 8] = [195, 233, 103, 103, 181, 234, 50, 163];
static CIPHER_TEXT_8_LEVEL1: [u8; 8] = [49, 188, 85, 204, 107, 67, 206, 70];
static CIPHER_TEXT_8_LEVEL2: [u8; 8] = [234, 6, 99, 4, 147, 138, 221, 23];
static EXPECT_TEXT_16: &str = "abcdefghijklmnop";
static CIPHER_TEXT_16_LEVEL0: [u8; 16] = [
    195, 233, 103, 103, 181, 234, 50, 163, 218, 3, 22, 226, 147, 169, 252, 216,
];
static CIPHER_TEXT_16_LEVEL1: [u8; 16] = [
    49, 188, 85, 204, 107, 67, 206, 70, 250, 115, 122, 182, 89, 128, 168, 130,
];
static CIPHER_TEXT_16_LEVEL2: [u8; 16] = [
    234, 6, 99, 4, 147, 138, 221, 23, 83, 147, 191, 140, 30, 224, 44, 137,
];

#[test]
fn encrypt_key8_fast_level0() {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let mut data = EXPECT_TEXT_8.as_bytes().to_owned();
    test_ice.encrypt(&mut data);
    assert_eq!(data, CIPHER_TEXT_8_LEVEL0);
}

#[test]
fn decrypt_key8_fast_level0() {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let mut data = CIPHER_TEXT_8_LEVEL0.to_owned();
    test_ice.decrypt(&mut data);
    let plaintext = String::from_utf8(data.to_vec()).unwrap();
    assert_eq!(plaintext, EXPECT_TEXT_8);
}

#[test]
fn encrypt_key8_fast_level1() {
    let test_ice = icefast::Ice::new(1, &KEY8);
    let mut data = EXPECT_TEXT_8.as_bytes().to_owned();
    test_ice.encrypt(&mut data);
    assert_eq!(data, CIPHER_TEXT_8_LEVEL1);
}

#[test]
fn decrypt_key8_fast_level1() {
    let test_ice = icefast::Ice::new(1, &KEY8);
    let mut data = CIPHER_TEXT_8_LEVEL1.to_owned();
    test_ice.decrypt(&mut data);
    assert_eq!(data, EXPECT_TEXT_8.as_bytes());
    let plaintext = String::from_utf8(data.to_vec()).unwrap();
    assert_eq!(plaintext, EXPECT_TEXT_8);
}

#[test]
fn encrypt_key8_fast_level2() {
    let test_ice = icefast::Ice::new(2, &KEY16);
    let mut data = EXPECT_TEXT_8.as_bytes().to_owned();
    test_ice.encrypt(&mut data);
    assert_eq!(data, CIPHER_TEXT_8_LEVEL2);
}

#[test]
fn decrypt_key8_fast_level2() {
    let test_ice = icefast::Ice::new(2, &KEY16);
    let mut data = CIPHER_TEXT_8_LEVEL2.to_owned();
    test_ice.decrypt(&mut data);
    let plaintext = String::from_utf8(data.to_vec()).unwrap();
    assert_eq!(plaintext, EXPECT_TEXT_8);
}

#[test]
fn encrypt_key16_fast_level0() {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let mut data = EXPECT_TEXT_16.as_bytes().to_owned();
    test_ice.encrypt(&mut data);
    assert_eq!(data, CIPHER_TEXT_16_LEVEL0);
}

#[test]
fn decrypt_key16_fast_level0() {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let mut data = CIPHER_TEXT_16_LEVEL0.to_owned();
    test_ice.decrypt(&mut data);
    let plaintext = String::from_utf8(data.to_vec()).unwrap();
    assert_eq!(plaintext, EXPECT_TEXT_16);
}

#[test]
fn encrypt_key16_fast_level1() {
    let test_ice = icefast::Ice::new(1, &KEY8);
    let mut data = EXPECT_TEXT_16.as_bytes().to_owned();
    test_ice.encrypt(&mut data);
    assert_eq!(data, CIPHER_TEXT_16_LEVEL1);
}

#[test]
fn decrypt_key16_fast_level1() {
    let test_ice = icefast::Ice::new(1, &KEY8);
    let mut data = CIPHER_TEXT_16_LEVEL1.to_owned();
    test_ice.decrypt(&mut data);
    assert_eq!(data, EXPECT_TEXT_16.as_bytes());
    let plaintext = String::from_utf8(data.to_vec()).unwrap();
    assert_eq!(plaintext, EXPECT_TEXT_16);
}

#[test]
fn encrypt_key16_fast_level2() {
    let test_ice = icefast::Ice::new(2, &KEY16);
    let mut data = EXPECT_TEXT_16.as_bytes().to_owned();
    test_ice.encrypt(&mut data);
    assert_eq!(data, CIPHER_TEXT_16_LEVEL2);
}

#[test]
fn decrypt_key16_fast_level2() {
    let test_ice = icefast::Ice::new(2, &KEY16);
    let mut data = CIPHER_TEXT_16_LEVEL2.to_owned();
    test_ice.decrypt(&mut data);
    let plaintext = String::from_utf8(data.to_vec()).unwrap();
    assert_eq!(plaintext, EXPECT_TEXT_16);
}

#[test]
fn decrypt_key16_fast_par_level0() {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let mut data = CIPHER_TEXT_16_LEVEL0.to_owned();
    test_ice.decrypt_par(&mut data);
    let plaintext = String::from_utf8(data.to_vec()).unwrap();
    assert_eq!(plaintext, EXPECT_TEXT_16);
}

#[test]
fn encrypt_key16_fast_par_level1() {
    let test_ice = icefast::Ice::new(1, &KEY8);
    let mut data = EXPECT_TEXT_16.as_bytes().to_owned();
    test_ice.encrypt_par(&mut data);
    assert_eq!(data, CIPHER_TEXT_16_LEVEL1);
}

#[test]
fn decrypt_key16_fast_par_level1() {
    let test_ice = icefast::Ice::new(1, &KEY8);
    let mut data = CIPHER_TEXT_16_LEVEL1.to_owned();
    test_ice.decrypt_par(&mut data);
    assert_eq!(data, EXPECT_TEXT_16.as_bytes());
    let plaintext = String::from_utf8(data.to_vec()).unwrap();
    assert_eq!(plaintext, EXPECT_TEXT_16);
}

#[test]
fn encrypt_key16_fast_par_level2() {
    let test_ice = icefast::Ice::new(2, &KEY16);
    let mut data = EXPECT_TEXT_16.as_bytes().to_owned();
    test_ice.encrypt_par(&mut data);
    assert_eq!(data, CIPHER_TEXT_16_LEVEL2);
}

#[test]
fn decrypt_key16_fast_par_level2() {
    let test_ice = icefast::Ice::new(2, &KEY16);
    let mut data = CIPHER_TEXT_16_LEVEL2.to_owned();
    test_ice.decrypt_par(&mut data);
    let plaintext = String::from_utf8(data.to_vec()).unwrap();
    assert_eq!(plaintext, EXPECT_TEXT_16);
}
