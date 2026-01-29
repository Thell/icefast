// Benching for base implmentation of ICE
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[macro_use]
extern crate bencher;
use bencher::Bencher;

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

fn encrypt_8_fast_level0_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let datax = EXPECT_TEXT_8.as_bytes().to_owned();
    bench.iter(|| {
        let mut data = datax.clone();
        test_ice.encrypt(&mut data);
        assert_eq!(data, CIPHER_TEXT_8_LEVEL0);
    });
}

fn decrypt_8_fast_level0_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(0, &KEY8);
    bench.iter(|| {
        let mut data = CIPHER_TEXT_8_LEVEL0.to_owned();
        test_ice.decrypt(&mut data);
        let plaintext = String::from_utf8(data.to_vec()).unwrap();
        assert_eq!(plaintext, EXPECT_TEXT_8);
    });
}

fn encrypt_8_fast_level1_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(1, &KEY8);
    let datax = EXPECT_TEXT_8.as_bytes().to_owned();
    bench.iter(|| {
        let mut data = datax.clone();
        test_ice.encrypt(&mut data);
        assert_eq!(data, CIPHER_TEXT_8_LEVEL1);
    });
}

fn decrypt_8_fast_level1_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(1, &KEY8);
    bench.iter(|| {
        let mut data = CIPHER_TEXT_8_LEVEL1.to_owned();
        test_ice.decrypt(&mut data);
        let plaintext = String::from_utf8(data.to_vec()).unwrap();
        assert_eq!(plaintext, EXPECT_TEXT_8);
    });
}

fn encrypt_8_fast_level2_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(2, &KEY16);
    let datax = EXPECT_TEXT_8.as_bytes().to_owned();
    bench.iter(|| {
        let mut data = datax.clone();
        test_ice.encrypt(&mut data);
        assert_eq!(data, CIPHER_TEXT_8_LEVEL2);
    });
}

fn decrypt_8_fast_level2_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(2, &KEY16);
    bench.iter(|| {
        let mut data = CIPHER_TEXT_8_LEVEL2.to_owned();
        test_ice.decrypt(&mut data);
        let plaintext = String::from_utf8(data.to_vec()).unwrap();
        assert_eq!(plaintext, EXPECT_TEXT_8);
    });
}

fn encrypt_8x10k_fast_level0_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let datax = EXPECT_TEXT_8.repeat(10000).as_bytes().to_owned();
    bench.iter(|| {
        let mut data = datax.clone();
        test_ice.encrypt(&mut data);
        assert_eq!(data.len(), datax.len());
    });
}

fn encrypt_8x10k_fast_par_level0_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let datax = EXPECT_TEXT_8.repeat(10000).as_bytes().to_owned();
    bench.iter(|| {
        let mut data = datax.clone();
        test_ice.encrypt_par(&mut data);
        assert_eq!(data.len(), datax.len());
    });
}

fn decrypt_8x10k_fast_level0_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let expect_text = EXPECT_TEXT_8.repeat(10000).as_bytes().to_owned();
    let mut cipher_text = expect_text.clone();
    test_ice.encrypt(&mut cipher_text);
    bench.iter(|| {
        let mut data = cipher_text.clone();
        test_ice.decrypt(&mut data);
        assert_eq!(data.len(), expect_text.len());
    });
}

fn decrypt_8x10k_fast_par_level0_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let expect_text = EXPECT_TEXT_8.repeat(10000).as_bytes().to_owned();
    let mut cipher_text = expect_text.clone();
    test_ice.encrypt(&mut cipher_text);
    bench.iter(|| {
        let mut data = cipher_text.clone();
        test_ice.decrypt_par(&mut data);
        assert_eq!(data.len(), expect_text.len());
    });
}

fn encrypt_16_fast_level0_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let datax = EXPECT_TEXT_16.as_bytes().to_owned();
    bench.iter(|| {
        let mut data = datax.clone();
        test_ice.encrypt(&mut data);
        assert_eq!(data, CIPHER_TEXT_16_LEVEL0);
    });
}

fn decrypt_16_fast_level0_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(0, &KEY8);
    bench.iter(|| {
        let mut data = CIPHER_TEXT_16_LEVEL0.to_owned();
        test_ice.decrypt(&mut data);
        let plaintext = String::from_utf8(data.to_vec()).unwrap();
        assert_eq!(plaintext, EXPECT_TEXT_16);
    });
}

fn encrypt_16_fast_level1_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(1, &KEY8);
    let datax = EXPECT_TEXT_16.as_bytes().to_owned();
    bench.iter(|| {
        let mut data = datax.clone();
        test_ice.encrypt(&mut data);
        assert_eq!(data, CIPHER_TEXT_16_LEVEL1);
    });
}

fn decrypt_16_fast_level1_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(1, &KEY8);
    bench.iter(|| {
        let mut data = CIPHER_TEXT_16_LEVEL1.to_owned();
        test_ice.decrypt(&mut data);
        let plaintext = String::from_utf8(data.to_vec()).unwrap();
        assert_eq!(plaintext, EXPECT_TEXT_16);
    });
}

fn encrypt_16_fast_level2_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(2, &KEY16);
    let datax = EXPECT_TEXT_16.as_bytes().to_owned();
    bench.iter(|| {
        let mut data = datax.clone();
        test_ice.encrypt(&mut data);
        assert_eq!(data, CIPHER_TEXT_16_LEVEL2);
    });
}

fn decrypt_16_fast_level2_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(2, &KEY16);
    bench.iter(|| {
        let mut data = CIPHER_TEXT_16_LEVEL2.to_owned();
        test_ice.decrypt(&mut data);
        let plaintext = String::from_utf8(data.to_vec()).unwrap();
        assert_eq!(plaintext, EXPECT_TEXT_16);
    });
}

fn encrypt_16x10k_fast_level0_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let datax = EXPECT_TEXT_16.repeat(10000).as_bytes().to_owned();
    bench.iter(|| {
        let mut data = datax.clone();
        test_ice.encrypt(&mut data);
        assert_eq!(data.len(), datax.len());
    });
}

fn encrypt_16x10k_fast_par_level0_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let datax = EXPECT_TEXT_16.repeat(10000).as_bytes().to_owned();
    bench.iter(|| {
        let mut data = datax.clone();
        test_ice.encrypt_par(&mut data);
        assert_eq!(data.len(), datax.len());
    });
}

fn decrypt_16x10k_fast_level0_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let expect_text = EXPECT_TEXT_16.repeat(10000).as_bytes().to_owned();
    let mut cipher_text = expect_text.clone();
    test_ice.encrypt(&mut cipher_text);
    bench.iter(|| {
        let mut data = cipher_text.clone();
        test_ice.decrypt(&mut data);
        assert_eq!(data.len(), expect_text.len());
    });
}

fn decrypt_16x10k_fast_par_level0_bench(bench: &mut Bencher) {
    let test_ice = icefast::Ice::new(0, &KEY8);
    let expect_text = EXPECT_TEXT_16.repeat(10000).as_bytes().to_owned();
    let mut cipher_text = expect_text.clone();
    test_ice.encrypt(&mut cipher_text);
    bench.iter(|| {
        let mut data = cipher_text.clone();
        test_ice.decrypt_par(&mut data);
        assert_eq!(data.len(), expect_text.len());
    });
}

benchmark_group!(
    bench_fast,
    encrypt_8_fast_level0_bench,
    decrypt_8_fast_level0_bench,
    encrypt_8_fast_level1_bench,
    decrypt_8_fast_level1_bench,
    encrypt_8_fast_level2_bench,
    decrypt_8_fast_level2_bench,
    encrypt_8x10k_fast_level0_bench,
    encrypt_8x10k_fast_par_level0_bench,
    decrypt_8x10k_fast_level0_bench,
    decrypt_8x10k_fast_par_level0_bench,
    encrypt_16_fast_level0_bench,
    decrypt_16_fast_level0_bench,
    encrypt_16_fast_level1_bench,
    decrypt_16_fast_level1_bench,
    encrypt_16_fast_level2_bench,
    decrypt_16_fast_level2_bench,
    encrypt_16x10k_fast_level0_bench,
    encrypt_16x10k_fast_par_level0_bench,
    decrypt_16x10k_fast_level0_bench,
    decrypt_16x10k_fast_par_level0_bench,
);
benchmark_main!(bench_fast);
