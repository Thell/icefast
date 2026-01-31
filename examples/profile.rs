//! Profile ICE implementation
//! Usage: cargo run --release --example profile optimized 1000000
//! Usage: cargo run --release --example profile optimized_par 1000000
use mimalloc::MiMalloc;
use std::env;

use icefast::Ice;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
    let args: Vec<String> = env::args().collect();
    let test = &args[1];
    let text_len = &args[2];

    let ice_key = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];
    let base_text = "abcdefgh".to_string();
    let text = base_text.repeat(text_len.parse::<usize>().unwrap());

    match &test[..] {
        "optimized" => {
            let test_ice = Ice::new(0, &ice_key);
            let mut data = text.as_bytes().to_owned();
            test_ice.encrypt(&mut data);
            test_ice.decrypt(&mut data);
            assert_eq!(data, text.as_bytes());
        }
        "optimized_par" => {
            let test_ice = Ice::new(0, &ice_key);
            let mut data = text.as_bytes().to_owned();
            test_ice.encrypt_par(&mut data);
            test_ice.decrypt_par(&mut data);
            assert_eq!(data, text.as_bytes());
        }
        _ => {
            panic!("Unknown test: {}", test);
        }
    }
}
