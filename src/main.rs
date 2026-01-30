use mimalloc::MiMalloc;
use std::env;

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
        "baseline" => {
            let mut test_ice = ice::ice::Ice::new(0);
            test_ice.key_set(&ice_key);
            let mut ciphertext = Vec::new();
            let mut ctext = [0; 8];
            let mut ptext = [0; 8];
            text.as_bytes().chunks_exact(8).for_each(|chunk| {
                ptext.copy_from_slice(chunk);
                test_ice.encrypt(&ptext, &mut ctext);
                ciphertext.extend_from_slice(&ctext);
            });
            let mut plaintext = Vec::new();
            ciphertext.chunks_exact(8).for_each(|chunk| {
                ctext.copy_from_slice(chunk);
                test_ice.decrypt(&ctext, &mut ptext);
                plaintext.extend_from_slice(&ptext);
            });
            assert_eq!(plaintext, text.as_bytes());
        }
        "optimized" => {
            let test_ice = ice::icefast::Ice::new(0, &ice_key);
            let mut data = text.as_bytes().to_owned();
            test_ice.encrypt(&mut data);
            test_ice.decrypt(&mut data);
            assert_eq!(data, text.as_bytes());
        }
        "optimized_par" => {
            let test_ice = ice::icefast::Ice::new(0, &ice_key);
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
