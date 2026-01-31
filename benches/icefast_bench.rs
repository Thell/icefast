use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

use divan::counter::BytesCount;
use icefast::Ice;

static KEY8: [u8; 8] = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];
static PLAIN_TEXT_8: &str = "abcdefgh";
static CIPHER_TEXT_8_LEVEL0: [u8; 8] = [195, 233, 103, 103, 181, 234, 50, 163];

fn main() {
    divan::main();
}

trait BenchBatch {
    const BLOCKS: usize;
    fn run_decrypt(ice: &Ice, data: &mut [u8]);
    fn run_decrypt_par(ice: &Ice, data: &mut [u8]);
    fn run_encrypt(ice: &Ice, data: &mut [u8]);
    fn run_encrypt_par(ice: &Ice, data: &mut [u8]);
}

macro_rules! impl_bench_batch {
    ($name:ident, $n:expr) => {
        struct $name;
        impl BenchBatch for $name {
            const BLOCKS: usize = $n;
            #[inline(always)]
            fn run_decrypt(ice: &Ice, data: &mut [u8]) {
                data.chunks_exact_mut($n * 8)
                    .for_each(|chunk| ice.decrypt_blocks::<$n>(chunk));
            }
            #[inline(always)]
            fn run_decrypt_par(ice: &Ice, data: &mut [u8]) {
                ice.decrypt_blocks_par::<$n>(data);
            }
            #[inline(always)]
            fn run_encrypt(ice: &Ice, data: &mut [u8]) {
                data.chunks_exact_mut($n * 8)
                    .for_each(|chunk| ice.encrypt_blocks::<$n>(chunk));
            }
            #[inline(always)]
            fn run_encrypt_par(ice: &Ice, data: &mut [u8]) {
                ice.encrypt_blocks_par::<$n>(data);
            }
        }
    };
}

impl_bench_batch!(Blocks1, 1);
impl_bench_batch!(Blocks2, 2);
impl_bench_batch!(Blocks4, 4);
impl_bench_batch!(Blocks8, 8);
impl_bench_batch!(Blocks16, 16);
impl_bench_batch!(Blocks32, 32);
impl_bench_batch!(Blocks64, 64);
impl_bench_batch!(Blocks128, 128);

macro_rules! define_size_benches {
    ($size:expr, $name_suffix:ident, small) => {
        #[divan::bench_group]
        mod $name_suffix {
            use super::*;
            const LEN: usize = $size;

            #[divan::bench(types = [Blocks1, Blocks2, Blocks4, Blocks8, Blocks16, Blocks32, Blocks64, Blocks128])]
            fn decrypt_serial<C: BenchBatch>(bencher: divan::Bencher) {
                if C::BLOCKS * 8 > LEN { return; }
                let ice = Ice::new(0, &KEY8);
                let data = CIPHER_TEXT_8_LEVEL0.repeat(LEN / 8);
                bencher.counter(BytesCount::new(LEN)).with_inputs(|| data.clone()).bench_local_values(|mut b| C::run_decrypt(&ice, &mut b));
            }

            #[divan::bench]
            fn auto_decrypt(bencher: divan::Bencher) {
                let ice = Ice::new(0, &KEY8);
                let data = CIPHER_TEXT_8_LEVEL0.repeat(LEN / 8);
                bencher.counter(BytesCount::new(LEN)).with_inputs(|| data.clone()).bench_local_values(|mut b| ice.decrypt_auto(&mut b));
            }

            #[divan::bench(types = [Blocks1, Blocks2, Blocks4, Blocks8, Blocks16, Blocks32, Blocks64, Blocks128])]
            fn encrypt_serial<C: BenchBatch>(bencher: divan::Bencher) {
                if C::BLOCKS * 8 > LEN { return; }
                let ice = Ice::new(0, &KEY8);
                // Convert String to Vec<u8> to satisfy &mut [u8] requirement
                let data = PLAIN_TEXT_8.repeat(LEN / 8).into_bytes();
                bencher.counter(BytesCount::new(LEN)).with_inputs(|| data.clone()).bench_local_values(|mut b| C::run_encrypt(&ice, &mut b));
            }

            #[divan::bench]
            fn auto_encrypt(bencher: divan::Bencher) {
                let ice = Ice::new(0, &KEY8);
                let data = PLAIN_TEXT_8.repeat(LEN / 8).into_bytes();
                bencher.counter(BytesCount::new(LEN)).with_inputs(|| data.clone()).bench_local_values(|mut b| ice.encrypt_auto(&mut b));
            }
        }
    };
    ($size:expr, $name_suffix:ident, large) => {
        #[divan::bench_group]
        mod $name_suffix {
            use super::*;
            const LEN: usize = $size;

            #[divan::bench(types = [Blocks1, Blocks2, Blocks4, Blocks8, Blocks16, Blocks32, Blocks64, Blocks128])]
            fn decrypt_par<C: BenchBatch>(bencher: divan::Bencher) {
                let ice = Ice::new(0, &KEY8);
                let data = CIPHER_TEXT_8_LEVEL0.repeat(LEN / 8);
                bencher.counter(BytesCount::new(LEN)).with_inputs(|| data.clone()).bench_local_values(|mut b| C::run_decrypt_par(&ice, &mut b));
            }

            #[divan::bench]
            fn auto_decrypt(bencher: divan::Bencher) {
                let ice = Ice::new(0, &KEY8);
                let data = CIPHER_TEXT_8_LEVEL0.repeat(LEN / 8);
                bencher.counter(BytesCount::new(LEN)).with_inputs(|| data.clone()).bench_local_values(|mut b| ice.decrypt_auto(&mut b));
            }

            #[divan::bench(types = [Blocks1, Blocks2, Blocks4, Blocks8, Blocks16, Blocks32, Blocks64, Blocks128])]
            fn encrypt_par<C: BenchBatch>(bencher: divan::Bencher) {
                let ice = Ice::new(0, &KEY8);
                let data = PLAIN_TEXT_8.repeat(LEN / 8).into_bytes();
                bencher.counter(BytesCount::new(LEN)).with_inputs(|| data.clone()).bench_local_values(|mut b| C::run_encrypt_par(&ice, &mut b));
            }

            #[divan::bench]
            fn auto_encrypt(bencher: divan::Bencher) {
                let ice = Ice::new(0, &KEY8);
                let data = PLAIN_TEXT_8.repeat(LEN / 8).into_bytes();
                bencher.counter(BytesCount::new(LEN)).with_inputs(|| data.clone()).bench_local_values(|mut b| ice.encrypt_auto(&mut b));
            }
        }
    };
}

// Micro-loads (Serial optimization focus)
define_size_benches!(16, ser_size_16_b, small);
define_size_benches!(32, ser_size_32_b, small);
define_size_benches!(64, ser_size_64_b, small);
define_size_benches!(128, ser_size_128_b, small);
define_size_benches!(256, ser_size_256_b, small);
define_size_benches!(512, ser_size_512_b, small);
define_size_benches!(1024, ser_size_1_k, small);
define_size_benches!(2048, ser_size_2_k, small);
// Overlap - Serial
define_size_benches!(4096, ser_size_4_k, small);
define_size_benches!(8192, ser_size_8_k, small);
define_size_benches!(16384, ser_size_16_k, small);
define_size_benches!(32768, ser_size_32_k, small);
// Overlap - Parallel
define_size_benches!(4096, par_size_4_k, large);
define_size_benches!(8192, par_size_8_k, large);
define_size_benches!(16384, par_size_16_k, large);
define_size_benches!(32768, par_size_32_k, large);
// Macro-loads (Parallel optimization focus)
define_size_benches!(65536, par_size_64_k, large);
define_size_benches!(131072, par_size_128_k, large);
define_size_benches!(262144, par_size_256_k, large);
define_size_benches!(524288, par_size_512_k, large);
define_size_benches!(1048576, par_size_1_m, large);
define_size_benches!(33554432, par_size_32_m, large);
