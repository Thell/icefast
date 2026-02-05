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
impl_bench_batch!(Blocks256, 256);
impl_bench_batch!(Blocks512, 512);
impl_bench_batch!(Blocks1024, 1024);
impl_bench_batch!(Blocks2048, 2048);
impl_bench_batch!(Blocks4096, 4096);
impl_bench_batch!(Blocks8192, 8192);

macro_rules! define_size_benches {
    ($size:expr, $name_suffix:ident, small) => {
        #[divan::bench_group(sample_count = 2_000)]
        mod $name_suffix {
            use super::*;
            const LEN: usize = $size;

            #[divan::bench(types = [Blocks1, Blocks2, Blocks4, Blocks8, Blocks16, Blocks32, Blocks64, Blocks128, Blocks256, Blocks512, Blocks1024, Blocks2048, Blocks4096, Blocks8192])]
            fn decrypt<C: BenchBatch>(bencher: divan::Bencher) {
                if C::BLOCKS * 8 > LEN { return; }
                let ice = Ice::new(0, &KEY8);
                bencher
                    .counter(BytesCount::new(LEN))
                    .with_inputs(|| CIPHER_TEXT_8_LEVEL0.repeat(LEN / 8))
                    .bench_refs(|mut b| C::run_decrypt(&ice, &mut b));
            }

            #[divan::bench]
            fn decrypt_auto(bencher: divan::Bencher) {
                let ice = Ice::new(0, &KEY8);
                bencher
                    .counter(BytesCount::new(LEN))
                    .with_inputs(|| CIPHER_TEXT_8_LEVEL0.repeat(LEN / 8))
                    .bench_refs(|mut b| ice.decrypt_auto(&mut b));
            }

            #[divan::bench(types = [Blocks1, Blocks2, Blocks4, Blocks8, Blocks16, Blocks32, Blocks64, Blocks128, Blocks256, Blocks512, Blocks1024, Blocks2048, Blocks4096, Blocks8192])]
            fn encrypt<C: BenchBatch>(bencher: divan::Bencher) {
                if C::BLOCKS * 8 > LEN { return; }
                let ice = Ice::new(0, &KEY8);
                bencher
                    .counter(BytesCount::new(LEN))
                    .with_inputs(|| PLAIN_TEXT_8.repeat(LEN / 8).into_bytes())
                    .bench_refs(|mut b| C::run_encrypt(&ice, &mut b));
            }

            #[divan::bench]
            fn encrypt_auto(bencher: divan::Bencher) {
                let ice = Ice::new(0, &KEY8);
                bencher
                    .counter(BytesCount::new(LEN))
                    .with_inputs(|| PLAIN_TEXT_8.repeat(LEN / 8).into_bytes())
                    .bench_refs(|mut b| ice.encrypt_auto(&mut b));
            }
        }
    };
    ($size:expr, $name_suffix:ident, large) => {
        #[divan::bench_group(sample_count=2_000)]
        mod $name_suffix {
            use super::*;
            const LEN: usize = $size;

            #[divan::bench(types = [Blocks1, Blocks2, Blocks4, Blocks8, Blocks16, Blocks32, Blocks64, Blocks128, Blocks256, Blocks512, Blocks1024, Blocks2048, Blocks4096, Blocks8192])]
            fn decrypt_par<C: BenchBatch>(bencher: divan::Bencher) {
                if C::BLOCKS * 8 > LEN { return; }
                let ice = Ice::new(0, &KEY8);
                bencher
                    .counter(BytesCount::new(LEN))
                    .with_inputs(|| CIPHER_TEXT_8_LEVEL0.repeat(LEN / 8))
                    .bench_refs(|mut b| C::run_decrypt_par(&ice, &mut b));
            }

            #[divan::bench]
            fn decrypt_auto(bencher: divan::Bencher) {
                let ice = Ice::new(0, &KEY8);
                bencher
                    .counter(BytesCount::new(LEN))
                    .with_inputs(|| CIPHER_TEXT_8_LEVEL0.repeat(LEN / 8))
                    .bench_refs(|mut b| ice.decrypt_auto(&mut b));
            }

            #[divan::bench(types = [Blocks1, Blocks2, Blocks4, Blocks8, Blocks16, Blocks32, Blocks64, Blocks128, Blocks256, Blocks512, Blocks1024, Blocks2048, Blocks4096, Blocks8192])]
            fn encrypt_par<C: BenchBatch>(bencher: divan::Bencher) {
                if C::BLOCKS * 8 > LEN { return; }
                let ice = Ice::new(0, &KEY8);
                bencher
                    .counter(BytesCount::new(LEN))
                    .with_inputs(|| PLAIN_TEXT_8.repeat(LEN / 8).into_bytes())
                    .bench_refs(|mut b| C::run_encrypt_par(&ice, &mut b));
            }

            #[divan::bench]
            fn encrypt_auto(bencher: divan::Bencher) {
                let ice = Ice::new(0, &KEY8);
                bencher
                    .counter(BytesCount::new(LEN))
                    .with_inputs(|| PLAIN_TEXT_8.repeat(LEN / 8).into_bytes())
                    .bench_refs(|mut d| ice.encrypt_auto(&mut d))
            }
        }
    };
}

// Micro-loads (Serial optimization focus)
define_size_benches!(16, serial_b_16, small);
define_size_benches!(32, serial_b_32, small);
define_size_benches!(64, serial_b_64, small);
define_size_benches!(128, serial_b_128, small);
define_size_benches!(256, serial_b_256, small);
define_size_benches!(512, serial_b_512, small);
define_size_benches!(1024, serial_kb_1, small);
define_size_benches!(2048, serial_kb_2, small);
define_size_benches!(4096, serial_kb_4, small);
define_size_benches!(8192, serial_kb_8, small);
define_size_benches!(16384, serial_kb_16, small);
define_size_benches!(32768, serial_kb_32, small);
define_size_benches!(65536, serial_kb_64, small);
define_size_benches!(131072, serial_kb_128, small);
define_size_benches!(262144, serial_kb_256, small);
define_size_benches!(524288, serial_kb_512, small);
define_size_benches!(1048576, serial_mb_1, small);

// Overlap - Parallel
define_size_benches!(16, parallel_b_16, large);
define_size_benches!(32, parallel_b_32, large);
define_size_benches!(64, parallel_b_64, large);
define_size_benches!(128, parallel_b_128, large);
define_size_benches!(256, parallel_b_256, large);
define_size_benches!(512, parallel_b_512, large);
define_size_benches!(1024, parallel_kb_1, large);
define_size_benches!(2048, parallel_kb_2, large);
define_size_benches!(4096, parallel_kb_4, large);
define_size_benches!(8192, parallel_kb_8, large);
define_size_benches!(16384, parallel_kb_16, large);
define_size_benches!(32768, parallel_kb_32, large);
define_size_benches!(65536, parallel_kb_64, large);
define_size_benches!(131072, parallel_kb_128, large);
define_size_benches!(262144, parallel_kb_256, large);
define_size_benches!(524288, parallel_kb_512, large);
define_size_benches!(1048576, parallel_mb_1, large);
define_size_benches!(33554432, parallel_mb_32, large);

////////////////////////////////////////////////////////////////////

// This benches what decrypting many random length files looks like
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::Rng;
use rand_chacha::rand_core::SeedableRng;

static WEIGHTS: &[u32] = &[
    1824, 768, 1392, 1536, 2016, 3312, 1344, 1200, 960, 432, 480, 768, 624, 144, 48, 96, 48,
];

static UPPERS: &[usize] = &[
    31, 63, 127, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767, 65535, 131071, 262143, 524287,
    1048575, 4194303,
];

fn next_u32(rng: &mut ChaCha8Rng) -> u32 {
    rng.next_u32()
}

fn pick_bucket(rng: &mut ChaCha8Rng) -> usize {
    let total: u32 = WEIGHTS.iter().copied().sum();
    let mut x = next_u32(rng) % total;
    for (i, w) in WEIGHTS.iter().copied().enumerate() {
        if x < w {
            return i;
        }
        x -= w;
    }
    WEIGHTS.len() - 1
}

fn random_file_size(rng: &mut ChaCha8Rng) -> usize {
    let idx = pick_bucket(rng);
    let max = UPPERS[idx];
    let r = next_u32(rng) as usize;
    1 + (r % max)
}

#[divan::bench]
fn decrypt_5000_random_files_auto(bencher: divan::Bencher) {
    let ice = Ice::new(0, &KEY8);
    let mut rng = ChaCha8Rng::from_seed([1; 32]);
    let mut file_buffers = Vec::with_capacity(5000);
    for _ in 0..5000 {
        let size = random_file_size(&mut rng);
        let blocks = (size + 7) / 8;
        let buf = CIPHER_TEXT_8_LEVEL0.repeat(blocks);
        file_buffers.push(buf);
    }
    let total_bytes: usize = file_buffers.iter().map(|b| b.len()).sum();
    bencher
        .counter(BytesCount::new(total_bytes))
        .with_inputs(|| file_buffers.clone())
        .bench_refs(|bufs| {
            for buf in bufs {
                ice.decrypt_auto(buf);
            }
        });
}

#[divan::bench]
fn par_decrypt_5000_random_files_auto(bencher: divan::Bencher) {
    use rayon::prelude::*;

    let ice = Ice::new(0, &KEY8);
    let mut rng = ChaCha8Rng::from_seed([1; 32]);
    let mut file_buffers = Vec::with_capacity(5000);
    for _ in 0..5000 {
        let size = random_file_size(&mut rng);
        let blocks = (size + 7) / 8;
        let buf = CIPHER_TEXT_8_LEVEL0.repeat(blocks);
        file_buffers.push(buf);
    }
    let total_bytes: usize = file_buffers.iter().map(|b| b.len()).sum();
    bencher
        .counter(BytesCount::new(total_bytes))
        .with_inputs(|| file_buffers.clone())
        .bench_refs(|bufs| {
            bufs.par_iter_mut().for_each(|buf| {
                ice.decrypt_auto(buf);
            });
        });
}

#[divan::bench]
fn decrypt_5000_random_files_serial(bencher: divan::Bencher) {
    let ice = Ice::new(0, &KEY8);
    let mut rng = ChaCha8Rng::from_seed([1; 32]);
    let mut file_buffers = Vec::with_capacity(5000);
    for _ in 0..5000 {
        let size = random_file_size(&mut rng);
        let blocks = (size + 7) / 8;
        let buf = CIPHER_TEXT_8_LEVEL0.repeat(blocks);
        file_buffers.push(buf);
    }
    let total_bytes: usize = file_buffers.iter().map(|b| b.len()).sum();
    bencher
        .counter(BytesCount::new(total_bytes))
        .with_inputs(|| file_buffers.clone())
        .bench_refs(|bufs| {
            for buf in bufs {
                ice.decrypt(buf);
            }
        });
}

#[divan::bench]
fn par_decrypt_5000_random_files_serial(bencher: divan::Bencher) {
    use rayon::prelude::*;

    let ice = Ice::new(0, &KEY8);
    let mut rng = ChaCha8Rng::from_seed([1; 32]);
    let mut file_buffers = Vec::with_capacity(5000);
    for _ in 0..5000 {
        let size = random_file_size(&mut rng);
        let blocks = (size + 7) / 8;
        let buf = CIPHER_TEXT_8_LEVEL0.repeat(blocks);
        file_buffers.push(buf);
    }
    let total_bytes: usize = file_buffers.iter().map(|b| b.len()).sum();
    bencher
        .counter(BytesCount::new(total_bytes))
        .with_inputs(|| file_buffers.clone())
        .bench_refs(|bufs| {
            bufs.par_iter_mut().for_each(|buf| {
                ice.decrypt(buf);
            });
        });
}

#[divan::bench]
fn decrypt_5000_random_files_par(bencher: divan::Bencher) {
    let ice = Ice::new(0, &KEY8);
    let mut rng = ChaCha8Rng::from_seed([1; 32]);
    let mut file_buffers = Vec::with_capacity(5000);
    for _ in 0..5000 {
        let size = random_file_size(&mut rng);
        let blocks = (size + 7) / 8;
        let buf = CIPHER_TEXT_8_LEVEL0.repeat(blocks);
        file_buffers.push(buf);
    }
    let total_bytes: usize = file_buffers.iter().map(|b| b.len()).sum();
    bencher
        .counter(BytesCount::new(total_bytes))
        .with_inputs(|| file_buffers.clone())
        .bench_refs(|bufs| {
            for buf in bufs {
                ice.decrypt_par(buf);
            }
        });
}

#[divan::bench]
fn par_decrypt_5000_random_files_par(bencher: divan::Bencher) {
    use rayon::prelude::*;

    let ice = Ice::new(0, &KEY8);
    let mut rng = ChaCha8Rng::from_seed([1; 32]);
    let mut file_buffers = Vec::with_capacity(5000);
    for _ in 0..5000 {
        let size = random_file_size(&mut rng);
        let blocks = (size + 7) / 8;
        let buf = CIPHER_TEXT_8_LEVEL0.repeat(blocks);
        file_buffers.push(buf);
    }
    let total_bytes: usize = file_buffers.iter().map(|b| b.len()).sum();
    bencher
        .counter(BytesCount::new(total_bytes))
        .with_inputs(|| file_buffers.clone())
        .bench_refs(|bufs| {
            bufs.par_iter_mut().for_each(|buf| {
                ice.decrypt_par(buf);
            });
        });
}
