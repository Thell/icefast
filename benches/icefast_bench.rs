use divan::counter::BytesCount;
use ice::icefast::Ice;
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

static KEY8: [u8; 8] = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];
static PLAIN_TEXT_8: &str = "abcdefgh";
static CIPHER_TEXT_8_LEVEL0: [u8; 8] = [195, 233, 103, 103, 181, 234, 50, 163];

const BLOCKS: [usize; 3] = [2usize.pow(10), 2usize.pow(20), 2usize.pow(25)];
const BLOCKS_PAR: [usize; 4] = [
    2usize.pow(10),
    2usize.pow(20),
    2usize.pow(25),
    2usize.pow(30),
];

fn main() {
    divan::main();
}

trait BenchBatch {
    const BATCH: usize;

    fn run_encrypt(ice: &Ice, data: &mut [u8]);
    fn run_encrypt_par(ice: &Ice, data: &mut [u8]);
    fn run_decrypt(ice: &Ice, data: &mut [u8]);
    fn run_decrypt_par(ice: &Ice, data: &mut [u8]);
}

macro_rules! impl_bench_batch {
    ($name:ident, $n:expr) => {
        struct $name;
        impl BenchBatch for $name {
            const BATCH: usize = $n;

            #[inline(always)]
            fn run_encrypt(ice: &Ice, data: &mut [u8]) {
                let batch_bytes = $n * 8;
                data.chunks_exact_mut(batch_bytes).for_each(|chunk| {
                    ice.encrypt_blocks::<$n>(chunk);
                });
            }

            #[inline(always)]
            fn run_encrypt_par(ice: &Ice, data: &mut [u8]) {
                ice.encrypt_blocks_par::<$n>(data);
            }

            #[inline(always)]
            fn run_decrypt(ice: &Ice, data: &mut [u8]) {
                let batch_bytes = $n * 8;
                data.chunks_exact_mut(batch_bytes).for_each(|chunk| {
                    ice.decrypt_blocks::<$n>(chunk);
                });
            }

            #[inline(always)]
            fn run_decrypt_par(ice: &Ice, data: &mut [u8]) {
                ice.decrypt_blocks_par::<$n>(data);
            }
        }
    };
}

impl_bench_batch!(Batch8, 8);
impl_bench_batch!(Batch16, 16);
impl_bench_batch!(Batch32, 32);
impl_bench_batch!(Batch64, 64);
impl_bench_batch!(Batch128, 128);

#[divan::bench(types = [Batch8, Batch16, Batch32, Batch64, Batch128], args = BLOCKS)]
fn encrypt_key8_level0<C: BenchBatch>(bencher: divan::Bencher, len: usize) {
    let test_ice = Ice::new(0, &KEY8);
    let batch_bytes = C::BATCH * 8;
    let adjusted_len = (len / batch_bytes) * batch_bytes;

    let plain_text = PLAIN_TEXT_8.repeat(adjusted_len / 8).into_bytes();

    bencher
        .counter(BytesCount::new(adjusted_len))
        .with_inputs(|| plain_text.clone())
        .bench_local_values(|mut buffer| {
            C::run_encrypt(&test_ice, &mut buffer);
            divan::black_box(buffer);
        });
}

#[divan::bench(types = [Batch8, Batch16, Batch32, Batch64, Batch128], args = BLOCKS_PAR)]
fn encrypt_key8_level0_par<C: BenchBatch>(bencher: divan::Bencher, len: usize) {
    let test_ice = Ice::new(0, &KEY8);
    let batch_bytes = C::BATCH * 8;
    let adjusted_len = (len / batch_bytes) * batch_bytes;

    let plain_text = PLAIN_TEXT_8.repeat(adjusted_len / 8).into_bytes();

    bencher
        .counter(BytesCount::new(adjusted_len))
        .with_inputs(|| plain_text.clone())
        .bench_local_values(|mut buffer| {
            C::run_encrypt_par(&test_ice, &mut buffer);
            divan::black_box(buffer);
        });
}

#[divan::bench(types = [Batch8, Batch16, Batch32, Batch64, Batch128], args = BLOCKS)]
fn decrypt_key8_level0<C: BenchBatch>(bencher: divan::Bencher, len: usize) {
    let test_ice = Ice::new(0, &KEY8);
    let batch_bytes = C::BATCH * 8;
    let adjusted_len = (len / batch_bytes) * batch_bytes;

    let cipher_text = CIPHER_TEXT_8_LEVEL0.repeat(adjusted_len / 8);

    bencher
        .counter(BytesCount::new(adjusted_len))
        .with_inputs(|| cipher_text.clone())
        .bench_local_values(|mut buffer| {
            C::run_decrypt(&test_ice, &mut buffer);
            divan::black_box(buffer);
        });
}

#[divan::bench(types = [Batch8, Batch16, Batch32, Batch64, Batch128], args = BLOCKS_PAR)]
fn decrypt_key8_level0_par<C: BenchBatch>(bencher: divan::Bencher, len: usize) {
    let test_ice = Ice::new(0, &KEY8);
    let batch_bytes = C::BATCH * 8;
    let adjusted_len = (len / batch_bytes) * batch_bytes;

    let cipher_text = CIPHER_TEXT_8_LEVEL0.repeat(adjusted_len / 8);

    bencher
        .counter(BytesCount::new(adjusted_len))
        .with_inputs(|| cipher_text.clone())
        .bench_local_values(|mut buffer| {
            C::run_decrypt_par(&test_ice, &mut buffer);
            divan::black_box(buffer);
        });
}

#[divan::bench(args = BLOCKS_PAR)]
fn encrypt_auto(bencher: divan::Bencher, len: usize) {
    let test_ice = Ice::new(0, &KEY8);
    let plain_text = PLAIN_TEXT_8.repeat(len / 8).into_bytes();

    bencher
        .counter(BytesCount::new(len))
        .with_inputs(|| plain_text.clone())
        .bench_local_values(|mut buffer| {
            test_ice.encrypt(&mut buffer);
            divan::black_box(buffer);
        });
}

#[divan::bench(args = BLOCKS_PAR)]
fn decrypt_auto(bencher: divan::Bencher, len: usize) {
    let test_ice = Ice::new(0, &KEY8);
    let cipher_text = CIPHER_TEXT_8_LEVEL0.repeat(len / 8);

    bencher
        .counter(BytesCount::new(len))
        .with_inputs(|| cipher_text.clone())
        .bench_local_values(|mut buffer| {
            test_ice.decrypt(&mut buffer);
            divan::black_box(buffer);
        });
}
