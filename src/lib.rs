//! # Icefast
//!
//! A high-performance implementation of the
//! [ICE (Information Concealment Engine)](https://www.darkside.com.au/ice/)
//! encryption algorithm.
//!
//! **Important:** ICE is an older block cipher and is **not considered
//! cryptographically secure** by modern standards. With contemporary hardware, especially GPUs
//! and large precomputed tables, it can be attacked far more efficiently than modern ciphers.
//! `Icefast` is intended for compatibility, experimentation, and educational use.
//! **It is not for protecting sensitive data.**
//!
//! `Icefast` is built to give the compiler the best possible chance at **auto‑vectorizing** the
//! hot loops and generating efficient jump tables. The internal loops use fixed bounds and
//! aligned memory access so the compiler can emit **AVX2**, **AVX‑512**, or **NEON** instructions
//! when it decides they’re beneficial for a particular loop. The dispatch layer is also fully
//! specialized at compile time to reduce branching and minimize overhead.
//!
//! Supports ICE level 0 (Thin-ICE), 1 and 2.
//!
//! ### Dispatching Logic
//! The library provides dispatching to balance latency and throughput:
//! * **Serial Path**: Used for smaller buffers to avoid the overhead of thread synchronization.
//! * **Parallel Path**: Utilizes Rayon for work-stealing parallelism on large data chunks (> 32 KB).
//! * **Tail Handling**: Recursive dispatch, using smaller block counts, is used to process the tail.
//!
//! ## Requirements
//! * **Alignment**: All input buffers must be multiples of the 8-byte ICE block size.
//! * **Data Size**: Manual `_chunk` processing functions require:
//!   - `B` to be a power of two
//!   - `data.len() >= B * 8` (where `8` is the BLOCK_SIZE constant)
//!
//! ## API Selection
//!
//! * **General Use**: Use `encrypt_auto` and `decrypt_auto`. Serial and parallel
//!   processing is automatically selected based on buffer size and tail processing is handled.
//! * **Serial Processing**: Use `encrypt` and `decrypt` to process serially with tail handling.
//! * **Parallel Processing**: Use `encrypt_par` or `decrypt_par` to process in parallel with tail handling.
//! * **High-Frequency Loops**: Use the `_chunks<B>` and `_chunks_par<B>` variants to bypass
//!   dispatching and tail processing.
//!
//! ## Performance
//! * **Benchmarks**: Run `cargo bench` to see performance comparisons between
//!   auto-dispatch and manual parallelism.
//!
//! ## Examples
//!
//! ```rust
//! use icefast::Ice;
//!
//! let key = [0x51, 0xF3, 0x0F, 0x11, 0x04, 0x24, 0x6A, 0x00];
//! let ice = Ice::new(0, &key);
//!
//! let mut data = vec![0u8; 1024]; // 1024 is a multiple of 8
//! ice.encrypt_auto(&mut data);
//! ice.decrypt_auto(&mut data);
//! ```

pub mod icefast;

pub use icefast::Ice;
