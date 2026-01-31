//! # Icefast
//!
//! A high-performance implementation of the ICE (Information Concealment Engine)
//! encryption algorithm, optimized for AVX2 and AVX-512 auto-vectorization.
//!
//! ## High-Performance Vectorization
//! `Icefast` is designed specifically to assist the LLVM compiler in performing
//! **auto-vectorization**. By structuring internal loops with clear bounds and memory
//! alignment, the library leverages **AVX2**, **AVX-512**, and **NEON** instruction
//! sets where available. This allows for processing multiple 64-bit blocks in a single
//! clock cycle.
//!
//! ### Auto-Dispatch Logic
//! The library provides intelligent dispatching to balance latency and throughput:
//! * **Serial Path**: Used for smaller buffers to avoid the overhead of thread synchronization.
//! * **Parallel Path**: Utilizes Rayon for work-stealing parallelism on large data chunks (> 8 KB).
//! * **Tail Handling**: The `_auto` methods process primary batches of size `B`, while
//!   automatically handling the remaining 8-byte blocks in a final serial pass.
//!
//! ## Requirements
//! * **Alignment**: All input buffers must be multiples of the 8-byte ICE block size.
//!   Operations on unaligned buffers will result in an explicit panic to ensure
//!   data integrity.
//!
//! //! ## API Selection
//!
//! * **General Use**: Use `encrypt_auto` and `decrypt_auto`. These manage batch sizes
//!   and thread dispatching automatically to find the best balance for the data size.
//! * **Manual Parallelism**: Use `encrypt_par` or `decrypt_par` if you know you want
//!   multithreading regardless of the 8 KB default threshold.
//! * **High-Frequency Loops**: Use `encrypt_blocks<B>` with a fixed `B` to provide
//!   the compiler with the best opportunity for unrolling and SIMD generation.
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
