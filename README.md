# Icefast

A high-performance implementation of the
[ICE (Information Concealment Engine)](https://www.darkside.com.au/ice/)
encryption algorithm.

**Important:** ICE is an older block cipher and is **not considered
cryptographically secure** by modern standards. With contemporary hardware, especially GPUs
and large precomputed tables, it can be attacked far more efficiently than modern ciphers.
`Icefast` is intended for compatibility, experimentation, and educational use.
**It is not for protecting sensitive data.**

`Icefast` is built to give the compiler the best possible chance at **auto‑vectorizing** the
hot loops and generating efficient jump tables. The internal loops use fixed bounds and
aligned memory access so the compiler can emit **AVX2**, **AVX‑512**, or **NEON** instructions
when it decides they’re beneficial for a particular loop. The dispatch layer is also fully
specialized at compile time to reduce branching and minimize overhead.

Supports ICE level 0 (Thin-ICE), 1 and 2.
