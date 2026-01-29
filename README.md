# Information Concealment Engine

This is my attempt at implementing [ICE][darkside] with SIMD instructions.
I am specifically aiming at use in decrypting for a specific key using Thin-ICE
but I don't plan on optimizing the instance creation (sbox lookup table, and
simd Galois functions) or Thin-ICE itself until I figure out how to get the
main `ice_f()` loop vectorized.

[update] I did get the ice_f and salt/mix implemented using u32x4 and u32x8 types
but my SIMD implementation was not good and the best I could get was
just over double the runtime of the baseline implementation, so I will let the
compiler take care of it. The time overhead of converting into the registers
and the creation of the intermediate registers absolutely killed the time.

* _Level 0 (or Thin-ICE) uses 8 rounds, while higher levels n use 16n rounds._

## Start

I will be using Matthew's c code as a reference implementation and, hopefully,
incrementally adding intrinsics. First, basic optimizations to the rust code
will be done to make things easier.

Testing is done using bytes from from the original c source code for `abcdefgh` at each level.

## Notes 1

After some initial cleanup and changes these are the improvements seen...

__Initial__: (Release build)

```python
running 8 tests
test decrypt_level0_10kbench ... bench:     429,745 ns/iter (+/- 14,646)
test decrypt_level0_bench    ... bench:         138 ns/iter (+/- 2)
test decrypt_level1_bench    ... bench:         189 ns/iter (+/- 3)
test decrypt_level2_bench    ... bench:         270 ns/iter (+/- 12)
test encrypt_level0_10kbench ... bench:     431,752 ns/iter (+/- 9,430)
test encrypt_level0_bench    ... bench:         127 ns/iter (+/- 23)
test encrypt_level1_bench    ... bench:         175 ns/iter (+/- 2)
test encrypt_level2_bench    ... bench:         260 ns/iter (+/- 1)
```

__Initial__: (Release build with Opt-Level 3, LTO, codegen-units 1, native cpu)

```python
running 8 tests
test decrypt_level0_10kbench ... bench:     399,127 ns/iter (+/- 83,596)
test decrypt_level0_bench    ... bench:         133 ns/iter (+/- 2)
test decrypt_level1_bench    ... bench:         190 ns/iter (+/- 60)
test decrypt_level2_bench    ... bench:         258 ns/iter (+/- 8)
test encrypt_level0_10kbench ... bench:     395,702 ns/iter (+/- 48,113)
test encrypt_level0_bench    ... bench:         123 ns/iter (+/- 2)
test encrypt_level1_bench    ... bench:         170 ns/iter (+/- 4)
test encrypt_level2_bench    ... bench:         248 ns/iter (+/- 3)
```

__Phase 1__: (Cleanup, flow, iterator usage, in-place encrypt/decrypt - Release w/o Opts)

```python
running 8 tests
test decrypt_fast_level0_10kbench ... bench:     393,635 ns/iter (+/- 9,490)
test decrypt_fast_level0_bench    ... bench:         125 ns/iter (+/- 2)
test decrypt_fast_level1_bench    ... bench:         159 ns/iter (+/- 2)
test decrypt_fast_level2_bench    ... bench:         232 ns/iter (+/- 5)
test encrypt_fast_level0_10kbench ... bench:     309,420 ns/iter (+/- 3,900)
test encrypt_fast_level0_bench    ... bench:         113 ns/iter (+/- 1)
test encrypt_fast_level1_bench    ... bench:         151 ns/iter (+/- 42)
test encrypt_fast_level2_bench    ... bench:         223 ns/iter (+/- 4)
```

__Phase 1__: (Release w/ options.)

```python
running 8 tests
test decrypt_fast_level0_10kbench ... bench:     312,087 ns/iter (+/- 6,475)
test decrypt_fast_level0_bench    ... bench:         117 ns/iter (+/- 3)
test decrypt_fast_level1_bench    ... bench:         154 ns/iter (+/- 2)
test decrypt_fast_level2_bench    ... bench:         230 ns/iter (+/- 5)
test encrypt_fast_level0_10kbench ... bench:     308,107 ns/iter (+/- 68,092)
test encrypt_fast_level0_bench    ... bench:         110 ns/iter (+/- 2)
test encrypt_fast_level1_bench    ... bench:         145 ns/iter (+/- 38)
test encrypt_fast_level2_bench    ... bench:         221 ns/iter (+/- 3)
```

Phase 1 Notes:

* The 10k runs are actually 20k bytes (the basic `abcdefgh` * 10k)
* Notice the decrypt 10k in __Phase 1__. I don't know what is going on there but if I replace
the reversed chunk iterator with a regular loop then the timing is `316,777` and `322,384` with
and without opts respectively. So my guess is that reversed `chunk_exact` iterators are __not__
treated the same as the forward iterators without compile opts.
I took a quick look with Godbolt and it didn't help much in identifying the issue so it might
be worth revisiting someday.

## Notes 2

I've identified where simd optimizations _could_ be made and a couple of places intrinsics
_could_ be used but the algo wont work for it because of the loop dependencies (that I can see).

Added in a larger chunk handling for 16 bytes as well as a parallel version with benchs/tests.

The expanded test cases for the baseline.

__Phase 2__: 16 byte test and bulk test

```python
test decrypt_16_level0_bench     ... bench:         271 ns/iter (+/- 30)
test decrypt_16_level1_bench     ... bench:         405 ns/iter (+/- 87)
test decrypt_16_level2_bench     ... bench:         527 ns/iter (+/- 11)
test decrypt_16x10k_level0_bench ... bench:     792,495 ns/iter (+/- 17,442)
test decrypt_8_level0_bench      ... bench:         130 ns/iter (+/- 2)
test decrypt_8_level1_bench      ... bench:         176 ns/iter (+/- 22)
test decrypt_8_level2_bench      ... bench:         265 ns/iter (+/- 50)
test decrypt_8x10k_level0_bench  ... bench:     397,712 ns/iter (+/- 83,366)
test encrypt_16_level0_bench     ... bench:         256 ns/iter (+/- 5)
test encrypt_16_level1_bench     ... bench:         352 ns/iter (+/- 9)
test encrypt_16_level2_bench     ... bench:         524 ns/iter (+/- 19)
test encrypt_16x10k_level0_bench ... bench:     796,459 ns/iter (+/- 29,059)
test encrypt_8_level0_bench      ... bench:         116 ns/iter (+/- 6)
test encrypt_8_level1_bench      ... bench:         169 ns/iter (+/- 2)
test encrypt_8_level2_bench      ... bench:         243 ns/iter (+/- 4)
test encrypt_8x10k_level0_bench  ... bench:     399,414 ns/iter (+/- 3,025)
```

__Phase 2__: 16 byte test and bulk test for the fast and par versions.

```python
running 20 tests
test decrypt_16_fast_level0_bench         ... bench:         125 ns/iter (+/- 7)
test decrypt_16_fast_level1_bench         ... bench:         166 ns/iter (+/- 1)
test decrypt_16_fast_level2_bench         ... bench:         252 ns/iter (+/- 2)
test decrypt_16x10k_fast_level0_bench     ... bench:     435,142 ns/iter (+/- 22,082)
test decrypt_16x10k_fast_par_level0_bench ... bench:     126,264 ns/iter (+/- 4,494)
test decrypt_8_fast_level0_bench          ... bench:         122 ns/iter (+/- 2)
test decrypt_8_fast_level1_bench          ... bench:         156 ns/iter (+/- 1)
test decrypt_8_fast_level2_bench          ... bench:         229 ns/iter (+/- 42)
test decrypt_8x10k_fast_level0_bench      ... bench:     209,768 ns/iter (+/- 1,562)
test decrypt_8x10k_fast_par_level0_bench  ... bench:      73,726 ns/iter (+/- 3,424)
test encrypt_16_fast_level0_bench         ... bench:         121 ns/iter (+/- 1)
test encrypt_16_fast_level1_bench         ... bench:         164 ns/iter (+/- 4)
test encrypt_16_fast_level2_bench         ... bench:         246 ns/iter (+/- 2)
test encrypt_16x10k_fast_level0_bench     ... bench:     422,600 ns/iter (+/- 6,905)
test encrypt_16x10k_fast_par_level0_bench ... bench:     125,868 ns/iter (+/- 5,416)
test encrypt_8_fast_level0_bench          ... bench:         110 ns/iter (+/- 15)
test encrypt_8_fast_level1_bench          ... bench:         147 ns/iter (+/- 1)
test encrypt_8_fast_level2_bench          ... bench:         220 ns/iter (+/- 4)
test encrypt_8x10k_fast_level0_bench      ... bench:     212,656 ns/iter (+/- 27,392)
test encrypt_8x10k_fast_par_level0_bench  ... bench:      72,282 ns/iter (+/- 4,787)
```

__Phase 2__: Replaced the std allocator with mimalloc for the optimized version yielding
a notable improvement on the small tests.

```python
test decrypt_16_fast_level0_bench         ... bench:          71 ns/iter (+/- 13)
test decrypt_16_fast_level1_bench         ... bench:         126 ns/iter (+/- 28)
test decrypt_16_fast_level2_bench         ... bench:         185 ns/iter (+/- 1)
test decrypt_16x10k_fast_level0_bench     ... bench:     451,815 ns/iter (+/- 5,432)
test decrypt_16x10k_fast_par_level0_bench ... bench:     171,748 ns/iter (+/- 6,207)
test decrypt_8_fast_level0_bench          ... bench:          46 ns/iter (+/- 2)
test decrypt_8_fast_level1_bench          ... bench:          81 ns/iter (+/- 4)
test decrypt_8_fast_level2_bench          ... bench:         157 ns/iter (+/- 4)
test decrypt_8x10k_fast_level0_bench      ... bench:     224,378 ns/iter (+/- 1,803)
test decrypt_8x10k_fast_par_level0_bench  ... bench:      95,824 ns/iter (+/- 2,774)
test encrypt_16_fast_level0_bench         ... bench:          51 ns/iter (+/- 0)
test encrypt_16_fast_level1_bench         ... bench:          91 ns/iter (+/- 3)
test encrypt_16_fast_level2_bench         ... bench:         177 ns/iter (+/- 1)
test encrypt_16x10k_fast_level0_bench     ... bench:     442,265 ns/iter (+/- 6,230)
test encrypt_16x10k_fast_par_level0_bench ... bench:     129,188 ns/iter (+/- 12,137)
test encrypt_8_fast_level0_bench          ... bench:          41 ns/iter (+/- 18)
test encrypt_8_fast_level1_bench          ... bench:          78 ns/iter (+/- 27)
test encrypt_8_fast_level2_bench          ... bench:         152 ns/iter (+/- 5)
test encrypt_8x10k_fast_level0_bench      ... bench:     220,593 ns/iter (+/- 1,594)
test encrypt_8x10k_fast_par_level0_bench  ... bench:      71,772 ns/iter (+/- 5,827)
```

## Notes 3

It seems there is a substantial SIMD boost available during the ICE rounds even
though the SBOX lookup is still done via general register loads. The trick was
just going wide enough to offset the cost of swapping between the vectors and
registers. With a 4-round `ice_f` the benches stayed flat but with an 8-round
`ice_f` the AVX2 pipeline was filled and effectively used. If someone had AVX512
then a 16-round `ice_f` would likely be appropriate.

I will be changing the benchmarks to not measure the allocation overhead and to
more directly compare the width being used. The following benchmark serves as
the 'after' of implementing the 8-round `ice_f` with the previouslt used setup.

```
test decrypt_16_fast_level0_bench         ... bench:          69 ns/iter (+/- 3)
test decrypt_16_fast_level1_bench         ... bench:         130 ns/iter (+/- 5)
test decrypt_16_fast_level2_bench         ... bench:         250 ns/iter (+/- 7)
test decrypt_16x10k_fast_level0_bench     ... bench:     280,709 ns/iter (+/- 10,425)
test decrypt_16x10k_fast_par_level0_bench ... bench:      63,032 ns/iter (+/- 7,250)
test decrypt_8_fast_level0_bench          ... bench:          42 ns/iter (+/- 2)
test decrypt_8_fast_level1_bench          ... bench:          71 ns/iter (+/- 3)
test decrypt_8_fast_level2_bench          ... bench:         131 ns/iter (+/- 2)
test decrypt_8x10k_fast_level0_bench      ... bench:     139,335 ns/iter (+/- 6,128)
test decrypt_8x10k_fast_par_level0_bench  ... bench:      41,191 ns/iter (+/- 2,671)
test encrypt_16_fast_level0_bench         ... bench:          65 ns/iter (+/- 2)
test encrypt_16_fast_level1_bench         ... bench:         125 ns/iter (+/- 4)
test encrypt_16_fast_level2_bench         ... bench:         250 ns/iter (+/- 16)
test encrypt_16x10k_fast_level0_bench     ... bench:     276,949 ns/iter (+/- 11,750)
test encrypt_16x10k_fast_par_level0_bench ... bench:      63,245 ns/iter (+/- 6,177)
test encrypt_8_fast_level0_bench          ... bench:          36 ns/iter (+/- 1)
test encrypt_8_fast_level1_bench          ... bench:          66 ns/iter (+/- 3)
test encrypt_8_fast_level2_bench          ... bench:         128 ns/iter (+/- 4)
test encrypt_8x10k_fast_level0_bench      ... bench:     137,755 ns/iter (+/- 21,205)
test encrypt_8x10k_fast_par_level0_bench  ... bench:      41,527 ns/iter (+/- 7,189)
```

**New Benchmark Setup**



[darkside]: http://www.darkside.com.au/ice/description.html
