use rayon::prelude::*;

const BLOCK_SIZE: usize = 8;
const AUTO_PAR_THRESHOLD: usize = 32_768;

/// Must be power of 2; match statement implementation is limited to 256
const MAX_BLOCKS_PER_BATCH_PARALLEL: usize = 256;

/// Must be power of 2; match statement implementation is limited to 512
const MAX_BLOCKS_PER_BATCH_SERIAL: usize = 512;

const KEYROT: [i32; 16] = [0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2];

const ICE_SMOD: [[u32; 4]; 4] = [
    [333, 313, 505, 369],
    [379, 375, 319, 391],
    [361, 445, 451, 397],
    [397, 425, 395, 505],
];

const ICE_SXOR: [[u32; 4]; 4] = [
    [0x83, 0x85, 0x9b, 0xcd],
    [0xcc, 0xa7, 0xad, 0x41],
    [0x4b, 0x2e, 0xd4, 0x33],
    [0xea, 0xcb, 0x2e, 0x04],
];

const ICE_PBOX: [u32; 32] = [
    0x00000001, 0x00000080, 0x00000400, 0x00002000, 0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000, 0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000, 0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000, 0x00040000, 0x00100000, 0x02000000, 0x80000000,
];

const fn gf_mult(mut a: u32, mut b: u32, m: u32) -> u32 {
    let mut res: u32 = 0;
    while b != 0 {
        if (b & 1) != 0 {
            res ^= a;
        }
        a <<= 1;
        b >>= 1;
        if a >= 256 {
            a ^= m;
        }
    }
    res
}

const fn gf_exp7(b: u32, m: u32) -> u32 {
    if b == 0 {
        return 0;
    }
    let mut x = gf_mult(b, b, m);
    x = gf_mult(b, x, m);
    x = gf_mult(x, x, m);
    gf_mult(b, x, m)
}

const fn ice_perm32(mut x: u32) -> u32 {
    let mut res: u32 = 0;
    let mut i = 0;
    while i < 32 {
        if (x & 1) != 0 {
            res |= ICE_PBOX[i];
        }
        x >>= 1;
        i += 1;
    }
    res
}

const fn build_sboxes() -> [u32; 4096] {
    let mut out = [0u32; 4096];
    let mut i = 0;
    while i < 1024 {
        let col = ((i >> 1) & 0xff) as u32;
        let row = (i & 1) | ((i & 0x200) >> 8);

        out[i] = ice_perm32(gf_exp7(col ^ ICE_SXOR[0][row], ICE_SMOD[0][row]) << 24);
        out[1024 + i] = ice_perm32(gf_exp7(col ^ ICE_SXOR[1][row], ICE_SMOD[1][row]) << 16);
        out[2048 + i] = ice_perm32(gf_exp7(col ^ ICE_SXOR[2][row], ICE_SMOD[2][row]) << 8);
        out[3072 + i] = ice_perm32(gf_exp7(col ^ ICE_SXOR[3][row], ICE_SMOD[3][row]));
        i += 1;
    }
    out
}

type IceSboxes = [u32; 4096];
const ICE_SBOXES: IceSboxes = build_sboxes();

#[derive(Clone, Debug)]
pub struct IceSubkey {
    val: [u32; 3],
}

#[derive(Clone, Debug)]
pub struct IceKeyStruct {
    size: usize,
    rounds: usize,
    pub keysched: Vec<IceSubkey>,
}

#[derive(Clone, Debug)]
#[repr(C, align(64))]
pub struct Ice {
    sbox: IceSboxes,
    pub key: IceKeyStruct,
}

impl Ice {
    /// Create a new ICE instance.
    ///
    /// - `key` must be 8 bytes per `level`.
    /// - `level` must be in the range [0, 2].
    ///
    /// It is recommended to use Level 0 (or Thin-ICE) for most use cases for performance reasons.
    pub fn new(level: usize, key: &[u8]) -> Self {
        assert!(
            key.len() >= (if level < 1 { 1 } else { level }) * 8,
            "ICE key must be at least 8 bytes per level"
        );

        let mut ice = Ice {
            key: IceKeyStruct {
                size: if level < 1 { 1 } else { level },
                rounds: if level < 1 { 8 } else { level * 16 },
                keysched: Vec::new(),
            },
            sbox: ICE_SBOXES,
        };

        ice.key.keysched = vec![IceSubkey { val: [0; 3] }; ice.key.rounds];
        ice.key_set(key);
        ice
    }

    fn ice_f_batch<const B: usize>(&self, p: [u32; B], sk: &IceSubkey) -> [u32; B] {
        let mut res = [0u32; B];
        let s = &self.sbox;

        for i in 0..B {
            let val = p[i];
            let tr = (val & 0x3ff) | ((val << 2) & 0xffc00);
            let tl = ((val >> 16) & 0x3ff) | (val.rotate_left(18) & 0xffc00);

            let al_base = sk.val[2] & (tl ^ tr);
            let al = al_base ^ tl ^ sk.val[0];
            let ar = al_base ^ tr ^ sk.val[1];

            res[i] = s[((al >> 10) & 0x3ff) as usize]
                | s[1024 + (al & 0x3ff) as usize]
                | s[2048 + ((ar >> 10) & 0x3ff) as usize]
                | s[3072 + (ar & 0x3ff) as usize];
        }
        res
    }

    fn process_chunk<const B: usize, const DECRYPT: bool>(&self, chunk: &mut [u8]) {
        // This assertion allows the compiler to eliminate all bounds checks from the hot loop.
        assert!(chunk.len() == B * BLOCK_SIZE);

        let mut l = [0u32; B];
        let mut r = [0u32; B];

        for i in 0..B {
            let off = i * 8;
            l[i] = u32::from_be_bytes(chunk[off..off + 4].try_into().unwrap());
            r[i] = u32::from_be_bytes(chunk[off + 4..off + 8].try_into().unwrap());
        }

        if DECRYPT {
            for pair in self.key.keysched.rchunks_exact(2) {
                let f_r = self.ice_f_batch::<B>(r, &pair[1]);
                for i in 0..B {
                    l[i] ^= f_r[i];
                }
                let f_l = self.ice_f_batch::<B>(l, &pair[0]);
                for i in 0..B {
                    r[i] ^= f_l[i];
                }
            }
        } else {
            for pair in self.key.keysched.chunks_exact(2) {
                let f_r = self.ice_f_batch::<B>(r, &pair[0]);
                for i in 0..B {
                    l[i] ^= f_r[i];
                }
                let f_l = self.ice_f_batch::<B>(l, &pair[1]);
                for i in 0..B {
                    r[i] ^= f_l[i];
                }
            }
        }

        for i in 0..B {
            let off = i * 8;
            chunk[off..off + 4].copy_from_slice(&r[i].to_be_bytes());
            chunk[off + 4..off + 8].copy_from_slice(&l[i].to_be_bytes());
        }
    }

    /// Encrypts the provided data in-place.
    ///
    /// # Panics
    /// Panics if `data.len()` is not a positive multiple of 8.
    pub fn encrypt(&self, data: &mut [u8]) {
        self.dispatch_serial::<false>(data);
    }

    /// Decrypts the provided data in-place.
    ///
    /// # Panics
    /// Panics if `data.len()` is not a positive multiple of 8.
    pub fn decrypt(&self, data: &mut [u8]) {
        self.dispatch_serial::<true>(data);
    }

    fn dispatch_serial<const DECRYPT: bool>(&self, data: &mut [u8]) {
        let len = data.len();

        assert!(len.is_multiple_of(BLOCK_SIZE) && len >= BLOCK_SIZE);

        let blocks = len / BLOCK_SIZE;
        let prev_pow_2 = std::cmp::min(1usize << blocks.ilog2(), MAX_BLOCKS_PER_BATCH_SERIAL);
        let pow_2_exponent = prev_pow_2.ilog2();

        match pow_2_exponent {
            0 => self.process_serial::<1, DECRYPT>(data),
            1 => self.process_serial::<2, DECRYPT>(data),
            2 => self.process_serial::<4, DECRYPT>(data),
            3 => self.process_serial::<8, DECRYPT>(data),
            4 => self.process_serial::<16, DECRYPT>(data),
            5 => self.process_serial::<32, DECRYPT>(data),
            6 => self.process_serial::<64, DECRYPT>(data),
            7 => self.process_serial::<128, DECRYPT>(data),
            8 => self.process_serial::<256, DECRYPT>(data),
            9 => self.process_serial::<512, DECRYPT>(data),
            _ => unreachable!("pow_2_exponent should be guaranteed to be between 0 and 9"),
        }
    }

    fn process_serial<const B: usize, const DECRYPT: bool>(&self, data: &mut [u8]) {
        let len = data.len();

        assert!(len.is_multiple_of(BLOCK_SIZE));

        let chunk_size: usize = B * BLOCK_SIZE;
        let (head, tail) = { data.split_at_mut((len / chunk_size) * chunk_size) };

        head.chunks_exact_mut(chunk_size)
            .for_each(|c| self.process_chunk::<B, DECRYPT>(c));

        if tail.len() >= BLOCK_SIZE {
            self.dispatch_serial::<DECRYPT>(tail);
        }
    }

    /// Encrypts the provided data in-place in parallel.
    ///
    /// # Panics
    /// Panics if `data.len()` is not a multiple of 8.
    pub fn encrypt_par(&self, data: &mut [u8]) {
        self.dispatch_par::<false>(data);
    }

    /// Decrypts the provided data in-place in parallel.
    ///
    /// # Panics
    /// Panics if `data.len()` is not a multiple of 8.
    pub fn decrypt_par(&self, data: &mut [u8]) {
        self.dispatch_par::<true>(data);
    }

    fn dispatch_par<const DECRYPT: bool>(&self, data: &mut [u8]) {
        let len = data.len();

        assert!(len.is_multiple_of(BLOCK_SIZE) && len >= BLOCK_SIZE);

        let blocks = len / BLOCK_SIZE;
        let prev_pow_2 = std::cmp::min(1usize << blocks.ilog2(), MAX_BLOCKS_PER_BATCH_PARALLEL);
        let pow_2_exponent = prev_pow_2.ilog2();

        match pow_2_exponent {
            0 => self.process_par::<1, DECRYPT>(data),
            1 => self.process_par::<2, DECRYPT>(data),
            2 => self.process_par::<4, DECRYPT>(data),
            3 => self.process_par::<8, DECRYPT>(data),
            4 => self.process_par::<16, DECRYPT>(data),
            5 => self.process_par::<32, DECRYPT>(data),
            6 => self.process_par::<64, DECRYPT>(data),
            7 => self.process_par::<128, DECRYPT>(data),
            8 => self.process_par::<256, DECRYPT>(data),
            _ => unreachable!("pow_2_exponent should be guaranteed to be between 0 and 8"),
        }
    }

    fn process_par<const B: usize, const DECRYPT: bool>(&self, data: &mut [u8]) {
        let len = data.len();

        assert!(len.is_multiple_of(BLOCK_SIZE));

        let chunk_size: usize = B * BLOCK_SIZE;
        let (head, tail) = { data.split_at_mut((len / chunk_size) * chunk_size) };

        head.par_chunks_exact_mut(chunk_size)
            .for_each(|c| self.process_chunk::<B, DECRYPT>(c));

        if tail.len() >= BLOCK_SIZE {
            self.dispatch_par::<DECRYPT>(tail);
        }
    }

    /// Encrypts the provided data in-place.
    ///
    /// Switches between serial and parallel processing based on input length (32 KB).
    ///
    /// # Panics
    /// Panics if `data.len()` is not a positive multiple of 8.
    #[allow(unused)]
    pub fn encrypt_auto(&self, data: &mut [u8]) {
        if data.len() >= AUTO_PAR_THRESHOLD {
            if rayon::current_num_threads() < 2 {
                self.dispatch_serial::<false>(data);
                return;
            }
            self.dispatch_par::<false>(data);
        } else {
            self.dispatch_serial::<false>(data);
        }
    }

    /// Decrypts the provided data in-place.
    ///
    /// Switches between serial and parallel processing based on input length (32 KB).
    ///
    /// # Panics
    /// Panics if `data.len()` is not a positive multiple of 8.
    #[allow(unused)]
    pub fn decrypt_auto(&self, data: &mut [u8]) {
        let len = data.len();
        if len >= AUTO_PAR_THRESHOLD {
            if rayon::current_num_threads() < 2 {
                self.dispatch_serial::<true>(data);
                return;
            }
            self.dispatch_par::<true>(data);
        } else {
            self.dispatch_serial::<true>(data);
        }
    }

    /// Encrypts the provided data in-place using B 8-byte blocks.
    ///
    /// # Panics
    /// Panics if `data.len()` is not a positive multiple of B.
    #[allow(unused)]
    pub fn encrypt_chunks<const B: usize>(&self, data: &mut [u8]) {
        assert!(data.len().is_multiple_of(BLOCK_SIZE) && data.len() >= B * BLOCK_SIZE);
        data.chunks_exact_mut(B * BLOCK_SIZE)
            .for_each(|c| self.process_chunk::<B, false>(c));
    }

    /// Encrypts the provided data in-place using B 8-byte blocks in parallel.
    ///
    /// # Panics
    /// Panics if `data.len()` is not a positive multiple of B.
    #[allow(unused)]
    pub fn encrypt_chunks_par<const B: usize>(&self, data: &mut [u8]) {
        assert!(data.len().is_multiple_of(BLOCK_SIZE) && data.len() >= B * BLOCK_SIZE);
        data.par_chunks_exact_mut(B * BLOCK_SIZE)
            .for_each(|c| self.process_chunk::<B, false>(c));
    }

    /// Decrypts the provided data in-place using B 8-byte blocks
    ///
    /// # Panics
    /// Panics if `data.len()` is not a positive multiple of B.
    #[allow(unused)]
    pub fn decrypt_chunks<const B: usize>(&self, data: &mut [u8]) {
        assert!(data.len().is_multiple_of(BLOCK_SIZE) && data.len() >= B * BLOCK_SIZE);
        data.chunks_exact_mut(B * BLOCK_SIZE)
            .for_each(|c| self.process_chunk::<B, true>(c));
    }

    /// Decrypts the provided data in-place using B 8-byte blocks in parallel
    ///
    /// # Panics
    /// Panics if `data.len()` is not a positive multiple of B.
    #[allow(unused)]
    pub fn decrypt_chunks_par<const B: usize>(&self, data: &mut [u8]) {
        assert!(data.len().is_multiple_of(BLOCK_SIZE) && data.len() >= B * BLOCK_SIZE);
        data.par_chunks_exact_mut(B * BLOCK_SIZE)
            .for_each(|c| self.process_chunk::<B, true>(c));
    }

    fn key_sched_build(&mut self, kb: &mut [u16; 4], n: usize, keyrot: &[i32]) {
        for (i, &kr) in keyrot.iter().enumerate().take(8) {
            let isk = &mut self.key.keysched[n + i];
            isk.val.fill(0);
            for j in 0..15 {
                let curr_sk = &mut isk.val[j % 3];
                for k in 0..4 {
                    let curr_kb = &mut kb[((kr + k) & 3) as usize];
                    let bit = *curr_kb & 1;
                    *curr_sk = (*curr_sk << 1) | bit as u32;
                    *curr_kb = (*curr_kb >> 1) | ((bit ^ 1) << 15);
                }
            }
        }
    }

    /// Set the key to be used by the ICE instance.
    fn key_set(&mut self, key: &[u8]) {
        let levels = self.key.size;
        if levels == 1 && self.key.rounds == 8 {
            let mut kb = [0u16; 4];
            for i in 0..4 {
                kb[3 - i] = u16::from_be_bytes([key[i * 2], key[i * 2 + 1]]);
            }
            self.key_sched_build(&mut kb, 0, &KEYROT);
            return;
        }

        for i in 0..levels {
            let mut kb = [0u16; 4];
            for j in 0..4 {
                let base = i * 8 + j * 2;
                kb[3 - j] = u16::from_be_bytes([key[base], key[base + 1]]);
            }
            self.key_sched_build(&mut kb, i * 8, &KEYROT);
            self.key_sched_build(&mut kb, self.key.rounds - 8 - i * 8, &KEYROT[8..16]);
        }
    }
}
