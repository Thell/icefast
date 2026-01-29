use rayon::prelude::*;

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

#[repr(C, align(64))]
#[derive(Clone, Debug)]
pub struct IceSboxes {
    pub s: [[u32; 1024]; 4],
}

impl IceSboxes {
    pub fn new() -> Self {
        Self { s: [[0; 1024]; 4] }
    }
}

#[derive(Clone, Debug)]
pub struct Ice {
    pub key: IceKeyStruct,
    sbox: IceSboxes,
}

const ICE_SMOD: [[i32; 4]; 4] = [
    [333, 313, 505, 369],
    [379, 375, 319, 391],
    [361, 445, 451, 397],
    [397, 425, 395, 505],
];

const ICE_SXOR: [[i32; 4]; 4] = [
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

const KEYROT: [i32; 16] = [0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2];

fn gf_mult(mut a: u32, mut b: u32, m: u32) -> u32 {
    let mut res: u32 = 0;
    while b != 0 {
        if b & 1 != 0 {
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

fn gf_exp7(b: u32, m: u32) -> u32 {
    if b == 0 {
        return 0;
    }
    let mut x = gf_mult(b, b, m);
    x = gf_mult(b, x, m);
    x = gf_mult(x, x, m);
    gf_mult(b, x, m)
}

fn ice_perm32(mut x: u32) -> u32 {
    let mut res: u32 = 0;
    for pb in ICE_PBOX.iter().take(32) {
        if x & 1 != 0 {
            res |= pb;
        }
        x >>= 1;
    }
    res
}

impl Ice {
    pub fn new(level: usize, key: &[u8]) -> Self {
        let mut ik = Ice {
            key: IceKeyStruct {
                size: if level < 1 { 1 } else { level },
                rounds: if level < 1 { 8 } else { level * 16 },
                keysched: Vec::new(),
            },
            sbox: IceSboxes::new(),
        };

        ik.sboxes_init();
        ik.key.keysched = vec![IceSubkey { val: [0; 3] }; ik.key.rounds];
        ik.key_set(key);
        ik
    }

    fn sboxes_init(&mut self) {
        for i in 0..1024 {
            let col = (i >> 1) & 0xff;
            let row = (i & 0x1) | ((i & 0x200) >> 8);

            self.sbox.s[0][i] = ice_perm32(
                gf_exp7(
                    (col ^ ICE_SXOR[0][row] as usize) as u32,
                    ICE_SMOD[0][row] as u32,
                ) << 24,
            );
            self.sbox.s[1][i] = ice_perm32(
                gf_exp7(
                    (col ^ ICE_SXOR[1][row] as usize) as u32,
                    ICE_SMOD[1][row] as u32,
                ) << 16,
            );
            self.sbox.s[2][i] = ice_perm32(
                gf_exp7(
                    (col ^ ICE_SXOR[2][row] as usize) as u32,
                    ICE_SMOD[2][row] as u32,
                ) << 8,
            );
            self.sbox.s[3][i] = ice_perm32(gf_exp7(
                (col ^ ICE_SXOR[3][row] as usize) as u32,
                ICE_SMOD[3][row] as u32,
            ));
        }
    }

    #[inline(always)]
    fn ice_f_batch<const B: usize>(&self, p: [u32; B], sk: &IceSubkey) -> [u32; B] {
        let mut res = [0u32; B];
        let s = &self.sbox.s;
        for i in 0..B {
            let val = p[i];
            let tr = (val & 0x3ff) | ((val << 2) & 0xffc00);
            let tl = ((val >> 16) & 0x3ff) | (val.rotate_left(18) & 0xffc00);

            let al_base = sk.val[2] & (tl ^ tr);
            let al = al_base ^ tl ^ sk.val[0];
            let ar = al_base ^ tr ^ sk.val[1];

            res[i] = s[0][((al >> 10) & 0x3ff) as usize]
                | s[1][(al & 0x3ff) as usize]
                | s[2][((ar >> 10) & 0x3ff) as usize]
                | s[3][(ar & 0x3ff) as usize];
        }
        res
    }

    #[inline(always)]
    fn process_batch<const B: usize, const DECRYPT: bool>(&self, chunk: &mut [u8]) {
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

    /// Encrypts the provided data in-place using the optimal batch size
    /// based on the workload size and available system threads.
    pub fn encrypt(&self, data: &mut [u8]) {
        let len = data.len();
        let threads = rayon::current_num_threads();

        // 1. Serial Path: For small buffers or single-threaded environments.
        // Your benches showed Batch64 is the undisputed serial champion.
        if len < 32_768 || threads < 2 {
            self.encrypt_blocks::<64>(data);
            return;
        }

        // 2. Parallel Path: Dispatch based on "Workload Density".
        let bytes_per_thread = len / threads;

        if bytes_per_thread > 1_048_576 {
            // Massive data per thread: Batch8 stays lean in the L1/L2 caches.
            self.encrypt_blocks_par::<32>(data);
        } else {
            // Moderate data: Batch32 provides the best balance of unrolling
            // without exceeding register capacity on most modern CPUs.
            self.encrypt_blocks_par::<64>(data);
        }
    }

    /// Decrypts the provided data in-place using the optimal batch size.
    pub fn decrypt(&self, data: &mut [u8]) {
        let len = data.len();
        let threads = rayon::current_num_threads();

        if len < 32_768 || threads < 2 {
            self.decrypt_blocks::<64>(data);
            return;
        }

        let bytes_per_thread = len / threads;

        if bytes_per_thread > 1_048_576 {
            self.decrypt_blocks_par::<32>(data);
        } else {
            self.decrypt_blocks_par::<64>(data);
        }
    }

    pub fn encrypt_par(&self, data: &mut [u8]) {
        self.dispatch::<false>(data, true);
    }

    pub fn decrypt_par(&self, data: &mut [u8]) {
        self.dispatch::<true>(data, true);
    }

    /// Benchmarking hook for specific batch sizes in serial mode.
    #[allow(unused)]
    pub fn encrypt_blocks<const B: usize>(&self, data: &mut [u8]) {
        self.process_batch::<B, false>(data);
    }

    /// Benchmarking hook for specific batch sizes in parallel mode.
    #[allow(unused)]
    pub fn encrypt_blocks_par<const B: usize>(&self, data: &mut [u8]) {
        const BLOCK_SIZE: usize = 8;
        data.par_chunks_exact_mut(B * BLOCK_SIZE).for_each(|chunk| {
            self.process_batch::<B, false>(chunk);
        });
    }

    /// Benchmarking hook for specific batch sizes in serial mode.
    #[allow(unused)]
    pub fn decrypt_blocks<const B: usize>(&self, data: &mut [u8]) {
        self.process_batch::<B, true>(data);
    }

    /// Benchmarking hook for specific batch sizes in parallel mode.
    #[allow(unused)]
    pub fn decrypt_blocks_par<const B: usize>(&self, data: &mut [u8]) {
        const BLOCK_SIZE: usize = 8;
        data.par_chunks_exact_mut(B * BLOCK_SIZE).for_each(|chunk| {
            self.process_batch::<B, true>(chunk);
        });
    }

    fn dispatch<const DECRYPT: bool>(&self, data: &mut [u8], parallel: bool) {
        assert!(data.len() % 8 == 0);
        const B: usize = 8;
        const B_BYTES: usize = B * 8;

        let (head, tail) = {
            let len = (data.len() / B_BYTES) * B_BYTES;
            data.split_at_mut(len)
        };

        if parallel {
            head.par_chunks_exact_mut(B_BYTES).for_each(|chunk| {
                self.process_batch::<B, DECRYPT>(chunk);
            });
        } else {
            head.chunks_exact_mut(B_BYTES).for_each(|chunk| {
                self.process_batch::<B, DECRYPT>(chunk);
            });
        }

        tail.chunks_exact_mut(8).for_each(|block| {
            self.process_batch::<1, DECRYPT>(block);
        });
    }

    fn key_sched_build(&mut self, kb: &mut [u16; 4], n: usize, keyrot: &[i32]) {
        for (i, &kr) in keyrot.iter().enumerate().take(8) {
            let isk = &mut self.key.keysched[n + i];
            isk.val.fill(0);
            for j in 0..15 {
                let curr_sk = &mut isk.val[j % 3];
                for k in 0..4 {
                    let curr_kb = &mut kb[((kr + k as i32) & 3) as usize];
                    let bit = *curr_kb & 1;
                    *curr_sk = (*curr_sk << 1) | bit as u32;
                    *curr_kb = (*curr_kb >> 1) | ((bit ^ 1) << 15);
                }
            }
        }
    }

    pub fn key_set(&mut self, key: &[u8]) {
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
