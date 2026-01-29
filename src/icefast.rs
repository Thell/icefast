use rayon::prelude::*;

/* Structure of a single round subkey */
#[derive(Clone, Debug)]
pub struct IceSubkey {
    val: [u32; 3],
}

/* Internal structure of the ICE_KEY structure */
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
    pub fn new() -> IceSboxes {
        IceSboxes { s: [[0; 1024]; 4] }
    }
}

#[warn(dead_code)]
#[derive(Clone, Debug)]
pub struct Ice {
    pub key: IceKeyStruct,
    sboxes_initialised: bool,
    sbox: IceSboxes,
}

/* Modulo values for the S-boxes */
const ICE_SMOD: [[i32; 4]; 4] = [
    [333, 313, 505, 369],
    [379, 375, 319, 391],
    [361, 445, 451, 397],
    [397, 425, 395, 505],
];

/* XOR values for the S-boxes */
const ICE_SXOR: [[i32; 4]; 4] = [
    [0x83, 0x85, 0x9b, 0xcd],
    [0xcc, 0xa7, 0xad, 0x41],
    [0x4b, 0x2e, 0xd4, 0x33],
    [0xea, 0xcb, 0x2e, 0x04],
];

/* Expanded permutation values for the P-box */
const ICE_PBOX: [u32; 32] = [
    0x00000001, 0x00000080, 0x00000400, 0x00002000, 0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000, 0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000, 0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000, 0x00040000, 0x00100000, 0x02000000, 0x80000000,
];

// The key rotation schedule
const KEYROT: [i32; 16] = [0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2];

// Galois Field multiplication of a by b, modulo m.
// Just like arithmetic multiplication, except that additions and
// subtractions are replaced by XOR.
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

// Galois Field exponentiation. Raise the base to the power of 7, modulo m.
fn gf_exp7(b: u32, m: u32) -> u32 {
    if b == 0 {
        return 0;
    }
    let mut x = gf_mult(b, b, m);
    x = gf_mult(b, x, m);
    x = gf_mult(x, x, m);
    gf_mult(b, x, m)
}

// Carry out the ICE 32-bit P-box permutation.
fn ice_perm32(mut x: u32) -> u32 {
    let mut res: u32 = 0;
    let pbox = &ICE_PBOX;
    for pb in pbox.iter().take(32) {
        if x & 1 != 0 {
            res |= pb;
        }
        x >>= 1;
    }
    res
}

impl Ice {
    /// Create a new ICE
    /// # Arguments
    /// * `level` - The level of the ICE (0-2)
    /// * `key` - The key to use
    pub fn new(level: usize, key: &[u8]) -> Self {
        let mut ik = Ice {
            key: IceKeyStruct {
                size: 0,
                rounds: 0,
                keysched: Vec::new(),
            },
            sbox: IceSboxes::new(),
            sboxes_initialised: false,
        };

        if !ik.sboxes_initialised {
            ik.sboxes_init();
            ik.sboxes_initialised = true;
        }

        if level < 1 {
            // Thin-ICE
            ik.key.size = 1;
            ik.key.rounds = 8;
            assert!(key.len() == 8);
        } else {
            ik.key.size = level;
            ik.key.rounds = level * 16;
            assert!(key.len() == level * 8);
        }

        ik.key.keysched = vec![IceSubkey { val: [0; 3] }; ik.key.rounds];
        ik.key_set(key);
        ik
    }

    // Initialise the ICE S-boxes. This only has to be done once.
    fn sboxes_init(&mut self) {
        for i in 0..1024 {
            let col = (i >> 1) & 0xff;
            let row = (i & 0x1) | ((i & 0x200) >> 8);

            let x0 = gf_exp7(
                (col ^ ICE_SXOR[0][row] as usize) as u32,
                ICE_SMOD[0][row] as u32,
            ) << 24;
            self.sbox.s[0][i] = ice_perm32(x0);

            let x1 = gf_exp7(
                (col ^ ICE_SXOR[1][row] as usize) as u32,
                ICE_SMOD[1][row] as u32,
            ) << 16;
            self.sbox.s[1][i] = ice_perm32(x1);

            let x2 = gf_exp7(
                (col ^ ICE_SXOR[2][row] as usize) as u32,
                ICE_SMOD[2][row] as u32,
            ) << 8;
            self.sbox.s[2][i] = ice_perm32(x2);

            let x3 = gf_exp7(
                (col ^ ICE_SXOR[3][row] as usize) as u32,
                ICE_SMOD[3][row] as u32,
            );
            self.sbox.s[3][i] = ice_perm32(x3);
        }
    }

    // Single round of the ICE.
    #[inline(always)]
    fn ice_f(&self, p: u32, sk: &IceSubkey) -> u32 {
        // Expanded 2x20-bit values
        let tr = (p & 0x3ff) | ((p << 2) & 0xffc00);
        let tl = ((p >> 16) & 0x3ff) | (p.rotate_left(18) & 0xffc00);

        // Perform the salt permutation
        let al_base = sk.val[2] & (tl ^ tr);
        let mut al = al_base ^ tl;
        let mut ar = al_base ^ tr;

        // XOR with the subkey
        al ^= sk.val[0];
        ar ^= sk.val[1];

        // S-box lookup and permutation
        self.sbox.s[0][((al >> 10) & 0x3ff) as usize]
            | self.sbox.s[1][(al & 0x3ff) as usize]
            | self.sbox.s[2][((ar >> 10) & 0x3ff) as usize]
            | self.sbox.s[3][(ar & 0x3ff) as usize]
    }

    // 8 rounds of the ICE.
    #[inline(always)]
    fn ice_f_8way(&self, p: [u32; 8], sk: &IceSubkey) -> [u32; 8] {
        let mut res = [0u32; 8];
        for i in 0..8 {
            let val = p[i];
            let tr = (val & 0x3ff) | ((val << 2) & 0xffc00);
            let tl = ((val >> 16) & 0x3ff) | (val.rotate_left(18) & 0xffc00);

            let al_base = sk.val[2] & (tl ^ tr);
            let al = al_base ^ tl ^ sk.val[0];
            let ar = al_base ^ tr ^ sk.val[1];

            res[i] = self.sbox.s[0][((al >> 10) & 0x3ff) as usize]
                | self.sbox.s[1][(al & 0x3ff) as usize]
                | self.sbox.s[2][((ar >> 10) & 0x3ff) as usize]
                | self.sbox.s[3][(ar & 0x3ff) as usize];
        }
        res
    }

    #[inline(always)]
    fn encrypt_8(&self, chunk: &mut [u8]) {
        let mut l: u32 = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
        let mut r: u32 = u32::from_be_bytes(chunk[4..8].try_into().unwrap());

        self.key.keysched.chunks_exact(2).for_each(|pair| {
            l ^= self.ice_f(r, &pair[0]);
            r ^= self.ice_f(l, &pair[1]);
        });

        chunk[0..4].copy_from_slice(&r.to_be_bytes()[..]);
        chunk[4..8].copy_from_slice(&l.to_be_bytes()[..]);
    }

    #[inline(always)]
    fn encrypt_64(&self, chunk: &mut [u8]) {
        let mut l = [0u32; 8];
        let mut r = [0u32; 8];

        for i in 0..8 {
            l[i] = u32::from_be_bytes(chunk[i * 8..i * 8 + 4].try_into().unwrap());
            r[i] = u32::from_be_bytes(chunk[i * 8 + 4..i * 8 + 8].try_into().unwrap());
        }

        for pair in self.key.keysched.chunks_exact(2) {
            let f_r = self.ice_f_8way(r, &pair[0]);
            for i in 0..8 {
                l[i] ^= f_r[i];
            }

            let f_l = self.ice_f_8way(l, &pair[1]);
            for i in 0..8 {
                r[i] ^= f_l[i];
            }
        }

        for i in 0..8 {
            chunk[i * 8..i * 8 + 4].copy_from_slice(&r[i].to_be_bytes());
            chunk[i * 8 + 4..i * 8 + 8].copy_from_slice(&l[i].to_be_bytes());
        }
    }

    #[inline(always)]
    fn decrypt_8(&self, chunk: &mut [u8]) {
        let mut l: u32 = u32::from_be_bytes(chunk[0..4].try_into().unwrap());
        let mut r: u32 = u32::from_be_bytes(chunk[4..8].try_into().unwrap());

        self.key.keysched.rchunks_exact(2).for_each(|pair| {
            l ^= self.ice_f(r, &pair[1]);
            r ^= self.ice_f(l, &pair[0]);
        });

        chunk[0..4].copy_from_slice(&r.to_be_bytes()[..]);
        chunk[4..8].copy_from_slice(&l.to_be_bytes()[..]);
    }

    #[inline(always)]
    fn decrypt_64(&self, chunk: &mut [u8]) {
        let mut l = [0u32; 8];
        let mut r = [0u32; 8];

        for i in 0..8 {
            l[i] = u32::from_be_bytes(chunk[i * 8..i * 8 + 4].try_into().unwrap());
            r[i] = u32::from_be_bytes(chunk[i * 8 + 4..i * 8 + 8].try_into().unwrap());
        }

        // Decryption uses the keysched in reverse order
        for pair in self.key.keysched.rchunks_exact(2) {
            let f_r = self.ice_f_8way(r, &pair[1]);
            for i in 0..8 {
                l[i] ^= f_r[i];
            }

            let f_l = self.ice_f_8way(l, &pair[0]);
            for i in 0..8 {
                r[i] ^= f_l[i];
            }
        }

        for i in 0..8 {
            chunk[i * 8..i * 8 + 4].copy_from_slice(&r[i].to_be_bytes());
            chunk[i * 8 + 4..i * 8 + 8].copy_from_slice(&l[i].to_be_bytes());
        }
    }

    /// Encrypt data in-place.
    pub fn encrypt(&self, data: &mut [u8]) {
        assert!(data.len() % 8 == 0, "Data must be a multiple of 8 bytes");

        data.chunks_exact_mut(64).for_each(|chunk| {
            self.encrypt_64(chunk);
        });

        data.chunks_exact_mut(64)
            .into_remainder()
            .chunks_exact_mut(8)
            .for_each(|chunk| {
                self.encrypt_8(chunk);
            });
    }

    pub fn encrypt_par(&self, data: &mut [u8]) {
        assert!(data.len() % 8 == 0, "Data must be a multiple of 8 bytes");

        data.par_chunks_exact_mut(64).for_each(|chunk| {
            self.encrypt_64(chunk);
        });

        data.par_chunks_exact_mut(64)
            .into_remainder()
            .chunks_exact_mut(8)
            .for_each(|chunk| {
                self.encrypt_8(chunk);
            })
    }

    /// Decrypt data in-place.
    pub fn decrypt(&self, data: &mut [u8]) {
        assert!(data.len() % 8 == 0, "Data must be a multiple of 8 bytes");

        data.chunks_exact_mut(64).for_each(|chunk| {
            self.decrypt_64(chunk);
        });

        data.chunks_exact_mut(64)
            .into_remainder()
            .chunks_exact_mut(8)
            .for_each(|chunk| {
                self.decrypt_8(chunk);
            });
    }

    /// Decrypt data in-place using 'par_chunks'.
    pub fn decrypt_par(&self, data: &mut [u8]) {
        assert!(data.len() % 8 == 0, "Data must be a multiple of 8 bytes");

        data.par_chunks_exact_mut(64).for_each(|chunk| {
            self.decrypt_64(chunk);
        });

        data.par_chunks_exact_mut(64)
            .into_remainder()
            .chunks_exact_mut(8)
            .for_each(|chunk| {
                self.decrypt_8(chunk);
            });
    }

    //  Set 8 rounds [n, n+7] of the key schedule of an ICE key.
    fn key_sched_build(&mut self, kb: &mut [u16; 4], n: i32, keyrot: &[i32]) {
        for (i, kr) in keyrot.iter().enumerate().take(8) {
            let isk: &mut IceSubkey = &mut self.key.keysched[n as usize + i as usize];
            isk.val.fill(0);

            for j in 0..15 {
                let curr_sk: &mut u32 = &mut isk.val[j % 3];

                for k in 0..4 {
                    let curr_kb = &mut kb[(kr + k) as usize & 3];
                    let bit = *curr_kb & 1;

                    *curr_sk = (*curr_sk << 1) | bit as u32;
                    *curr_kb = (*curr_kb >> 1) | ((bit ^ 1) << 15);
                }
            }
        }
    }

    // Set the key schedule of an ICE key.
    pub fn key_set(&mut self, key: &[u8]) {
        if self.key.rounds == 8 {
            let mut kb: [u16; 4] = [0; 4];
            for i in 0..4 {
                kb[3 - i] = (key[i * 2] as u16) << 8 | key[i * 2 + 1] as u16;
            }
            self.key_sched_build(&mut kb, 0, &KEYROT);
            return;
        }

        for i in 0..self.key.size {
            let mut kb: [u16; 4] = [0; 4];
            for j in 0..4 {
                kb[3 - j] =
                    (key[i * 8 + j * 2] as u16) << 8 | key[i as usize * 8 + j * 2 + 1] as u16;
            }
            self.key_sched_build(&mut kb, (i * 8).try_into().unwrap(), &KEYROT);
            self.key_sched_build(
                &mut kb,
                (self.key.rounds - 8 - i * 8).try_into().unwrap(),
                &KEYROT[8..16],
            );
        }
    }

    // Return the key size, in bytes.
    #[allow(dead_code)]
    pub fn key_size(&self) -> i32 {
        (self.key.size * 8).try_into().unwrap()
    }
}
