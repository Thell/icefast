//	/* Structure of a single round subkey */
#[derive(Copy, Clone, Debug)]
pub struct IceSubkey {
    val: [u32; 3],
}

// /* Internal structure of the ICE_KEY structure */
pub struct IceKeyStruct {
    size: usize,
    rounds: usize,
    pub keysched: Vec<IceSubkey>,
}

#[warn(dead_code)]
pub struct Ice {
    // typedef struct ice_key_struct	ICE_KEY;
    pub key: IceKeyStruct,
    // /* The S-boxes */
    // static unsigned long	ice_sbox[4][1024];
    sbox: [[u32; 1024]; 4],
    // static int		ice_sboxes_initialised = 0;
    sboxes_initialised: bool,
}

// /* Modulo values for the S-boxes */
// static const int	ice_smod[4][4] = {
//     {333, 313, 505, 369},
//     {379, 375, 319, 391},
//     {361, 445, 451, 397},
//     {397, 425, 395, 505}};
const ICE_SMOD: [[i32; 4]; 4] = [
    [333, 313, 505, 369],
    [379, 375, 319, 391],
    [361, 445, 451, 397],
    [397, 425, 395, 505],
];

// /* XOR values for the S-boxes */
// static const int	ice_sxor[4][4] = {
//     {0x83, 0x85, 0x9b, 0xcd},
//     {0xcc, 0xa7, 0xad, 0x41},
//     {0x4b, 0x2e, 0xd4, 0x33},
//     {0xea, 0xcb, 0x2e, 0x04}};
const ICE_SXOR: [[i32; 4]; 4] = [
    [0x83, 0x85, 0x9b, 0xcd],
    [0xcc, 0xa7, 0xad, 0x41],
    [0x4b, 0x2e, 0xd4, 0x33],
    [0xea, 0xcb, 0x2e, 0x04],
];

// /* Expanded permutation values for the P-box */
// static const unsigned long	ice_pbox[32] = {
// 	0x00000001, 0x00000080, 0x00000400, 0x00002000,
// 	0x00080000, 0x00200000, 0x01000000, 0x40000000,
// 	0x00000008, 0x00000020, 0x00000100, 0x00004000,
// 	0x00010000, 0x00800000, 0x04000000, 0x20000000,
// 	0x00000004, 0x00000010, 0x00000200, 0x00008000,
// 	0x00020000, 0x00400000, 0x08000000, 0x10000000,
// 	0x00000002, 0x00000040, 0x00000800, 0x00001000,
// 	0x00040000, 0x00100000, 0x02000000, 0x80000000};
const ICE_PBOX: [u32; 32] = [
    0x00000001, 0x00000080, 0x00000400, 0x00002000, 0x00080000, 0x00200000, 0x01000000, 0x40000000,
    0x00000008, 0x00000020, 0x00000100, 0x00004000, 0x00010000, 0x00800000, 0x04000000, 0x20000000,
    0x00000004, 0x00000010, 0x00000200, 0x00008000, 0x00020000, 0x00400000, 0x08000000, 0x10000000,
    0x00000002, 0x00000040, 0x00000800, 0x00001000, 0x00040000, 0x00100000, 0x02000000, 0x80000000,
];

// /* The key rotation schedule */
// static const int	keyrot[16] = {
//     0, 1, 2, 3, 2, 1, 3, 0,
//     1, 3, 2, 0, 3, 1, 0, 2};
const KEYROT: [i32; 16] = [0, 1, 2, 3, 2, 1, 3, 0, 1, 3, 2, 0, 3, 1, 0, 2];

// /*
//  * Galois Field multiplication of a by b, modulo m.
//  * Just like arithmetic multiplication, except that additions and
//  * subtractions are replaced by XOR.
//  */

// static unsigned int
// gf_mult (
// 	register unsigned int	a,
// 	register unsigned int	b,
// 	register unsigned int	m
// ) {
// 	register unsigned int	res = 0;
//
// 	while (b) {
// 	    if (b & 1)
// 		res ^= a;
//
// 	    a <<= 1;
// 	    b >>= 1;
//
// 	    if (a >= 256)
// 		a ^= m;
// 	}
//
// 	return (res);
// }
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

/*
 * Galois Field exponentiation.
 * Raise the base to the power of 7, modulo m.
 */

// static unsigned long
// gf_exp7 (
// 	register unsigned int	b,
// 	unsigned int		m
// ) {
// 	register unsigned int	x;
//
// 	if (b == 0)
// 	    return (0);
//
// 	x = gf_mult (b, b, m);
// 	x = gf_mult (b, x, m);
// 	x = gf_mult (x, x, m);
// 	return (gf_mult (b, x, m));
// }
fn gf_exp7(b: u32, m: u32) -> u32 {
    if b == 0 {
        return 0;
    }
    let mut x = gf_mult(b, b, m);
    x = gf_mult(b, x, m);
    x = gf_mult(x, x, m);
    gf_mult(b, x, m)
}

// /*
//  * Carry out the ICE 32-bit P-box permutation.
//  */
// static unsigned long
// ice_perm32 (
// 	register unsigned long	x
// ) {
// 	register unsigned long		res = 0;
// 	register const unsigned long	*pbox = ICE_PBOX;
//
// 	while (x) {
// 	    if (x & 1)
// 		res |= *pbox;
// 	    pbox++;
// 	    x >>= 1;
// 	}
//
// 	return (res);
// }
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

#[warn(dead_code)]
impl Ice {
    // /*
    //  * Initialise the ICE S-boxes.
    //  * This only has to be done once.
    //  */
    // static void
    // ice_sboxes_init (void)
    // {
    // 	register int	i;
    //
    // 	for (i=0; i<1024; i++) {
    // 	    int			col = (i >> 1) & 0xff;
    // 	    int			row = (i & 0x1) | ((i & 0x200) >> 8);
    // 	    unsigned long	x;
    //
    // 	    x = gf_exp7 (col ^ ICE_SXOR[0][row], ICE_SMOD[0][row]) << 24;
    // 	    ice_sbox[0][i] = ice_perm32 (x);
    //
    // 	    x = gf_exp7 (col ^ ICE_SXOR[1][row], ICE_SMOD[1][row]) << 16;
    // 	    ice_sbox[1][i] = ice_perm32 (x);
    //
    // 	    x = gf_exp7 (col ^ ICE_SXOR[2][row], ICE_SMOD[2][row]) << 8;
    // 	    ice_sbox[2][i] = ice_perm32 (x);
    //
    // 	    x = gf_exp7 (col ^ ICE_SXOR[3][row], ICE_SMOD[3][row]);
    // 	    ice_sbox[3][i] = ice_perm32 (x);
    // 	}
    // }
    fn sboxes_init(&mut self) {
        for i in 0..1024 {
            let col = (i >> 1) & 0xff;
            let row = (i & 0x1) | ((i & 0x200) >> 8);
            let mut x = gf_exp7(
                (col ^ ICE_SXOR[0][row] as usize).try_into().unwrap(),
                ICE_SMOD[0][row].try_into().unwrap(),
            ) << 24;
            self.sbox[0][i] = ice_perm32(x);

            x = gf_exp7(
                (col ^ ICE_SXOR[1][row] as usize).try_into().unwrap(),
                ICE_SMOD[1][row].try_into().unwrap(),
            ) << 16;
            self.sbox[1][i] = ice_perm32(x);

            x = gf_exp7(
                (col ^ ICE_SXOR[2][row] as usize).try_into().unwrap(),
                ICE_SMOD[2][row].try_into().unwrap(),
            ) << 8;
            self.sbox[2][i] = ice_perm32(x);

            x = gf_exp7(
                (col ^ ICE_SXOR[3][row] as usize).try_into().unwrap(),
                ICE_SMOD[3][row].try_into().unwrap(),
            );
            self.sbox[3][i] = ice_perm32(x);
        }
    }

    // /*
    //  * Create a new ICE key.
    //  */
    // ICE_KEY *
    // ice_key_create (
    // 	int		n
    // ) {
    // 	ICE_KEY		*ik;
    //
    // 	if (!ice_sboxes_initialised) {
    // 	    ice_sboxes_init ();
    // 	    ice_sboxes_initialised = 1;
    // 	}
    //
    // 	if ((ik = (ICE_KEY *) malloc (sizeof (ICE_KEY))) == NULL)
    // 	    return (NULL);
    //
    // 	if (n < 1) {
    // 	    ik->ik_size = 1;
    // 	    ik->ik_rounds = 8;
    // 	} else {
    // 	    ik->ik_size = n;
    // 	    ik->ik_rounds = n * 16;
    // 	}
    //
    // 	if ((ik->ik_keysched = (ICE_SUBKEY *) malloc (ik->ik_rounds
    // 					* sizeof (ICE_SUBKEY))) == NULL) {
    // 	    free (ik);
    // 	    return (NULL);
    // 	}
    //
    // 	return (ik);
    // }

    pub fn new(level: usize) -> Self {
        let mut ik = Ice {
            key: IceKeyStruct {
                size: 0,
                rounds: 0,
                keysched: Vec::new(),
            },
            sbox: [[0; 1024]; 4],
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
        } else {
            ik.key.size = level;
            ik.key.rounds = level * 16;
        }

        ik.key.keysched = vec![IceSubkey { val: [0; 3] }; ik.key.rounds];
        ik
    }

    // /*
    //  * Destroy an ICE key.
    //  * Zero out the memory to prevent snooping.
    //  */
    // A destroy function is not needed.

    // /*
    //  * The single round ICE f function.
    //  */
    // static unsigned long
    // ice_f (
    // 	register unsigned long	p,
    // 	const ICE_SUBKEY	sk
    // ) {
    // 	unsigned long	tl, tr;		/* Expanded 40-bit values */
    // 	unsigned long	al, ar;		/* Salted expanded 40-bit values */
    // 					/* Left half expansion */
    // 	tl = ((p >> 16) & 0x3ff) | (((p >> 14) | (p << 18)) & 0xffc00);

    // 					/* Right half expansion */
    // 	tr = (p & 0x3ff) | ((p << 2) & 0xffc00);

    // 					/* Perform the salt permutation */
    // 				/* al = (tr & sk[2]) | (tl & ~sk[2]); */
    // 				/* ar = (tl & sk[2]) | (tr & ~sk[2]); */
    // 	al = sk[2] & (tl ^ tr);
    // 	ar = al ^ tr;
    // 	al ^= tl;

    // 	al ^= sk[0];			/* XOR with the subkey */
    // 	ar ^= sk[1];

    // 					/* S-box lookup and permutation */
    // 	return (ice_sbox[0][al >> 10] | ice_sbox[1][al & 0x3ff]
    // 		| ice_sbox[2][ar >> 10] | ice_sbox[3][ar & 0x3ff]);
    // }

    #[inline(never)]
    pub fn ice_f(&self, p: u32, sk: &IceSubkey) -> u32 {
        /* Left half expansion */
        let tl = ((p >> 16) & 0x3ff) | (((p >> 14) | (p << 18)) & 0xffc00);

        /* Right half expansion */
        let tr = (p & 0x3ff) | ((p << 2) & 0xffc00);

        /* Perform the salt permutation */
        let mut al = sk.val[2] & (tl ^ tr);
        let mut ar = al ^ tr;
        al ^= tl;

        al ^= sk.val[0]; /* XOR with the subkey */
        ar ^= sk.val[1];

        /* S-box lookup and permutation */
        // We could vectorize the above, if we split out the sbox
        // lookup and permutation and instead return a vector of
        // (al, ar) pairs.
        // I think we could also vectorize the sbox lookup if
        // we can notify the compiler that the >> 10 indexes are
        // always in the range 0-1023.
        self.sbox[0][al as usize >> 10]
            | self.sbox[1][al as usize & 0x3ff]
            | self.sbox[2][ar as usize >> 10]
            | self.sbox[3][ar as usize & 0x3ff]
    }

    // /*
    //  * Encrypt a block of 8 bytes of data with the given ICE key.
    //  */
    // void
    // ice_key_encrypt (
    // 	const ICE_KEY		*ik,
    // 	const unsigned char	*ptext,
    // 	unsigned char		*ctext
    // ) {
    // 	register int		i;
    // 	register unsigned long	l, r;

    // 	l = (((unsigned long) ptext[0]) << 24)
    // 				| (((unsigned long) ptext[1]) << 16)
    // 				| (((unsigned long) ptext[2]) << 8) | ptext[3];
    // 	r = (((unsigned long) ptext[4]) << 24)
    // 				| (((unsigned long) ptext[5]) << 16)
    // 				| (((unsigned long) ptext[6]) << 8) | ptext[7];

    // 	for (i = 0; i < ik->ik_rounds; i += 2) {
    // 	    l ^= ice_f (r, ik->ik_keysched[i]);
    // 	    r ^= ice_f (l, ik->ik_keysched[i + 1]);
    // 	}

    // 	for (i = 0; i < 4; i++) {
    // 	    ctext[3 - i] = r & 0xff;
    // 	    ctext[7 - i] = l & 0xff;

    // 	    r >>= 8;
    // 	    l >>= 8;
    // 	}
    // }
    pub fn encrypt(&self, ptext: &[u8; 8], ctext: &mut [u8; 8]) {
        // replace with u32::from_be_bytes for the lower (l) and upper (r)
        // four bytes of the &[u8; 8]
        let mut l = ((ptext[0] as u32) << 24)
            | ((ptext[1] as u32) << 16)
            | ((ptext[2] as u32) << 8)
            | ptext[3] as u32;
        let mut r = ((ptext[4] as u32) << 24)
            | ((ptext[5] as u32) << 16)
            | ((ptext[6] as u32) << 8)
            | ptext[7] as u32;

        for i in (0..self.key.rounds).step_by(2) {
            l ^= self.ice_f(r, &self.key.keysched[i as usize]);
            r ^= self.ice_f(l, &self.key.keysched[i as usize + 1]);
        }

        for i in 0..4 {
            ctext[3 - i] = (r & 0xff).try_into().unwrap();
            ctext[7 - i] = (l & 0xff).try_into().unwrap();

            r >>= 8;
            l >>= 8;
        }
    }

    // /*
    //  * Decrypt a block of 8 bytes of data with the given ICE key.
    //  */
    // void
    // ice_key_decrypt (
    // 	const ICE_KEY		*ik,
    // 	const unsigned char	*ctext,
    // 	unsigned char		*ptext
    // ) {
    // 	register int		i;
    // 	register unsigned long	l, r;

    // 	l = (((unsigned long) ctext[0]) << 24)
    // 				| (((unsigned long) ctext[1]) << 16)
    // 				| (((unsigned long) ctext[2]) << 8) | ctext[3];
    // 	r = (((unsigned long) ctext[4]) << 24)
    // 				| (((unsigned long) ctext[5]) << 16)
    // 				| (((unsigned long) ctext[6]) << 8) | ctext[7];

    // 	for (i = ik->ik_rounds - 1; i > 0; i -= 2) {
    // 	    l ^= ice_f (r, ik->ik_keysched[i]);
    // 	    r ^= ice_f (l, ik->ik_keysched[i - 1]);
    // 	}

    // 	for (i = 0; i < 4; i++) {
    // 	    ptext[3 - i] = r & 0xff;
    // 	    ptext[7 - i] = l & 0xff;

    // 	    r >>= 8;
    // 	    l >>= 8;
    // 	}
    // }
    pub fn decrypt(&self, ctext: &[u8; 8], ptext: &mut [u8; 8]) {
        let mut l = ((ctext[0] as u32) << 24)
            | ((ctext[1] as u32) << 16)
            | ((ctext[2] as u32) << 8)
            | ctext[3] as u32;
        let mut r = ((ctext[4] as u32) << 24)
            | ((ctext[5] as u32) << 16)
            | ((ctext[6] as u32) << 8)
            | ctext[7] as u32;

        for i in (0..self.key.rounds).rev().step_by(2) {
            l ^= self.ice_f(r, &self.key.keysched[i as usize]);
            r ^= self.ice_f(l, &self.key.keysched[i as usize - 1]);
        }

        for i in 0..4 {
            ptext[3 - i] = (r & 0xff).try_into().unwrap();
            ptext[7 - i] = (l & 0xff).try_into().unwrap();

            r >>= 8;
            l >>= 8;
        }
    }

    // /*
    //  * Set 8 rounds [n, n+7] of the key schedule of an ICE key.
    //  */
    // static void
    // key_sched_build (
    // 	ICE_KEY		*ik,
    // 	unsigned short	*kb,
    // 	int		n,
    // 	const int	*keyrot
    // ) {
    // 	int		i;

    // 	for (i=0; i<8; i++) {
    // 	    register int	j;
    // 	    register int	kr = keyrot[i];
    // 	    ICE_SUBKEY		*isk = &ik->ik_keysched[n + i];

    // 	    for (j=0; j<3; j++)
    // 		(*isk)[j] = 0;

    // 	    for (j=0; j<15; j++) {
    // 		register int	k;
    // 		unsigned long	*curr_sk = &(*isk)[j % 3];

    // 		for (k=0; k<4; k++) {
    // 		    unsigned short	*curr_kb = &kb[(kr + k) & 3];
    // 		    register int	bit = *curr_kb & 1;

    // 		    *curr_sk = (*curr_sk << 1) | bit;
    // 		    *curr_kb = (*curr_kb >> 1) | ((bit ^ 1) << 15);
    // 		}
    // 	    }
    // 	}
    // }
    fn key_sched_build(&mut self, kb: &mut [u16; 4], n: i32, keyrot: &[i32]) {
        for (i, kr) in keyrot.iter().enumerate().take(8) {
            let isk: &mut IceSubkey = &mut self.key.keysched[n as usize + i as usize];

            for j in 0..3 {
                (*isk).val[j] = 0;
            }

            for j in 0..15 {
                let curr_sk: &mut u32 = &mut (*isk).val[j % 3];

                for k in 0..4 {
                    let curr_kb = &mut kb[(kr + k) as usize & 3];
                    let bit = *curr_kb & 1;

                    *curr_sk = (*curr_sk << 1) | bit as u32;
                    *curr_kb = (*curr_kb >> 1) | ((bit ^ 1) << 15);
                }
            }
        }
    }

    // /*
    //  * Set the key schedule of an ICE key.
    //  */
    // void
    // key_set (
    // 	ICE_KEY			*ik,
    // 	const unsigned char	*key
    // ) {
    // 	int		i;

    // 	if (ik->ik_rounds == 8) {
    // 	    unsigned short	kb[4];

    // 	    for (i=0; i<4; i++)
    // 		kb[3 - i] = (key[i*2] << 8) | key[i*2 + 1];

    // 	    key_sched_build (ik, kb, 0, KEYROT);
    // 	    return;
    // 	}

    // 	for (i = 0; i < ik->ik_size; i++) {
    // 	    int			j;
    // 	    unsigned short	kb[4];

    // 	    for (j=0; j<4; j++)
    // 		kb[3 - j] = (key[i*8 + j*2] << 8) | key[i*8 + j*2 + 1];

    // 	    key_sched_build (ik, kb, i*8, KEYROT);
    // 	    key_sched_build (ik, kb, ik->ik_rounds - 8 - i*8,
    // 							&KEYROT[8]);
    // 	}
    // }
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

    // /*
    //  * Return the key size, in bytes.
    //  */
    #[allow(dead_code)]
    pub fn key_size(&self) -> i32 {
        (self.key.size * 8).try_into().unwrap()
    }

}
