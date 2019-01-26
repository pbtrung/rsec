use libc::{c_int, size_t, uint64_t};

const SKEIN_MAX_STATE_WORDS: usize = 16;
const SKEIN_MODIFIER_WORDS: usize = 2;
const SKEIN_512_STATE_WORDS: usize = 8;
const SKEIN_512_BLOCK_BYTES: usize = 8 * SKEIN_512_STATE_WORDS;
const SKEIN_256_STATE_WORDS: usize = 4;
const SKEIN_256_BLOCK_BYTES: usize = 8 * SKEIN_256_STATE_WORDS;
const SKEIN1024_STATE_WORDS: usize = 16;
const SKEIN1024_BLOCK_BYTES: usize = 8 * SKEIN1024_STATE_WORDS;

pub const T3F_KEY_LEN: usize = 128;
pub const T3F_TWEAK_LEN: usize = 16;
pub const T3F_BLOCK_LEN: usize = 128;
pub const SKEIN_MAC_KEY_LEN: usize = 64;
pub const SKEIN_MAC_LEN: usize = 64;

#[repr(C)]
pub enum ThreefishSize {
    Threefish1024 = 1024,
}

#[repr(C)]
enum SkeinSize {
    Skein512 = 512,
}

#[repr(C)]
struct Skein_Ctxt_Hdr_t {
    hash_bit_len: size_t,
    b_cnt: size_t,
    t: [uint64_t; SKEIN_MODIFIER_WORDS],
}

#[repr(C)]
struct Skein_512_Ctxt_t {
    h: Skein_Ctxt_Hdr_t,
    x: [uint64_t; SKEIN_512_STATE_WORDS],
    b: [u8; SKEIN_512_BLOCK_BYTES],
}

#[repr(C)]
struct Skein_256_Ctxt_t {
    h: Skein_Ctxt_Hdr_t,
    x: [uint64_t; SKEIN_256_STATE_WORDS],
    b: [u8; SKEIN_256_BLOCK_BYTES],
}

#[repr(C)]
struct Skein1024_Ctxt_t {
    h: Skein_Ctxt_Hdr_t,
    x: [uint64_t; SKEIN1024_STATE_WORDS],
    b: [u8; SKEIN1024_BLOCK_BYTES],
}

#[repr(C)]
struct SkeinCtx {
    skein_size: uint64_t,
    x_save: [uint64_t; SKEIN_MAX_STATE_WORDS],
    u: U,
}

#[repr(C)]
union U {
    h: Skein_Ctxt_Hdr_t,
    s256: Skein_256_Ctxt_t,
    s512: Skein_512_Ctxt_t,
    s1024: Skein1024_Ctxt_t,
}

impl Copy for Skein_512_Ctxt_t {}
impl Clone for Skein_512_Ctxt_t {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for Skein_256_Ctxt_t {}
impl Clone for Skein_256_Ctxt_t {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for Skein1024_Ctxt_t {}
impl Clone for Skein1024_Ctxt_t {
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for Skein_Ctxt_Hdr_t {}
impl Clone for Skein_Ctxt_Hdr_t {
    fn clone(&self) -> Self {
        *self
    }
}

#[repr(C)]
struct ThreefishKey {
    state_size: uint64_t,
    key: [u8; T3F_KEY_LEN + 8],     // 136
    tweak: [u8; T3F_TWEAK_LEN + 8], // 24
}

pub fn block_encrypt(
    input: &[u8; T3F_BLOCK_LEN],
    t3f_key: &[u8; T3F_KEY_LEN],
    t3f_tweak: &[u8; T3F_TWEAK_LEN],
) -> [u8; T3F_BLOCK_LEN] {
    
    let mut t3f_ctx: ThreefishKey = ThreefishKey {
        state_size: 0,
        key: [0; T3F_KEY_LEN + 8],
        tweak: [0; T3F_TWEAK_LEN + 8],
    };
    unsafe {
        threefishSetKey(
            &mut t3f_ctx,
            ThreefishSize::Threefish1024,
            t3f_key.as_ptr(),
            t3f_tweak.as_ptr(),
        );
    }

    let mut output: [u8; T3F_BLOCK_LEN] = [0; T3F_BLOCK_LEN];
    unsafe {
        threefishEncryptBlockBytes(&mut t3f_ctx, input.as_ptr(), output.as_mut_ptr());
    }
    output
}

extern "C" {
    fn threefishSetKey(
        t3f_ctx: *mut ThreefishKey,
        t3f_size: ThreefishSize,
        t3f_key: *const u8,
        tweak: *const u8,
    );
    fn threefishEncryptBlockBytes(t3f_ctx: *const ThreefishKey, input: *const u8, output: *mut u8);
    fn skeinCtxPrepare(skein_ctx: *mut SkeinCtx, skein_size: SkeinSize) -> c_int;
    fn skeinUpdate(skein_ctx: *mut SkeinCtx, input: *const u8, in_len: size_t) -> c_int;
    fn skeinFinal(skein_ctx: *mut SkeinCtx, output: *mut u8) -> c_int;
    fn skeinMacInit(
        skein_ctx: *mut SkeinCtx,
        skein_mac_key: *const u8,
        key_len: size_t,
        hash_bit_len: size_t,
    ) -> c_int;
}

pub fn mac(input: &[u8], skein_mac_key: &[u8; SKEIN_MAC_KEY_LEN]) -> [u8; SKEIN_MAC_LEN] {
    let h: Skein_Ctxt_Hdr_t = Skein_Ctxt_Hdr_t {
        hash_bit_len: 0,
        b_cnt: 0,
        t: [0; SKEIN_MODIFIER_WORDS],
    };
    let mut skein_ctx: SkeinCtx = SkeinCtx {
        skein_size: 0,
        x_save: [0; SKEIN_MAX_STATE_WORDS],
        u: U { h: h },
    };

    let mut output: [u8; SKEIN_MAC_LEN] = [0; SKEIN_MAC_LEN];
    unsafe {
        let mut rc: c_int;
        rc = skeinCtxPrepare(&mut skein_ctx, SkeinSize::Skein512);
        if rc != 0 {
            panic!("{}", "Error: skeinCtxPrepare");
        }
        rc = skeinMacInit(
            &mut skein_ctx,
            skein_mac_key.as_ptr(),
            skein_mac_key.len() as size_t,
            SkeinSize::Skein512 as size_t,
        );
        if rc != 0 {
            panic!("{}", "Error: skeinMacInit");
        }
        rc = skeinUpdate(&mut skein_ctx, input.as_ptr(), input.len() as size_t);
        if rc != 0 {
            panic!("{}", "Error: skeinUpdate");
        }
        rc = skeinFinal(&mut skein_ctx, output.as_mut_ptr());
        if rc != 0 {
            panic!("{}", "Error: skeinFinal");
        }
    }
    output
}

#[test]
fn test_block_encrypt() {
    let t3f_key: [u8; T3F_KEY_LEN] = [0; T3F_KEY_LEN];
    let t3f_tweak: [u8; T3F_TWEAK_LEN] = [0; T3F_TWEAK_LEN];
    let input: [u8; T3F_BLOCK_LEN] = [0; T3F_BLOCK_LEN];
    let _output = block_encrypt(&input, &t3f_key, &t3f_tweak);
}

#[test]
fn test_mac() {
    let input: [u8; SKEIN_MAC_LEN] = [0; SKEIN_MAC_LEN];
    let skein_mac_key: [u8; SKEIN_MAC_LEN] = [0; SKEIN_MAC_LEN];
    let _output = mac(&input, &skein_mac_key);
}
