use skein3fish;
use sodiumoxide::crypto::stream::xchacha20;
use std::time::Instant;

pub fn encrypt(
    input: &[u8],
    t3f_key: &[u8; skein3fish::T3F_KEY_LEN],
    t3f_tweak: &[u8; skein3fish::T3F_TWEAK_LEN],
    xchacha20_key: &xchacha20::Key,
    xchacha20_nonce: &xchacha20::Nonce,
) -> Vec<u8> {
    
    let mut in_len = input.len();
    let mut output: Vec<u8> = vec![0; in_len];

    let ctr_buf_len = (in_len / skein3fish::T3F_BLOCK_LEN
        + if in_len % skein3fish::T3F_BLOCK_LEN != 0 {
            1
        } else {
            0
        })
        * skein3fish::T3F_BLOCK_LEN;
    let mut ctr_buf: Vec<u8> = vec![0; ctr_buf_len];
    xchacha20::stream_xor_inplace(&mut ctr_buf, &xchacha20_nonce, &xchacha20_key);

    let mut t3f_buf = [0u8; skein3fish::T3F_BLOCK_LEN];
    let mut i = 0;
    while in_len >= skein3fish::T3F_BLOCK_LEN {
        t3f_buf.copy_from_slice(
            &ctr_buf[i * skein3fish::T3F_BLOCK_LEN..(i + 1) * skein3fish::T3F_BLOCK_LEN],
        );
        t3f_buf = skein3fish::block_encrypt(&t3f_buf, &t3f_key, &t3f_tweak);
        for j in 0..skein3fish::T3F_BLOCK_LEN {
            output[i * skein3fish::T3F_BLOCK_LEN + j] =
                t3f_buf[j] ^ input[i * skein3fish::T3F_BLOCK_LEN + j];
        }
        i = i + 1;
        in_len -= skein3fish::T3F_BLOCK_LEN;
    }
    if in_len > 0 {
        t3f_buf.copy_from_slice(
            &ctr_buf[i * skein3fish::T3F_BLOCK_LEN..(i + 1) * skein3fish::T3F_BLOCK_LEN],
        );
        t3f_buf = skein3fish::block_encrypt(&t3f_buf, &t3f_key, &t3f_tweak);
        for j in 0..in_len {
            output[i * skein3fish::T3F_BLOCK_LEN + j] =
                t3f_buf[j] ^ input[i * skein3fish::T3F_BLOCK_LEN + j];
        }
    }
    output
}

pub fn decrypt(
    input: &[u8],
    t3f_key: &[u8; skein3fish::T3F_KEY_LEN],
    t3f_tweak: &[u8; skein3fish::T3F_TWEAK_LEN],
    xchacha20_key: &xchacha20::Key,
    xchacha20_nonce: &xchacha20::Nonce,
) -> Vec<u8> {
    encrypt(
        &input,
        &t3f_key,
        &t3f_tweak,
        &xchacha20_key,
        &xchacha20_nonce,
    )
}

#[test]
fn test_ctr() {
    let t3f_key = [0u8; skein3fish::T3F_KEY_LEN];
    let t3f_tweak = [0u8; skein3fish::T3F_TWEAK_LEN];
    let xchacha20_key = xchacha20::Key::from_slice(&[0u8; xchacha20::KEYBYTES]).unwrap();
    let xchacha20_nonce = xchacha20::Nonce::from_slice(&[0u8; xchacha20::NONCEBYTES]).unwrap();
    let in_len: usize = skein3fish::T3F_BLOCK_LEN * 10 + 64;
    let input: Vec<u8> = vec![0; in_len];

    let start = Instant::now();
    let output = encrypt(
        &input,
        &t3f_key,
        &t3f_tweak,
        &xchacha20_key,
        &xchacha20_nonce,
    );
    let duration = start.elapsed();
    println!("{:?} for encrypting {} bytes.", duration, in_len);
    let dec_output = decrypt(
        &output,
        &t3f_key,
        &t3f_tweak,
        &xchacha20_key,
        &xchacha20_nonce,
    );
    assert_eq!(&input[..], &dec_output[..]);
}
