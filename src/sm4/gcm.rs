// R = 11100001 || 0(120)
const R: u128 = 0b11100001 << 120;

#[inline]
fn galois_mul(x: u128, y: u128) -> u128 {
    let mut z = 0u128;
    let mut v = y;
    for i in (0..128).rev() {
        if (x >> i) & 1 == 1 {
            z ^= v;
        }
        if v & 1 == 0 {
            v >>= 1;
        } else {
            v = (v >> 1) ^ R;
        }
    }
    z
}

pub(super) fn galois_hash(key: u128, messages: &[u128]) -> u128 {
    let mut y = 0;
    for message in messages {
        let yi = galois_mul(y ^ message, key);
        y = yi;
    }
    y
}

pub(super) fn gcm_block_add_one(a: &mut [u8]) {
    for i in 0..4 {
        let (t, c) = a[15 - i].overflowing_add(1);
        a[15 - i] = t;
        if !c {
            return;
        }
    }
}

pub(super) fn bytes_to_u128array(bytes: &[u8]) -> Vec<u128> {
    assert_eq!(bytes.len() % 16, 0);
    let mut out = vec![];
    for chunk in bytes.chunks(16) {
        let mut mid = [0; 16];
        mid.copy_from_slice(chunk);
        out.push(u128::from_be_bytes(mid));
    }
    out
}
