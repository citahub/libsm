use crate::sm3::hash::Sm3Hash;

// DIFFERNCE: klen bytes, not klen bits
pub fn kdf(z: &[u8], klen: usize) -> Vec<u8> {
    let mut ct = 0x0000_0001_u32;
    let bound = ((klen as f64) / 32.0).ceil() as u32;
    let mut h_a = Vec::new();
    for _i in 1..bound {
        let mut prepend = Vec::new();
        prepend.extend_from_slice(z);
        prepend.extend_from_slice(&ct.to_be_bytes());

        let mut hasher = Sm3Hash::new(&prepend[..]);
        let h_a_i = hasher.get_hash();
        h_a.extend_from_slice(&h_a_i);
        ct += 1;
    }
    let mut prepend = Vec::new();
    prepend.extend_from_slice(z);
    prepend.extend_from_slice(&ct.to_be_bytes());

    let mut hasher = Sm3Hash::new(&prepend[..]);
    let last = hasher.get_hash();

    if klen % 32 == 0 {
        h_a.extend_from_slice(&last);
    } else {
        h_a.extend_from_slice(&last[0..(klen % 32)]);
    }
    h_a
}
