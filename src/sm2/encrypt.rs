use num_bigint::BigUint;
use num_traits::One;

use crate::{sm2::util::kdf, sm3::hash::Sm3Hash};

use super::ecc::{EccCtx, Point};

pub struct EncryptCtx {
    klen: usize,
    curve: EccCtx,
    pk_b: Point,
}

pub struct DecryptCtx {
    klen: usize,
    curve: EccCtx,
    sk_b: BigUint,
}

impl EncryptCtx {
    pub fn new(klen: usize, pk_b: Point) -> EncryptCtx {
        EncryptCtx {
            klen,
            curve: EccCtx::new(),
            pk_b,
        }
    }

    // klen bytes, result: C1+C2+C3
    pub fn encrypt(&self, msg: &[u8]) -> Vec<u8> {
        loop {
            let k = self.curve.random_uint();
            let c_1_point = self.curve.g_mul(&k);
            let h = BigUint::one();
            let s_point = self.curve.mul(&h, &self.pk_b);
            assert!(!s_point.is_zero());

            let c_2_point = self.curve.mul(&k, &self.pk_b);
            let (x_2, y_2) = self.curve.to_affine(&c_2_point);
            let x_2_bytes = x_2.to_bytes();
            let y_2_bytes = y_2.to_bytes();

            let mut prepend: Vec<u8> = vec![];
            prepend.extend_from_slice(&x_2_bytes);
            prepend.extend_from_slice(&y_2_bytes);
            let mut t = kdf(&prepend, self.klen);

            let mut flag = true;
            for elem in &t {
                if elem != &0 {
                    flag = false;
                    break;
                }
            }

            if !flag {
                for i in 0..t.len() {
                    t[i] ^= msg[i];
                }
                let mut prepend: Vec<u8> = vec![];
                prepend.extend_from_slice(&x_2_bytes);
                prepend.extend_from_slice(msg);
                prepend.extend_from_slice(&y_2_bytes);
                let c_3 = Sm3Hash::new(&prepend).get_hash();
                let c_1_bytes = self.curve.point_to_bytes(&c_1_point, false);

                let a = [c_1_bytes, t, c_3.to_vec()].concat();
                return a;
            }
        }
    }
}

impl DecryptCtx {
    pub fn new(klen: usize, sk_b: BigUint) -> DecryptCtx {
        DecryptCtx {
            klen,
            curve: EccCtx::new(),
            sk_b,
        }
    }

    pub fn decrypt(&self, cipher: &[u8]) -> Vec<u8> {
        let c_1_bytes = &cipher[0..65];
        let c_1_point = self.curve.bytes_to_point(c_1_bytes).unwrap();
        // if c_1_point not in curve, return error, todo return error
        assert!(self.curve.check_point(&c_1_point));
        let h = BigUint::one();
        let s_point = self.curve.mul(&h, &c_1_point);
        // todo return error
        assert!(!s_point.is_zero());

        let c_2_point = self.curve.mul(&self.sk_b, &c_1_point);
        let (x_2, y_2) = self.curve.to_affine(&c_2_point);
        let x_2_bytes = x_2.to_bytes();
        let y_2_bytes = y_2.to_bytes();

        let mut prepend: Vec<u8> = vec![];
        prepend.extend_from_slice(&x_2_bytes);
        prepend.extend_from_slice(&y_2_bytes);
        let t = kdf(&prepend, self.klen);
        let mut flag = true;
        for elem in &t {
            if elem != &0 {
                flag = false;
                break;
            }
        }
        assert!(!flag);
        let mut c_2 = cipher[65..(65 + self.klen)].to_vec();
        for i in 0..self.klen {
            c_2[i] ^= t[i];
        }
        let mut prepend: Vec<u8> = vec![];
        prepend.extend_from_slice(&x_2_bytes);
        prepend.extend_from_slice(&c_2);
        prepend.extend_from_slice(&y_2_bytes);
        let c_3 = &cipher[(65 + self.klen)..];
        let u = Sm3Hash::new(&prepend).get_hash();

        assert_eq!(u, c_3);
        c_2
    }
}

#[cfg(test)]
mod tests {
    use crate::sm2::signature::SigCtx;

    use super::*;

    #[test]
    fn sm2_encrypt_decrypt_test() {
        let msg = "hello world".as_bytes();
        let klen = msg.len();
        let ctx = SigCtx::new();
        let (pk_b, sk_b) = ctx.new_keypair();

        let encrypt_ctx = EncryptCtx::new(klen, pk_b);
        let cipher = encrypt_ctx.encrypt(msg);

        let decrypt_ctx = DecryptCtx::new(klen, sk_b);
        let plain = decrypt_ctx.decrypt(&cipher);
        assert_eq!(msg, plain);
    }
}
