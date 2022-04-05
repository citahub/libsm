use num_bigint::BigUint;
use num_traits::One;

use crate::{sm2::util::kdf, sm3::hash::Sm3Hash};

use super::ecc::{EccCtx, Point};

pub struct EncryptUser {
    klen: usize,
    curve: EccCtx,
    pk_b: Point,
}

pub struct DecryptUser {
    klen: usize,
    curve: EccCtx,
    sk_b: BigUint,
}

impl EncryptUser {
    pub fn new(klen: usize, pk_b: Point) -> EncryptUser {
        EncryptUser {
            klen,
            curve: EccCtx::new(),
            pk_b,
        }
    }

    // klen bytes
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
                // println!("{}, {}", msg.len(), t.len());
                for i in 0..t.len() {
                    t[i] ^= msg[i];
                }
                let mut prepend: Vec<u8> = vec![];
                prepend.extend_from_slice(&x_2_bytes);
                prepend.extend_from_slice(&msg);
                prepend.extend_from_slice(&y_2_bytes);
                let c_3 = Sm3Hash::new(&prepend).get_hash();
                let c_1_bytes = self.curve.point_to_bytes(&c_1_point, false);
                // println!("c_1_bytes = {}", c_1_bytes.len());
                let a = [c_1_bytes, t, c_3.to_vec()].concat();
                return a;
            }
        }
    }
}

impl DecryptUser {
    pub fn new(klen: usize, sk_b: BigUint) -> DecryptUser {
        DecryptUser {
            klen,
            curve: EccCtx::new(),
            sk_b, 
        }
    }

    pub fn decrypt(&self, cipher: &[u8]) -> Vec<u8> {
        let c_1_bytes = &cipher[0..65];
        let c_1_point = self.curve.bytes_to_point(c_1_bytes).unwrap();
        assert!(self.curve.check_point(&c_1_point)); // if c_1_point not in curve, return error
        let h = BigUint::one();
        let s_point = self.curve.mul(&h, &c_1_point);
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
        let mut c_2 = cipher[65..(65+self.klen)].to_vec();
        for i in 0..self.klen {
            c_2[i] ^= t[i];
        }
        let mut prepend: Vec<u8> = vec![];
        prepend.extend_from_slice(&x_2_bytes);
        prepend.extend_from_slice(&c_2);
        prepend.extend_from_slice(&y_2_bytes);
        let c_3 = &cipher[(65+self.klen)..];
        let u = Sm3Hash::new(&prepend).get_hash();
        assert_eq!(u, c_3);
        // u == c_3
        c_2
    }
}


#[cfg(test)]
mod tests {
    use crate::sm2::signature::SigCtx;

    use super::*;

    #[test]
    fn encrypt_test() {
        let msg = "aaaaaaaaaaa123aabb".as_bytes();
        // println!("msg: {}", std::str::from_utf8(&msg).unwrap());
        let klen = msg.len();
        let ctx = SigCtx::new();
        let (pk_b, sk_b) = ctx.new_keypair();

        let encrypt_user = EncryptUser::new(klen, pk_b);
        let cipher = encrypt_user.encrypt(msg);
        // println!("cipher: {:x?}", cipher);

        let decrypt_user = DecryptUser::new(klen, sk_b);
        let plain = decrypt_user.decrypt(&cipher);
        assert_eq!(msg, plain);
        // println!("plain: {}", std::str::from_utf8(&plain).unwrap());
    }
}