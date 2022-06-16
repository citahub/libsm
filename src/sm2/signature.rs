// Copyright 2018 Cryptape Technology LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::sm2::error::{Sm2Error, Sm2Result};
use crate::sm3::hash::Sm3Hash;

use super::ecc::*;
use super::field::FieldElem;
use byteorder::{BigEndian, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::*;
use std::fmt;
use yasna;

pub type Pubkey = Point;
pub type Seckey = BigUint;

pub struct Signature {
    r: BigUint,
    s: BigUint,
}

impl Signature {
    pub fn new(r_bytes: &[u8], s_bytes: &[u8]) -> Self {
        let r = BigUint::from_bytes_be(r_bytes);
        let s = BigUint::from_bytes_be(s_bytes);
        Signature { r, s }
    }

    pub fn der_decode(buf: &[u8]) -> Result<Signature, yasna::ASN1Error> {
        let (r, s) = yasna::parse_der(buf, |reader| {
            reader.read_sequence(|reader| {
                let r = reader.next().read_biguint()?;
                let s = reader.next().read_biguint()?;
                Ok((r, s))
            })
        })?;
        Ok(Signature { r, s })
    }

    pub fn der_decode_raw(buf: &[u8]) -> Result<Signature, Sm2Error> {
        if buf[0] != 0x02 {
            return Err(Sm2Error::InvalidDer);
        }
        let r_len: usize = buf[1] as usize;
        if buf.len() <= r_len + 4 {
            return Err(Sm2Error::InvalidDer);
        }
        let r = BigUint::from_bytes_be(&buf[2..2 + r_len]);

        let buf = &buf[2 + r_len..];
        if buf[0] != 0x02 {
            return Err(Sm2Error::InvalidDer);
        }
        let s_len: usize = buf[1] as usize;
        if buf.len() < s_len + 2 {
            return Err(Sm2Error::InvalidDer);
        }
        let s = BigUint::from_bytes_be(&buf[2..2 + s_len]);

        Ok(Signature { r, s })
    }

    pub fn der_encode(&self) -> Vec<u8> {
        yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_biguint(&self.r);
                writer.next().write_biguint(&self.s);
            })
        })
    }

    #[inline]
    pub fn get_r(&self) -> &BigUint {
        &self.r
    }

    #[inline]
    pub fn get_s(&self) -> &BigUint {
        &self.s
    }
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "r = 0x{:0>64}, s = 0x{:0>64}",
            self.r.to_str_radix(16),
            self.s.to_str_radix(16)
        )
    }
}

pub struct SigCtx {
    curve: EccCtx,
}

impl SigCtx {
    pub fn new() -> SigCtx {
        SigCtx {
            curve: EccCtx::new(),
        }
    }

    pub fn hash(&self, id: &str, pk: &Point, msg: &[u8]) -> Sm2Result<[u8; 32]> {
        let curve = &self.curve;

        let mut prepend: Vec<u8> = Vec::new();
        if id.len() * 8 > 65535 {
            return Err(Sm2Error::IdTooLong);
        }
        prepend
            .write_u16::<BigEndian>((id.len() * 8) as u16)
            .unwrap();
        for c in id.bytes() {
            prepend.push(c);
        }

        let mut a = curve.get_a().to_bytes();
        let mut b = curve.get_b().to_bytes();

        prepend.append(&mut a);
        prepend.append(&mut b);

        let (x_g, y_g) = curve.to_affine(&curve.generator()?)?;
        let (mut x_g, mut y_g) = (x_g.to_bytes(), y_g.to_bytes());
        prepend.append(&mut x_g);
        prepend.append(&mut y_g);

        let (x_a, y_a) = curve.to_affine(pk)?;
        let (mut x_a, mut y_a) = (x_a.to_bytes(), y_a.to_bytes());
        prepend.append(&mut x_a);
        prepend.append(&mut y_a);

        let mut hasher = Sm3Hash::new(&prepend[..]);
        let z_a = hasher.get_hash();

        // Z_A = HASH_256(ID_LEN || ID || x_G || y_G || x_A || y_A)

        // e = HASH_256(Z_A || M)

        let mut prepended_msg: Vec<u8> = Vec::new();
        prepended_msg.extend_from_slice(&z_a[..]);
        prepended_msg.extend_from_slice(msg);

        let mut hasher = Sm3Hash::new(&prepended_msg[..]);
        Ok(hasher.get_hash())
    }

    pub fn recid_combine(&self, id: &str, pk: &Point, msg: &[u8]) -> Sm2Result<Vec<u8>> {
        let curve = &self.curve;

        let mut prepend: Vec<u8> = Vec::new();
        if id.len() * 8 > 65535 {
            return Err(Sm2Error::IdTooLong);
        }
        prepend
            .write_u16::<BigEndian>((id.len() * 8) as u16)
            .unwrap();
        for c in id.bytes() {
            prepend.push(c);
        }

        let mut a = curve.get_a().to_bytes();
        let mut b = curve.get_b().to_bytes();

        prepend.append(&mut a);
        prepend.append(&mut b);

        let (x_g, y_g) = curve.to_affine(&curve.generator()?)?;
        let (mut x_g, mut y_g) = (x_g.to_bytes(), y_g.to_bytes());
        prepend.append(&mut x_g);
        prepend.append(&mut y_g);

        let (x_a, y_a) = curve.to_affine(pk)?;
        let (mut x_a, mut y_a) = (x_a.to_bytes(), y_a.to_bytes());
        prepend.append(&mut x_a);
        prepend.append(&mut y_a);

        let mut hasher = Sm3Hash::new(&prepend[..]);
        let z_a = hasher.get_hash();

        // Z_A = HASH_256(ID_LEN || ID || x_G || y_G || x_A || y_A)

        // e = HASH_256(Z_A || M)

        let mut prepended_msg: Vec<u8> = Vec::new();
        prepended_msg.extend_from_slice(&z_a[..]);
        prepended_msg.extend_from_slice(msg);

        Ok(prepended_msg)
    }

    pub fn sign(&self, msg: &[u8], sk: &BigUint, pk: &Point) -> Sm2Result<Signature> {
        // Get the value "e", which is the hash of message and ID, EC parameters and public key
        let digest = self.hash("1234567812345678", pk, msg)?;

        self.sign_raw(&digest[..], sk)
    }

    pub fn sign_raw(&self, digest: &[u8], sk: &BigUint) -> Sm2Result<Signature> {
        let curve = &self.curve;
        // Get the value "e", which is the hash of message and ID, EC parameters and public key

        let e = BigUint::from_bytes_be(digest);

        // two while loops
        loop {
            // k = rand()
            // (x_1, y_1) = g^kg
            let k = self.curve.random_uint();

            let p_1 = curve.g_mul(&k)?;
            let (x_1, _) = curve.to_affine(&p_1)?;
            let x_1 = x_1.to_biguint();

            // r = e + x_1
            let r = (&e + x_1) % curve.get_n();
            if r == BigUint::zero() || &r + &k == *curve.get_n() {
                continue;
            }

            // s = (1 + sk)^-1 * (k - r * sk)
            let s1 = curve.inv_n(&(sk + BigUint::one()))?;

            let mut s2_1 = &r * sk;
            if s2_1 < k {
                s2_1 += curve.get_n();
            }
            let mut s2 = s2_1 - k;
            s2 %= curve.get_n();
            let s2 = curve.get_n() - s2;

            let s = (s1 * s2) % curve.get_n();

            if s != BigUint::zero() {
                // Output the signature (r, s)
                return Ok(Signature { r, s });
            }
            return Err(Sm2Error::ZeroSig);
        }
    }

    pub fn verify(&self, msg: &[u8], pk: &Point, sig: &Signature) -> Sm2Result<bool> {
        //Get hash value
        let digest = self.hash("1234567812345678", pk, msg)?;
        //println!("digest: {:?}", digest);
        self.verify_raw(&digest[..], pk, sig)
    }

    pub fn verify_raw(&self, digest: &[u8], pk: &Point, sig: &Signature) -> Sm2Result<bool> {
        if digest.len() != 32 {
            return Err(Sm2Error::InvalidDigestLen);
        }
        let e = BigUint::from_bytes_be(digest);

        let curve = &self.curve;
        // check r and s
        if *sig.get_r() == BigUint::zero() || *sig.get_s() == BigUint::zero() {
            return Ok(false);
        }
        if *sig.get_r() >= *curve.get_n() || *sig.get_s() >= *curve.get_n() {
            return Ok(false);
        }

        // calculate R
        let t = (sig.get_s() + sig.get_r()) % curve.get_n();
        if t == BigUint::zero() {
            return Ok(false);
        }

        let p_1 = curve.add(&curve.g_mul(sig.get_s())?, &curve.mul(&t, pk)?)?;
        let (x_1, _) = curve.to_affine(&p_1)?;
        let x_1 = x_1.to_biguint();

        let r_ = (e + x_1) % curve.get_n();

        // check R == r?
        Ok(r_ == *sig.get_r())
    }

    pub fn new_keypair(&self) -> Sm2Result<(Point, BigUint)> {
        let curve = &self.curve;
        let mut sk: BigUint = curve.random_uint();
        let mut pk: Point = curve.g_mul(&sk)?;

        loop {
            if !pk.is_zero() {
                break;
            }
            sk = curve.random_uint();
            pk = curve.g_mul(&sk)?;
        }

        Ok((pk, sk))
    }

    pub fn pk_from_sk(&self, sk: &BigUint) -> Sm2Result<Point> {
        let curve = &self.curve;
        if *sk >= *curve.get_n() || *sk == BigUint::zero() {
            return Err(Sm2Error::InvalidSecretKey);
        }
        curve.g_mul(sk)
    }

    pub fn load_pubkey(&self, buf: &[u8]) -> Result<Point, Sm2Error> {
        self.curve.bytes_to_point(buf)
    }

    pub fn serialize_pubkey(&self, p: &Point, compress: bool) -> Sm2Result<Vec<u8>> {
        self.curve.point_to_bytes(p, compress)
    }

    pub fn load_seckey(&self, buf: &[u8]) -> Result<BigUint, Sm2Error> {
        if buf.len() != 32 {
            return Err(Sm2Error::InvalidPrivate);
        }
        let sk = BigUint::from_bytes_be(buf);
        if sk > *self.curve.get_n() {
            Err(Sm2Error::InvalidPrivate)
        } else {
            Ok(sk)
        }
    }

    pub fn serialize_seckey(&self, x: &BigUint) -> Sm2Result<Vec<u8>> {
        if *x > *self.curve.get_n() {
            return Err(Sm2Error::InvalidSecretKey);
        }
        let x = FieldElem::from_biguint(x)?;
        Ok(x.to_bytes())
    }
}

impl Default for SigCtx {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign() {
        let string = String::from("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        let msg = string.as_bytes();

        let ctx = SigCtx::new();
        let (pk, sk) = ctx.new_keypair().unwrap();
        let signature = ctx.sign(msg, &sk, &pk).unwrap();

        println!("public key is {}, signature is {}", pk, signature);
    }

    #[test]
    fn test_sign_and_verify() {
        let string = String::from("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        let msg = string.as_bytes();

        let ctx = SigCtx::new();
        let (pk, sk) = ctx.new_keypair().unwrap();
        let signature = ctx.sign(msg, &sk, &pk).unwrap();

        assert!(ctx.verify(msg, &pk, &signature).unwrap());
    }

    #[test]
    fn test_sig_encode_and_decode() {
        let string = String::from("abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd");
        let msg = string.as_bytes();

        let ctx = SigCtx::new();
        let (pk, sk) = ctx.new_keypair().unwrap();

        let signature = ctx.sign(msg, &sk, &pk).unwrap();
        let der = signature.der_encode();
        let sig = Signature::der_decode(&der[..]).unwrap();
        assert!(ctx.verify(msg, &pk, &sig).unwrap());

        let signature = ctx.sign(msg, &sk, &pk).unwrap();
        let der = signature.der_encode();
        let sig = Signature::der_decode_raw(&der[2..]).unwrap();
        assert!(ctx.verify(msg, &pk, &sig).unwrap());
    }

    #[test]
    fn test_key_serialization() {
        let ctx = SigCtx::new();
        let (pk, sk) = ctx.new_keypair().unwrap();

        let pk_v = ctx.serialize_pubkey(&pk, true).unwrap();
        let new_pk = ctx.load_pubkey(&pk_v[..]).unwrap();
        assert!(ctx.curve.eq(&new_pk, &pk).unwrap());

        let sk_v = ctx.serialize_seckey(&sk).unwrap();
        let new_sk = ctx.load_seckey(&sk_v[..]).unwrap();
        assert_eq!(new_sk, sk);
    }

    #[test]
    fn test_gmssl() {
        let msg: &[u8] = &[
            0x66, 0xc7, 0xf0, 0xf4, 0x62, 0xee, 0xed, 0xd9, 0xd1, 0xf2, 0xd4, 0x6b, 0xdc, 0x10,
            0xe4, 0xe2, 0x41, 0x67, 0xc4, 0x87, 0x5c, 0xf2, 0xf7, 0xa2, 0x29, 0x7d, 0xa0, 0x2b,
            0x8f, 0x4b, 0xa8, 0xe0,
        ];

        let pk: &[u8] = &[
            4, 233, 185, 71, 125, 111, 174, 63, 105, 217, 19, 218, 72, 114, 185, 96, 243, 176, 1,
            8, 239, 132, 114, 119, 216, 38, 21, 117, 142, 223, 42, 157, 170, 123, 219, 65, 50, 238,
            191, 116, 238, 240, 197, 158, 1, 145, 177, 107, 112, 91, 101, 86, 50, 204, 218, 254,
            172, 2, 250, 33, 56, 176, 121, 16, 215,
        ];

        let sig: &[u8] = &[
            48, 69, 2, 33, 0, 171, 111, 172, 181, 242, 159, 198, 106, 33, 229, 104, 147, 245, 97,
            132, 141, 141, 17, 27, 97, 156, 159, 160, 188, 239, 78, 124, 17, 211, 124, 113, 26, 2,
            32, 53, 21, 4, 195, 198, 42, 71, 17, 110, 157, 113, 185, 178, 74, 147, 87, 129, 179,
            168, 163, 171, 126, 39, 156, 198, 29, 163, 199, 82, 25, 13, 112,
        ];

        let curve = EccCtx::new();
        let ctx = SigCtx::new();

        let pk = curve.bytes_to_point(pk).unwrap();

        let sig = Signature::der_decode(sig).unwrap();

        assert!(ctx.verify_raw(msg, &pk, &sig).unwrap());
    }

    #[test]
    fn verify_third_test() {
        let ctx = SigCtx::new();
        let msg = b"hello world";

        let ecc_ctx = EccCtx::new();
        let pk_bz = hex::decode("0420e9c9497bf151e33c3af9e7deb63e2133a27d21fa1647cee0afda049af1f664f81dc793ebab487ab51414081075e57a65b016da4087f491c04977a6397327b2").unwrap();
        let pk = ecc_ctx.bytes_to_point(&pk_bz).unwrap();

        let sig_r_bz =
            hex::decode("76415405cbb177ebb37a835a2b5a022f66c250abf482e4cb343dcb2091bc1f2e")
                .unwrap();
        let sig_s_bz =
            hex::decode("61f0665f805e78dd19073922992c671867a1dee839e8179d39b532eb66b9cd90")
                .unwrap();
        let sig = Signature::new(&sig_r_bz, &sig_s_bz);

        assert!(ctx.verify(msg, &pk, &sig).unwrap());
    }

    #[test]
    fn verify_third_der_test() {
        let ctx = SigCtx::new();
        let msg = "jonllen".to_string().into_bytes();

        let ecc_ctx = EccCtx::new();
        let pk_bz = hex::decode("044f954d8c4d7c0133e5f402c7e75623438c2dcee5ae5ee6c2f1fca51c60f7017e9cfad13514cd4e7faeca476a98eeb0b8a62c1f6add9794beead4a42291b94278").unwrap();
        let pk = ecc_ctx.bytes_to_point(&pk_bz).unwrap();

        let sig_bz  = hex::decode("304402207e665a4d2781cb488bd374ccf1c8116e95ad0731c99e1dc36c189fd4daf0cb0202206a7ddd6483db176192b25aba9a92bc4de8b76e2c6d1559965ad06224d0725531").unwrap();
        let sig = Signature::der_decode(&sig_bz).unwrap();

        assert!(ctx.verify(&msg, &pk, &sig).unwrap());
    }
}

#[cfg(feature = "internal_benches")]
mod signature_benches {
    use sm2::signature::SigCtx;

    extern crate test;

    #[bench]
    fn sign_bench(bench: &mut test::Bencher) {
        let test_word = b"hello world";
        let ctx = SigCtx::new();
        let (pk, sk) = ctx.new_keypair().unwrap();

        bench.iter(|| {
            let _ = ctx.sign(test_word, &sk, &pk);
        });
    }

    #[bench]
    fn verify_bench(bench: &mut test::Bencher) {
        let test_word = b"hello world";
        let ctx = SigCtx::new();
        let (pk, sk) = ctx.new_keypair().unwrap();
        let sig = ctx.sign(test_word, &sk, &pk).unwrap();

        bench.iter(|| {
            let _ = ctx.verify(test_word, &pk, &sig);
        });
    }
}
