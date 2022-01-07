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

use super::field::*;
use num_bigint::BigUint;
use num_integer::Integer;
use num_traits::*;

use rand::os::OsRng;
use rand::Rng;

pub struct EccCtx {
    fctx: FieldCtx,
    a: FieldElem,
    b: FieldElem,
    n: BigUint,
}

#[derive(Clone, PartialEq, Eq, Copy)]
pub struct Point {
    pub x: FieldElem,
    pub y: FieldElem,
    pub z: FieldElem,
}

fn pre_vec_gen(n: u32) -> [u32; 8] {
    let mut pre_vec: [u32; 8] = [0; 8];
    let mut i = 0;
    while i < 8 {
        pre_vec[7 - i] = (n >> i) & 0x01;
        i += 1;
    }
    pre_vec
}
fn pre_vec_gen2(n: u32) -> [u32; 8] {
    let mut pre_vec: [u32; 8] = [0; 8];
    let mut i = 0;
    while i < 8 {
        pre_vec[7 - i] = ((n >> i) & 0x01) << 16;
        i += 1;
    }
    pre_vec
}

lazy_static! {
    static ref TABLE_1: Vec<Point> = {
        let mut table: Vec<Point> = Vec::new();
        let ctx = EccCtx::new();
        for i in 0..256 {
            let p1 = ctx.mul_raw(&pre_vec_gen(i as u32), &ctx.generator());
            table.push(p1);
        }
        table
    };
    static ref TABLE_2: Vec<Point> = {
        let mut table: Vec<Point> = Vec::new();
        let ctx = EccCtx::new();
        for i in 0..256 {
            let p1 = ctx.mul_raw(&pre_vec_gen2(i as u32), &ctx.generator());
            table.push(p1);
        }
        table
    };
}

impl EccCtx {
    pub fn new() -> EccCtx {
        EccCtx {
            fctx: FieldCtx::new(),
            a: FieldElem::new([
                0xffff_fffe,
                0xffff_ffff,
                0xffff_ffff,
                0xffff_ffff,
                0xffff_ffff,
                0x0000_0000,
                0xffff_ffff,
                0xffff_fffc,
            ]),
            b: FieldElem::new([
                0x28e9_fa9e,
                0x9d9f_5e34,
                0x4d5a_9e4b,
                0xcf65_09a7,
                0xf397_89f5,
                0x15ab_8f92,
                0xddbc_bd41,
                0x4d94_0e93,
            ]),
            n: BigUint::from_str_radix(
                "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123",
                16,
            )
            .unwrap(),
        }
    }

    #[inline]
    pub fn get_a(&self) -> &FieldElem {
        &self.a
    }

    #[inline]
    pub fn get_b(&self) -> &FieldElem {
        &self.b
    }

    #[inline]
    pub fn get_n(&self) -> &BigUint {
        &self.n
    }

    pub fn inv_n(&self, x: &BigUint) -> BigUint {
        if *x == BigUint::zero() {
            panic!("zero has no inversion.");
        }

        let mut ru = x.clone();
        let mut rv = self.get_n().clone();
        let mut ra = BigUint::one();
        let mut rc = BigUint::zero();

        let rn = self.get_n().clone();

        while ru != BigUint::zero() {
            if ru.is_even() {
                ru >>= 1;
                if ra.is_even() {
                    ra >>= 1;
                } else {
                    ra = (ra + &rn) >> 1;
                }
            }

            if rv.is_even() {
                rv >>= 1;
                if rc.is_even() {
                    rc >>= 1;
                } else {
                    rc = (rc + &rn) >> 1;
                }
            }

            if ru >= rv {
                ru -= &rv;
                if ra >= rc {
                    ra -= &rc;
                } else {
                    ra = ra + &rn - &rc;
                }
            } else {
                rv -= &ru;
                if rc >= ra {
                    rc -= &ra;
                } else {
                    rc = rc + &rn - &ra;
                }
            }
        }
        rc
    }

    pub fn new_point(&self, x: &FieldElem, y: &FieldElem) -> Result<Point, Sm2Error> {
        let ctx = &self.fctx;

        // Check if (x, y) is a valid point on the curve(affine projection)
        // y^2 = x^3 + a * x + b
        let lhs = ctx.mul(&y, &y);

        let x_cubic = ctx.mul(&x, &ctx.mul(&x, &x));
        let ax = ctx.mul(&x, &self.a);
        let rhs = ctx.add(&self.b, &ctx.add(&x_cubic, &ax));

        if !lhs.eq(&rhs) {
            return Err(Sm2Error::NotOnCurve);
        }

        let p = Point {
            x: *x,
            y: *y,
            z: FieldElem::from_num(1),
        };
        Ok(p)
    }

    // TODO: load point
    // pub fn load_point(&self, buf: &[u8]) -> Result<Point, ()>

    pub fn new_jacobian(
        &self,
        x: &FieldElem,
        y: &FieldElem,
        z: &FieldElem,
    ) -> Result<Point, String> {
        let ctx = &self.fctx;

        // Check if (x, y, z) is a valid point on the curve(in jacobian projection)
        // y^2 = x^3 + a * x * z^4 + b * z^6
        let lhs = ctx.square(y);

        let r1 = ctx.cubic(x);

        let r2 = ctx.mul(x, &self.a);
        let r2 = ctx.mul(&r2, z);
        let r2 = ctx.mul(&r2, &ctx.cubic(z));

        let r3 = ctx.cubic(z);
        let r3 = ctx.square(&r3);
        let r3 = ctx.mul(&r3, &self.b);

        let rhs = ctx.add(&r1, &ctx.add(&r2, &r3));

        // Require lhs =rhs
        if !lhs.eq(&rhs) {
            return Err(String::from("invalid jacobian point"));
        }

        let p = Point {
            x: *x,
            y: *y,
            z: *z,
        };
        Ok(p)
    }

    pub fn generator(&self) -> Point {
        let x = FieldElem::new([
            0x32c4_ae2c,
            0x1f19_8119,
            0x5f99_0446,
            0x6a39_c994,
            0x8fe3_0bbf,
            0xf266_0be1,
            0x715a_4589,
            0x334c_74c7,
        ]);
        let y = FieldElem::new([
            0xbc37_36a2,
            0xf4f6_779c,
            0x59bd_cee3,
            0x6b69_2153,
            0xd0a9_877c,
            0xc62a_4740,
            0x02df_32e5,
            0x2139_f0a0,
        ]);

        match self.new_point(&x, &y) {
            Ok(p) => p,
            Err(m) => panic!("{:?}", m),
        }
    }

    pub fn zero(&self) -> Point {
        let x = FieldElem::from_num(1);
        let y = FieldElem::from_num(1);
        let z = FieldElem::zero();

        self.new_jacobian(&x, &y, &z).unwrap()
    }

    pub fn to_affine(&self, p: &Point) -> (FieldElem, FieldElem) {
        let ctx = &self.fctx;
        if p.is_zero() {
            panic!("cannot convert the infinite point to affine");
        }

        let zinv = ctx.inv(&p.z);
        let x = ctx.mul(&p.x, &ctx.mul(&zinv, &zinv));
        let y = ctx.mul(&p.y, &ctx.mul(&zinv, &ctx.mul(&zinv, &zinv)));
        (x, y)
    }

    pub fn neg(&self, p: &Point) -> Point {
        let neg_y = self.fctx.neg(&p.y);
        match self.new_jacobian(&p.x, &neg_y, &p.z) {
            Ok(neg_p) => neg_p,
            Err(e) => panic!("{}", e),
        }
    }

    //add-1998-cmo-2 curve_add 13m+4s
    pub fn add(&self, p1: &Point, p2: &Point) -> Point {
        if p1.is_zero() {
            return p2.clone();
        } else if p2.is_zero() {
            return p1.clone();
        }

        if p1 == p2 {
            return self.double(&p1);
        }

        let ctx = &self.fctx;

        let z1z1 = ctx.square(&p1.z);
        let z2z2 = ctx.square(&p2.z);
        let u1 = ctx.mul(&p1.x, &z2z2);
        let u2 = ctx.mul(&p2.x, &z1z1);
        let s1 = ctx.mul(&p1.y, &ctx.mul(&p2.z, &z2z2));
        let s2 = ctx.mul(&p2.y, &ctx.mul(&p1.z, &z1z1));

        let h = ctx.sub(&u2, &u1);
        let hh = ctx.square(&h);
        let hhh = ctx.mul(&h, &hh);
        let r = ctx.sub(&s2, &s1);
        let v = ctx.mul(&u1, &hh);

        let x3 = ctx.sub(
            &ctx.sub(&ctx.square(&r), &hhh),
            &ctx.mul(&FieldElem::from_num(2), &v),
        );

        let rvx3 = ctx.mul(&r, &ctx.sub(&v, &x3));
        let s1hhh = ctx.mul(&s1, &hhh);

        let y3 = ctx.sub(&rvx3, &s1hhh);
        let z3 = ctx.mul(&p1.z, &ctx.mul(&p2.z, &h));

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    //dbl-1998-cmo-2 9m+6s
    // XX = X12
    // YY = Y12
    // ZZ = Z12
    // S = 4*X1*YY
    // M = 3*XX+a*ZZ2
    // T = M2-2*S
    // X3 = T
    // Y3 = M*(S-T)-8*YY2
    // Z3 = 2*Y1*Z1
    pub fn double(&self, p: &Point) -> Point {
        if p.is_zero() {
            return p.clone();
        }

        let ctx = &self.fctx;

        let xx = ctx.square(&p.x);
        let yy = ctx.square(&p.y);
        let zz = ctx.square(&p.z);
        let yy8 = &ctx.mul(&FieldElem::from_num(8), &ctx.square(&yy));

        let s = ctx.mul(&FieldElem::from_num(4), &ctx.mul(&p.x, &yy));
        let m = ctx.add(
            &ctx.mul(&FieldElem::from_num(3), &xx),
            &ctx.mul(&self.a, &ctx.square(&zz)),
        );

        let x3 = ctx.sub(&ctx.square(&m), &ctx.mul(&FieldElem::from_num(2), &s));

        let y3 = ctx.sub(&ctx.mul(&m, &ctx.sub(&s, &x3)), &yy8);

        let z3 = ctx.mul(&FieldElem::from_num(2), &ctx.mul(&p.y, &p.z));

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    pub fn mul(&self, m: &BigUint, p: &Point) -> Point {
        let m = m % self.get_n();

        let k = FieldElem::from_biguint(&m);

        self.mul_raw_naf(&k.value, p)
    }

    pub fn w_naf(&self, m:&[u32], w: usize, lst: &mut usize) -> [i8;257]{
        let mut carry = 0;
        let mut bit = 0;
        let mut ret: [i8; 257] = [0; 257];
        let mut n:[u32; 9] = [0; 9];

        n[1..9].clone_from_slice(&m[..8]);

        let window: u32 = (1 << w) -1;

        while bit < 256 {
            let u32_idx = 8 - bit as usize / 32;
            let bit_idx = 31 - bit as usize % 32;
            let mut word: u32 ;

            if ((n[u32_idx] >> (31 - bit_idx)) & 1) == carry{
                bit += 1;
                continue;
            }

            if bit_idx >= w-1 {
                word = (n[u32_idx] >> (31 - bit_idx)) & window;
            }
            else{
                word = ((n[u32_idx] >> (31 - bit_idx)) | (n[u32_idx - 1] << (bit_idx + 1)) ) & window;
            }

            word += carry;

            carry = (word >> (w-1)) & 1;
            ret[bit] = word as i8 - (carry<<w) as i8;

            *lst = bit;
            bit += w;

        }

        if carry == 1{
            ret[256] = 1;
            *lst = 256;
        }

        ret
    }

    pub fn mul_raw_naf(&self, m: &[u32], p: &Point) -> Point {
        let mut i = 256;
        let mut q = self.zero();
        let naf = self.w_naf(&m,5, &mut i);
        let offset = 16;
        let mut table = [self.zero(); 32];
        let double_p = self.double(&p);

        table[1 + offset] = p.clone();
        table[offset - 1] = self.neg(&table[1 + offset]);
        for i in 1..8 {
            table[2 * i + offset + 1] = self.add(&double_p, &table[2 * i + offset -1]);
            table[offset - 2 * i - 1] = self.neg(&table[2 * i + offset + 1]);
        }

        loop {
            q = self.double(&q);

            if naf[i] != 0 {
                let index = (naf[i] + 16) as usize;
                q = self.add(&q, &table[index]);
            }

            if i == 0 {
                break;
            }
            i -= 1;
        }
        q
    }

    pub fn mul_raw(&self, m: &[u32], p: &Point) -> Point {
        let mut q = self.zero();

        let mut i = 0;
        while i < 256 {
            let index = i as usize / 32;
            let bit = 31 - i as usize % 32;

            // let sum = self.add(&q0, &q1);
            q = self.double(&q);

            if (m[index] >> bit) & 0x01 != 0 {
                q = self.add(&q, &p);

                // q = self.double(&q0);
            }

            i += 1;
        }
        q
    }
    #[inline(always)]
    fn ith_bit(n: u32, i: i32) -> u32 {
        (n >> i) & 0x01
    }

    #[inline(always)]
    fn compose_k(v: &[u32], i: i32) -> u32 {
        EccCtx::ith_bit(v[7], i)
            + (EccCtx::ith_bit(v[6], i) << 1)
            + (EccCtx::ith_bit(v[5], i) << 2)
            + (EccCtx::ith_bit(v[4], i) << 3)
            + (EccCtx::ith_bit(v[3], i) << 4)
            + (EccCtx::ith_bit(v[2], i) << 5)
            + (EccCtx::ith_bit(v[1], i) << 6)
            + (EccCtx::ith_bit(v[0], i) << 7)
    }

    pub fn g_mul(&self, m: &BigUint) -> Point {
        let m = m % self.get_n();
        let k = FieldElem::from_biguint(&m);
        let mut q = self.zero();

        let mut i = 15;
        while i >= 0 {
            q = self.double(&q);
            let k1 = EccCtx::compose_k(&k.value, i);
            let k2 = EccCtx::compose_k(&k.value, i + 16);
            let p1 = &TABLE_1[k1 as usize];
            let p2 = &TABLE_2[k2 as usize];
            q = self.add(&self.add(&q, p1), p2);

            i -= 1;
        }

        q
    }

    pub fn eq(&self, p1: &Point, p2: &Point) -> bool {
        let z1 = &p1.z;
        let z2 = &p2.z;
        if z1.eq(&FieldElem::zero()) {
            return z2.eq(&FieldElem::zero());
        } else if z2.eq(&FieldElem::zero()) {
            return false;
        }

        let (p1x, p1y) = self.to_affine(p1);
        let (p2x, p2y) = self.to_affine(p2);

        p1x.eq(&p2x) && p1y.eq(&p2y)
    }

    pub fn random_uint(&self) -> BigUint {
        let mut rng = OsRng::new().unwrap();
        let mut buf: [u8; 32] = [0; 32];

        let mut ret;

        loop {
            rng.fill_bytes(&mut buf[..]);
            ret = BigUint::from_bytes_be(&buf[..]);
            if ret < self.get_n() - BigUint::one() && ret != BigUint::zero() {
                break;
            }
        }
        ret
    }

    pub fn point_to_bytes(&self, p: &Point, compress: bool) -> Vec<u8> {
        let (x, y) = self.to_affine(p);
        let mut ret: Vec<u8> = Vec::new();

        if compress {
            if y.get_value(7) & 0x01 == 0 {
                ret.push(0x02);
            } else {
                ret.push(0x03);
            }
            let mut x_vec = x.to_bytes();
            ret.append(&mut x_vec);
        } else {
            ret.push(0x04);
            let mut x_vec = x.to_bytes();
            let mut y_vec = y.to_bytes();
            ret.append(&mut x_vec);
            ret.append(&mut y_vec);
        }
        ret
    }

    pub fn bytes_to_point(&self, b: &[u8]) -> Result<Point, Sm2Error> {
        let ctx = &self.fctx;

        if b.len() == 33 {
            let y_q;
            if b[0] == 0x02 {
                y_q = 0;
            } else if b[0] == 0x03 {
                y_q = 1
            } else {
                return Err(Sm2Error::InvalidPublic);
            }

            let x = FieldElem::from_bytes(&b[1..]);

            let x_cubic = ctx.mul(&x, &ctx.mul(&x, &x));
            let ax = ctx.mul(&x, &self.a);
            let y_2 = ctx.add(&self.b, &ctx.add(&x_cubic, &ax));

            let mut y = self.fctx.sqrt(&y_2)?;

            if y.get_value(7) & 0x01 != y_q {
                y = self.fctx.neg(&y);
            }

            self.new_point(&x, &y)
        } else if b.len() == 65 {
            if b[0] != 0x04 {
                return Err(Sm2Error::InvalidPublic);
            }
            let x = FieldElem::from_bytes(&b[1..33]);
            let y = FieldElem::from_bytes(&b[33..65]);

            self.new_point(&x, &y)
        } else {
            Err(Sm2Error::InvalidPublic)
        }
    }
}

impl Default for EccCtx {
    fn default() -> Self {
        Self::new()
    }
}

impl Point {
    pub fn is_zero(&self) -> bool {
        self.z.eq(&FieldElem::zero())
    }
}

use sm2::error::Sm2Error;
use std::fmt;

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let curve = EccCtx::new();
        if self.is_zero() {
            write!(f, "(O)")
        } else {
            let (x, y) = curve.to_affine(self);
            write!(
                f,
                "(x = 0x{:0>64}, y = 0x{:0>64})",
                x.to_str(16),
                y.to_str(16)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_double_neg() {
        let curve = EccCtx::new();
        let g = curve.generator();

        let neg_g = curve.neg(&g);
        let double_g = curve.double(&g);
        let new_g = curve.add(&double_g, &neg_g);
        let zero = curve.add(&g, &neg_g);

        assert!(curve.eq(&g, &new_g));
        assert!(zero.is_zero());

        let double_g = curve.double(&g); //  2 * g
        let add_g = curve.add(&g, &g); // g + g
        assert!(curve.eq(&add_g, &double_g));
    }

    #[test]
    fn test_point_add() {
        let ecctx = EccCtx::new();
        let g = ecctx.generator();
        let g2 = ecctx.double(&g);

        println!("{}", ecctx.add(&g, &g2));
    }

    #[test]
    fn test_point_double() {
        let ecctx = EccCtx::new();
        let g = ecctx.generator();

        println!("{}", ecctx.double(&g));
    }

    #[test]
    fn test_multiplication() {
        let curve = EccCtx::new();
        let g = curve.generator();

        let double_g = curve.double(&g);
        let twice_g = curve.mul(&BigUint::from_u32(2).unwrap(), &g);

        assert!(curve.eq(&double_g, &twice_g));

        let n = curve.get_n() - BigUint::one();
        let new_g = curve.mul(&n, &g);
        let new_g = curve.add(&new_g, &double_g);
        assert!(curve.eq(&g, &new_g));
    }

    #[test]
    fn test_g_multiplication() {
        let curve = EccCtx::new();
        let g = curve.generator();

        let twice_g = curve.g_mul(&BigUint::from_u64(4_294_967_296).unwrap());
        let double_g = curve.mul(&BigUint::from_u64(4_294_967_296).unwrap(), &g);

        assert!(curve.eq(&double_g, &twice_g));

        let n = curve.get_n() - BigUint::one();
        let new_g = curve.g_mul(&n);
        let nn_g = curve.mul(&n, &g);
        assert!(curve.eq(&nn_g, &new_g));
    }

    #[test]
    fn test_w_naf() {
        let curve = EccCtx::new();
        let mut lst = 0;

        let n = curve.get_n() - BigUint::one();
        let _num = BigUint::from(1122334455 as u32) - BigUint::one();

        let k = FieldElem::from_biguint(&n);
        let ret = curve.w_naf(&k.value,5, &mut lst);
        let mut sum = BigUint::zero();
        let mut init = BigUint::from_str_radix(
            "10000000000000000000000000000000000000000000000000000000000000000",
            16,
        ).unwrap();

        for j in 0..257{
            let i = 256 - j;
            if ret[i] != 0{
                if ret[i] > 0{
                    sum += &init * BigUint::from(ret[i] as u8);
                }
                else{
                    let neg = (0 - ret[i]) as u8;
                    sum -= &init * BigUint::from(neg as u8);
                }
            }
            init = init >> 1;
        }
        assert_eq!(sum, n);
    }

    #[test]
    fn test_inv_n() {
        let curve = EccCtx::new();

        for _ in 0..20 {
            let r = curve.random_uint();
            let r_inv = curve.inv_n(&r);

            let product = r * r_inv;
            let product = product % curve.get_n();

            assert_eq!(product, BigUint::one());
        }
    }

    #[test]
    fn test_point_bytes_conversion() {
        let curve = EccCtx::new();

        let g = curve.generator();
        let g_bytes_uncomp = curve.point_to_bytes(&g, false);
        let new_g = curve.bytes_to_point(&g_bytes_uncomp[..]).unwrap();
        assert!(curve.eq(&g, &new_g));
        let g_bytes_comp = curve.point_to_bytes(&g, true);
        let new_g = curve.bytes_to_point(&g_bytes_comp[..]).unwrap();
        assert!(curve.eq(&g, &new_g));

        let g = curve.double(&g);
        let g_bytes_uncomp = curve.point_to_bytes(&g, false);
        let new_g = curve.bytes_to_point(&g_bytes_uncomp[..]).unwrap();
        assert!(curve.eq(&g, &new_g));
        let g_bytes_comp = curve.point_to_bytes(&g, true);
        let new_g = curve.bytes_to_point(&g_bytes_comp[..]).unwrap();
        assert!(curve.eq(&g, &new_g));

        let g = curve.double(&g);
        let g_bytes_uncomp = curve.point_to_bytes(&g, false);
        let new_g = curve.bytes_to_point(&g_bytes_uncomp[..]).unwrap();
        assert!(curve.eq(&g, &new_g));
        let g_bytes_comp = curve.point_to_bytes(&g, true);
        let new_g = curve.bytes_to_point(&g_bytes_comp[..]).unwrap();
        assert!(curve.eq(&g, &new_g));
    }
}

#[cfg(feature = "internal_benches")]
mod internal_benches {
    use sm2::ecc::EccCtx;
    use sm2::field::FieldElem;
    extern crate test;

    #[bench]
    fn sm2_inv_bench(bench: &mut test::Bencher) {
        let ecctx = EccCtx::new();
        let fe = FieldElem::from_num(2);
        bench.iter(|| {
            let _ = ecctx.fctx.inv(&fe);
        });
    }

    #[bench]
    fn sm2_point_add_bench(bench: &mut test::Bencher) {
        let ecctx = EccCtx::new();
        let g = ecctx.generator();
        let g2 = ecctx.double(&g);

        bench.iter(|| {
            ecctx.add(&g, &g2);
        });
    }

    #[bench]
    fn sm2_point_double_bench(bench: &mut test::Bencher) {
        let ecctx = EccCtx::new();
        let g = ecctx.generator();
        let g2 = ecctx.double(&g);

        bench.iter(|| {
            ecctx.double(&g2);
        });
    }
}
