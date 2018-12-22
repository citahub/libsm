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
    inv2: FieldElem,
}

#[derive(Clone)]
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
        let fctx = FieldCtx::new();
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
            inv2: fctx.inv(&FieldElem::from_num(2)),
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

        let two = BigUint::from_u32(2).unwrap();

        while ru != BigUint::zero() {
            if ru.is_even() {
                ru /= &two;
                if ra.is_even() {
                    ra /= &two;
                } else {
                    ra = (ra + &rn) / &two;
                }
            }

            if rv.is_even() {
                rv /= &two;
                if rc.is_even() {
                    rc /= &two;
                } else {
                    rc = (rc + &rn) / &two;
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

    pub fn new_point(&self, x: &FieldElem, y: &FieldElem) -> Result<Point, String> {
        let ctx = &self.fctx;

        // Check if (x, y) is a valid point on the curve(affine projection)
        // y^2 = x^3 + a * x + b
        let lhs = ctx.mul(&y, &y);

        let x_cubic = ctx.mul(&x, &ctx.mul(&x, &x));
        let ax = ctx.mul(&x, &self.a);
        let rhs = ctx.add(&self.b, &ctx.add(&x_cubic, &ax));

        if !lhs.eq(&rhs) {
            return Err(String::from("invalid point"));
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
            Err(m) => panic!(m),
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
            Err(e) => panic!(e),
        }
    }

    pub fn add(&self, p1: &Point, p2: &Point) -> Point {
        if p1.is_zero() {
            return p2.clone();
        } else if p2.is_zero() {
            return p1.clone();
        }

        let ctx = &self.fctx;

        //if self.eq(&p1, &p2) {
        //    return self.double(p1);
        //}

        let lam1 = ctx.mul(&p1.x, &ctx.square(&p2.z));
        let lam2 = ctx.mul(&p2.x, &ctx.square(&p1.z));
        let lam3 = ctx.sub(&lam1, &lam2);

        let lam4 = ctx.mul(&p1.y, &ctx.cubic(&p2.z));
        let lam5 = ctx.mul(&p2.y, &ctx.cubic(&p1.z));
        let lam6 = ctx.sub(&lam4, &lam5);

        let lam7 = ctx.add(&lam1, &lam2);
        let lam8 = ctx.add(&lam4, &lam5);

        let x3 = ctx.sub(&ctx.square(&lam6), &ctx.mul(&lam7, &ctx.square(&lam3)));

        let lam9 = ctx.sub(
            &ctx.mul(&lam7, &ctx.square(&lam3)),
            &ctx.mul(&FieldElem::from_num(2), &x3),
        );

        let y3 = ctx.mul(
            &self.inv2,
            &ctx.sub(&ctx.mul(&lam9, &lam6), &ctx.mul(&lam8, &ctx.cubic(&lam3))),
        );

        let z3 = ctx.mul(&p1.z, &ctx.mul(&p2.z, &lam3));

        Point {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    pub fn double(&self, p: &Point) -> Point {
        let ctx = &self.fctx;
        // λ1 = 3 * x1^2 + a * z1^4
        let lam1 = ctx.add(
            &ctx.mul(&FieldElem::from_num(3), &ctx.square(&p.x)),
            &ctx.mul(&self.a, &ctx.square(&ctx.square(&p.z))),
        );
        // λ2 = 4 * x1 * y1^2
        let lam2 = &ctx.mul(&FieldElem::from_num(4), &ctx.mul(&p.x, &ctx.square(&p.y)));
        // λ3 = 8 * y1^4
        let lam3 = &ctx.mul(&FieldElem::from_num(8), &ctx.square(&ctx.square(&p.y)));

        // x3 = λ1^2 - 2 * λ2
        let x3 = ctx.sub(&ctx.square(&lam1), &ctx.mul(&FieldElem::from_num(2), &lam2));
        // y3 = λ1 * (λ2 - x3) - λ3
        let y3 = ctx.sub(&ctx.mul(&lam1, &ctx.sub(&lam2, &x3)), &lam3);
        // z3 = 2 * y1 * z1
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

        self.mul_raw(&k.value, p)
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

    pub fn bytes_to_point(&self, b: &[u8]) -> Result<Point, ()> {
        let ctx = &self.fctx;

        if b.len() == 33 {
            let y_q;
            if b[0] == 0x02 {
                y_q = 0;
            } else if b[0] == 0x03 {
                y_q = 1
            } else {
                return Err(());
            }

            let x = FieldElem::from_bytes(&b[1..]);

            let x_cubic = ctx.mul(&x, &ctx.mul(&x, &x));
            let ax = ctx.mul(&x, &self.a);
            let y_2 = ctx.add(&self.b, &ctx.add(&x_cubic, &ax));

            let mut y = self.fctx.sqrt(&y_2)?;
            if y.get_value(7) & 0x01 != y_q {
                y = self.fctx.neg(&y);
            }

            match self.new_point(&x, &y) {
                Ok(p) => Ok(p),
                Err(_) => Err(()),
            }
        } else if b.len() == 65 {
            if b[0] != 0x04 {
                return Err(());
            }
            let x = FieldElem::from_bytes(&b[1..33]);
            let y = FieldElem::from_bytes(&b[33..65]);
            match self.new_point(&x, &y) {
                Ok(p) => Ok(p),
                Err(_) => Err(()),
            }
        } else {
            Err(())
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

use std::fmt;

impl fmt::Display for Point {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let curve = EccCtx::new();
        if self.is_zero() {
            write!(f, "(O)")
        } else {
            let (x, y) = curve.to_affine(self);
            write!(f, "(x = {}, y = {})", x.to_str(10), y.to_str(10))
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
