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

// Implementation of the prime field(SCA-256) used by SM2

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::Num;
use std::io::Cursor;

pub struct FieldCtx {
    modulus: FieldElem,
    modulus_complete: FieldElem,
}

impl FieldCtx {
    pub fn new() -> FieldCtx {
        // p = FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
        //   = 2^256 - 2^224 - 2^96 + 2^64 -1
        let modulus = FieldElem::new([
            0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0x00000000, 0xffffffff,
            0xffffffff,
        ]);

        let (modulus_complete, _borrow) = raw_sub(&FieldElem::zero(), &modulus);
        FieldCtx {
            modulus,
            modulus_complete,
        }
    }

    pub fn add(&self, a: &FieldElem, b: &FieldElem) -> FieldElem {
        let (raw_sum, carry) = raw_add(a, b);
        if carry == 1 || raw_sum >= self.modulus {
            let (sum, _borrow) = raw_sub(&raw_sum, &self.modulus);
            sum
        } else {
            raw_sum
        }
    }

    pub fn sub(&self, a: &FieldElem, b: &FieldElem) -> FieldElem {
        let (raw_diff, borrow) = raw_sub(a, b);
        if borrow == 1 {
            let (diff, _borrow) = raw_sub(&raw_diff, &self.modulus_complete);
            diff
        } else {
            raw_diff
        }
    }

    // a quick algorithm to reduce elements on SCA-256 field
    // Reference:
    // http://ieeexplore.ieee.org/document/7285166/ for details
    #[inline]
    fn fast_reduction(&self, input: &[u32; 16]) -> FieldElem {
        let mut s: [FieldElem; 10] = [FieldElem::zero(); 10];
        let mut x: [u32; 16] = [0; 16];

        let mut i = 0;
        while i < 16 {
            x[i] = input[15 - i];

            i += 1;
        }

        s[0] = FieldElem::new([x[7], x[6], x[5], x[4], x[3], x[2], x[1], x[0]]);
        s[1] = FieldElem::new([x[15], 0, 0, 0, 0, 0, x[15], x[14]]);
        s[2] = FieldElem::new([x[14], 0, 0, 0, 0, 0, x[14], x[13]]);
        s[3] = FieldElem::new([x[13], 0, 0, 0, 0, 0, 0, 0]);
        s[4] = FieldElem::new([x[12], 0, x[15], x[14], x[13], 0, 0, x[15]]);
        s[5] = FieldElem::new([x[15], x[15], x[14], x[13], x[12], 0, x[11], x[10]]);
        s[6] = FieldElem::new([x[11], x[14], x[13], x[12], x[11], 0, x[10], x[9]]);
        s[7] = FieldElem::new([x[10], x[11], x[10], x[9], x[8], 0, x[13], x[12]]);
        s[8] = FieldElem::new([x[9], 0, 0, x[15], x[14], 0, x[9], x[8]]);
        s[9] = FieldElem::new([x[8], 0, 0, 0, x[15], 0, x[12], x[11]]);

        let mut carry: i32 = 0;
        let mut sum = FieldElem::zero();

        let (t, c) = raw_add(&sum, &s[1]);
        sum = t;
        carry += c as i32;
        let (t, c) = raw_add(&sum, &s[2]);
        sum = t;
        carry += c as i32;
        let (t, c) = raw_add(&sum, &s[3]);
        sum = t;
        carry += c as i32;
        let (t, c) = raw_add(&sum, &s[4]);
        sum = t;
        carry += c as i32;

        let (t, c) = raw_add(&sum, &sum);
        sum = t;
        carry = carry * 2 + c as i32;

        let (t, c) = raw_add(&sum, &s[5]);
        sum = t;
        carry += c as i32;
        let (t, c) = raw_add(&sum, &s[6]);
        sum = t;
        carry += c as i32;
        let (t, c) = raw_add(&sum, &s[7]);
        sum = t;
        carry += c as i32;
        let (t, c) = raw_add(&sum, &s[8]);
        sum = t;
        carry += c as i32;
        let (t, c) = raw_add(&sum, &s[9]);
        sum = t;
        carry += c as i32;

        let mut part3 = FieldElem::zero();
        let t: u64 = u64::from(x[8]) + u64::from(x[9]) + u64::from(x[13]) + u64::from(x[14]);
        part3.value[5] = (t & 0xffffffff) as u32;
        part3.value[4] = (t >> 32) as u32;

        let (t, c) = raw_add(&sum, &s[0]);
        sum = t;
        carry += c as i32;

        let (t, c) = raw_sub(&sum, &part3);
        sum = t;
        carry -= c as i32;

        while carry > 0 || sum >= self.modulus {
            let (s, b) = raw_sub(&sum, &self.modulus);
            sum = s;
            carry -= b as i32;
        }
        sum
    }

    pub fn mul(&self, a: &FieldElem, b: &FieldElem) -> FieldElem {
        let raw_prod = raw_mul(a, b);
        self.fast_reduction(&raw_prod)
    }

    #[inline(always)]
    pub fn square(&self, a: &FieldElem) -> FieldElem {
        self.mul(a, a)
    }

    #[inline(always)]
    pub fn cubic(&self, a: &FieldElem) -> FieldElem {
        self.mul(a, &self.mul(a, a))
    }

    // Extended Eulidean Algorithm(EEA) to calculate x^(-1) mod p
    // Reference:
    // http://delta.cs.cinvestav.mx/~francisco/arith/julio.pdf
    pub fn inv(&self, x: &FieldElem) -> FieldElem {
        if x.is_zero() {
            panic!("zero has no inversion in filed");
        }

        let mut u = *x;
        let mut v = self.modulus;
        let mut a = FieldElem::from_num(1);
        let mut c = FieldElem::zero();

        while !u.is_zero() {
            if u.is_even() {
                u = u.div2(0);
                if a.is_even() {
                    a = a.div2(0);
                } else {
                    let (sum, car) = raw_add(&a, &self.modulus);
                    a = sum.div2(car);
                }
            }

            if v.is_even() {
                v = v.div2(0);
                if c.is_even() {
                    c = c.div2(0);
                } else {
                    let (sum, car) = raw_add(&c, &self.modulus);
                    c = sum.div2(car);
                }
            }

            if u >= v {
                u = self.sub(&u, &v);
                a = self.sub(&a, &c);
            } else {
                v = self.sub(&v, &u);
                c = self.sub(&c, &a);
            }
        }
        c
    }

    pub fn neg(&self, x: &FieldElem) -> FieldElem {
        self.sub(&self.modulus, x)
    }

    fn exp(&self, x: &FieldElem, n: &BigUint) -> FieldElem {
        let u = FieldElem::from_biguint(n);

        let mut q0 = FieldElem::from_num(1);
        let mut q1 = *x;

        let mut i = 0;
        while i < 256 {
            let index = i as usize / 32;
            let bit = 31 - i as usize % 32;

            let sum = self.mul(&q0, &q1);
            if (u.get_value(index) >> bit) & 0x01 == 0 {
                q1 = sum;
                q0 = self.square(&q0);
            } else {
                q0 = sum;
                q1 = self.square(&q1);
            }

            i += 1;
        }
        q0
    }

    // Square root of a field element
    pub fn sqrt(&self, g: &FieldElem) -> Result<FieldElem, ()> {
        // p = 4 * u + 3
        // u = u + 1
        let u = BigUint::from_str_radix(
            "28948022302589062189105086303505223191562588497981047863605298483322421248000",
            10,
        )
        .unwrap();

        let y = self.exp(g, &u);
        if self.square(&y) == *g {
            Ok(y)
        } else {
            Err(())
        }
    }
}

#[derive(Copy, Clone)]
pub struct FieldElem {
    pub value: [u32; 8],
}

fn raw_add(a: &FieldElem, b: &FieldElem) -> (FieldElem, u32) {
    let mut sum = FieldElem::zero();
    let mut carry: u32 = 0;

    let t_sum: u64 = u64::from(a.value[7]) + u64::from(b.value[7]) + u64::from(carry);
    sum.value[7] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a.value[6]) + u64::from(b.value[6]) + u64::from(carry);
    sum.value[6] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a.value[5]) + u64::from(b.value[5]) + u64::from(carry);
    sum.value[5] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a.value[4]) + u64::from(b.value[4]) + u64::from(carry);
    sum.value[4] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a.value[3]) + u64::from(b.value[3]) + u64::from(carry);
    sum.value[3] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a.value[2]) + u64::from(b.value[2]) + u64::from(carry);
    sum.value[2] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a.value[1]) + u64::from(b.value[1]) + u64::from(carry);
    sum.value[1] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    let t_sum: u64 = u64::from(a.value[0]) + u64::from(b.value[0]) + u64::from(carry);
    sum.value[0] = (t_sum & 0xffffffff) as u32;
    carry = (t_sum >> 32) as u32;

    (sum, carry)
}

fn raw_sub(a: &FieldElem, b: &FieldElem) -> (FieldElem, u32) {
    let mut sum = FieldElem::new([0; 8]);
    let mut borrow: u32 = 0;
    let mut j = 0;
    while j < 8 {
        let i = 7 - j;
        let t_sum: i64 = i64::from(a.value[i]) - i64::from(b.value[i]) - i64::from(borrow);
        if t_sum < 0 {
            sum.value[i] = (t_sum + (1 << 32)) as u32;
            borrow = 1;
        } else {
            sum.value[i] = t_sum as u32;
            borrow = 0;
        }
        j += 1;
    }
    (sum, borrow)
}

#[inline(always)]
fn u32_mul(a: u32, b: u32) -> (u64, u64) {
    let uv = u64::from(a) * u64::from(b);
    let u = uv >> 32;
    let v = uv & 0xffffffff;
    (u, v)
}

fn raw_mul(a: &FieldElem, b: &FieldElem) -> [u32; 16] {
    let mut local: u64 = 0;
    let mut carry: u64 = 0;
    let mut ret: [u32; 16] = [0; 16];

    let mut k = 0;
    while k < 15 {
        let index = 15 - k;
        let mut i = 0;
        while i < 8 {
            if i > k {
                break;
            }
            let j = k - i;
            if j < 8 {
                let (u, v) = u32_mul(a.value[7 - i], b.value[7 - j]);
                local += v;
                carry += u;
            }

            i += 1;
        }
        carry += local >> 32;
        local &= 0xffffffff;
        ret[index] = local as u32;
        local = carry;
        carry = 0;

        k += 1;
    }
    ret[0] = local as u32;
    ret
}

impl ::std::cmp::PartialEq for FieldElem {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        let lhs = self.value;
        let rhs = other.value;
        if lhs[0] != rhs[0] {
            return false;
        }
        if lhs[1] != rhs[1] {
            return false;
        }
        if lhs[2] != rhs[2] {
            return false;
        }
        if lhs[3] != rhs[3] {
            return false;
        }
        if lhs[4] != rhs[4] {
            return false;
        }
        if lhs[5] != rhs[5] {
            return false;
        }
        if lhs[6] != rhs[6] {
            return false;
        }
        if lhs[7] != rhs[7] {
            return false;
        }
        true
    }
}

impl ::std::cmp::Eq for FieldElem {}

impl ::std::cmp::PartialOrd for FieldElem {
    #[inline]
    fn partial_cmp(&self, other: &Self) -> Option<::std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl ::std::cmp::Ord for FieldElem {
    #[inline]
    fn cmp(&self, other: &Self) -> ::std::cmp::Ordering {
        let lhs = self.value;
        let rhs = other.value;
        if lhs[0] != rhs[0] {
            return if lhs[0] > rhs[0] {
                ::std::cmp::Ordering::Greater
            } else {
                ::std::cmp::Ordering::Less
            };
        }
        if lhs[1] != rhs[1] {
            return if lhs[1] > rhs[1] {
                ::std::cmp::Ordering::Greater
            } else {
                ::std::cmp::Ordering::Less
            };
        }
        if lhs[2] != rhs[2] {
            return if lhs[2] > rhs[2] {
                ::std::cmp::Ordering::Greater
            } else {
                ::std::cmp::Ordering::Less
            };
        }
        if lhs[3] != rhs[3] {
            return if lhs[3] > rhs[3] {
                ::std::cmp::Ordering::Greater
            } else {
                ::std::cmp::Ordering::Less
            };
        }
        if lhs[4] != rhs[4] {
            return if lhs[4] > rhs[4] {
                ::std::cmp::Ordering::Greater
            } else {
                ::std::cmp::Ordering::Less
            };
        }
        if lhs[5] != rhs[5] {
            return if lhs[5] > rhs[5] {
                ::std::cmp::Ordering::Greater
            } else {
                ::std::cmp::Ordering::Less
            };
        }
        if lhs[6] != rhs[6] {
            return if lhs[6] > rhs[6] {
                ::std::cmp::Ordering::Greater
            } else {
                ::std::cmp::Ordering::Less
            };
        }
        if lhs[7] != rhs[7] {
            return if lhs[7] > rhs[7] {
                ::std::cmp::Ordering::Greater
            } else {
                ::std::cmp::Ordering::Less
            };
        }
        ::std::cmp::Ordering::Equal
    }
}

impl FieldElem {
    pub fn new(x: [u32; 8]) -> FieldElem {
        FieldElem { value: x }
    }

    pub fn from_slice(x: &[u32]) -> FieldElem {
        let mut arr: [u32; 8] = [0; 8];
        arr[0] = x[0];
        arr[1] = x[1];
        arr[2] = x[2];
        arr[3] = x[3];
        arr[4] = x[4];
        arr[5] = x[5];
        arr[6] = x[6];
        arr[7] = x[7];
        FieldElem::new(arr)
    }

    pub fn zero() -> FieldElem {
        FieldElem::new([0; 8])
    }

    #[inline]
    pub fn is_zero(&self) -> bool {
        self.value == [0; 8]
    }

    pub fn div2(&self, carry: u32) -> FieldElem {
        let mut ret = FieldElem::zero();
        let mut carry = carry;

        let mut i = 0;
        while i < 8 {
            ret.value[i] = (carry << 31) + (self.value[i] >> 1);
            carry = self.value[i] & 0x01;

            i += 1;
        }
        ret
    }

    pub fn is_even(&self) -> bool {
        self.value[7] & 0x01 == 0
    }

    // Conversions
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ret: Vec<u8> = Vec::new();
        for i in 0..8 {
            ret.write_u32::<BigEndian>(self.value[i]).unwrap();
        }
        ret
    }
    pub fn from_bytes(x: &[u8]) -> FieldElem {
        if x.len() != 32 {
            panic!("a SCA-256 field element must be 32-byte long");
        }
        let mut elem = FieldElem::zero();
        let mut c = Cursor::new(x);
        for i in 0..8 {
            let x = c.read_u32::<BigEndian>().unwrap();
            elem.value[i] = x;
        }
        elem
    }

    pub fn to_biguint(&self) -> BigUint {
        let v = self.to_bytes();
        BigUint::from_bytes_be(&v[..])
    }

    pub fn from_biguint(bi: &BigUint) -> FieldElem {
        let v = bi.to_bytes_be();
        let mut num_v: Vec<u8> = Vec::new();
        let padding = 32 - v.len();
        for _i in 0..padding {
            num_v.push(0);
        }
        for i in v.iter() {
            num_v.push(*i);
        }
        FieldElem::from_bytes(&num_v[..])
    }

    pub fn from_num(x: u64) -> FieldElem {
        let mut arr: [u32; 8] = [0; 8];
        arr[7] = (x & 0xffffffff) as u32;
        arr[6] = (x >> 32) as u32;

        FieldElem::new(arr)
    }

    pub fn to_str(&self, radix: u32) -> String {
        let b = self.to_biguint();
        b.to_str_radix(radix)
    }

    pub fn get_value(&self, i: usize) -> u32 {
        self.value[i]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rand::os::OsRng;
    use rand::Rng;

    #[test]
    fn test_add() {
        let ctx = FieldCtx::new();

        let a = FieldElem::from_num(1);
        let b = FieldElem::from_num(0xffffffff);
        let c = ctx.add(&a, &b);
        let c1 = FieldElem::from_num(0x100000000);
        assert!(c == c1);

        let b1 = ctx.add(&ctx.modulus, &b);
        assert!(b1 == b);
    }

    #[test]
    fn test_sub() {
        let ctx = FieldCtx::new();

        let a = FieldElem::from_num(0xffffffff);
        let a1 = ctx.sub(&a, &ctx.modulus);
        assert!(a == a1);
    }

    fn rand_elem() -> FieldElem {
        let mut rng = OsRng::new().unwrap();
        let mut buf: [u32; 8] = [0; 8];
        for v in buf.iter_mut().take(8) {
            *v = rng.next_u32();
        }

        let ret = FieldElem::new(buf);
        let ctx = FieldCtx::new();
        if ret >= ctx.modulus {
            let (ret, _borrow) = raw_sub(&ret, &ctx.modulus);
            return ret;
        }
        ret
    }

    #[test]
    fn add_sub_rand_test() {
        let ctx = FieldCtx::new();

        for _i in 0..20 {
            let a = rand_elem();
            let b = rand_elem();
            let c = ctx.add(&a, &b);
            let a1 = ctx.sub(&c, &b);
            assert!(a1 == a);
        }
    }

    // test multiplilcations
    #[test]
    fn test_mul() {
        let ctx = FieldCtx::new();
        let x = raw_mul(&ctx.modulus, &ctx.modulus);
        let y = ctx.fast_reduction(&x);
        assert!(y.is_zero());
    }

    #[test]
    fn test_div2() {
        let x = FieldElem::new([
            0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff,
        ]);
        let y = FieldElem::new([
            0x7fffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
            0xffffffff,
        ]);
        assert!(y == x.div2(0));
        assert!(x == x.div2(1));
        assert!(!x.is_even());
        assert!(FieldElem::from_num(10).is_even());
    }

    #[test]
    fn test_inv() {
        let ctx = FieldCtx::new();
        let one = FieldElem::from_num(1);

        for _x in 1..100 {
            let x = rand_elem();
            let xinv = ctx.inv(&x);

            let y = ctx.mul(&x, &xinv);
            assert!(y == one);
        }
    }

    #[test]
    fn test_byte_conversion() {
        for _x in 1..100 {
            let x = rand_elem();
            let y = x.to_bytes();
            let newx = FieldElem::from_bytes(&y[..]);

            assert!(x == newx);
        }
    }

    #[test]
    fn test_bigint_conversion() {
        for _x in 1..100 {
            let x = rand_elem();
            let y = x.to_biguint();
            let newx = FieldElem::from_biguint(&y);

            assert!(x == newx);
        }
    }

    #[test]
    fn test_neg() {
        let ctx = FieldCtx::new();
        for _ in 0..100 {
            let x = rand_elem();
            let neg_x = ctx.neg(&x);
            let zero = ctx.add(&x, &neg_x);
            assert!(zero.is_zero());
        }
    }

    #[test]
    fn test_sqrt() {
        let ctx = FieldCtx::new();

        for _ in 0..10 {
            let x = rand_elem();
            let x_2 = ctx.square(&x);
            let new_x = ctx.sqrt(&x_2).unwrap();

            assert!(x == new_x || ctx.add(&x, &new_x).is_zero());
        }
    }
}
