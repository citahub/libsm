use super::ecc::*;
use super::util::kdf;
use crate::sm2::error::{Sm2Error, Sm2Result};
use crate::sm3::hash::Sm3Hash;

use byteorder::{BigEndian, WriteBytesExt};
use num_bigint::BigUint;
use num_traits::*;

fn compute_z(id: &str, pk: &Point) -> Sm2Result<[u8; 32]> {
    let curve = EccCtx::new();

    let mut prepend: Vec<u8> = Vec::new();
    if id.len() * 8 > 65535 {
        return Err(Sm2Error::IdTooLong);
    }
    // ENTL_A
    prepend
        .write_u16::<BigEndian>((id.len() * 8) as u16)
        .unwrap();
    // ID_A
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
    Ok(hasher.get_hash())
}

pub struct ExchangeCtxA {
    klen: usize,
    curve: EccCtx,
    z_a: [u8; 32],
    z_b: [u8; 32],
    pk_b: Point,

    sk_a: BigUint,

    r_a: Option<BigUint>,
    r_a_point: Option<Point>,
    k_a: Option<Vec<u8>>,
}

pub struct ExchangeCtxB {
    klen: usize,
    curve: EccCtx,
    z_a: [u8; 32],
    z_b: [u8; 32],
    pk_a: Point,

    sk_b: BigUint,

    v: Option<Point>,
    r_b: Option<BigUint>,
    r_b_point: Option<Point>,
    k_b: Option<Vec<u8>>,
}

impl ExchangeCtxA {
    pub fn new(
        klen: usize,
        id_a: &str,
        id_b: &str,
        pk_a: Point,
        pk_b: Point,
        sk_a: BigUint,
    ) -> Sm2Result<ExchangeCtxA> {
        Ok(ExchangeCtxA {
            klen,
            curve: EccCtx::new(),
            z_a: compute_z(id_a, &pk_a)?,
            z_b: compute_z(id_b, &pk_b)?,
            pk_b,
            sk_a,
            r_a: None,
            r_a_point: None,
            k_a: None,
        })
    }

    pub fn exchange1(&mut self) -> Sm2Result<Point> {
        let r_a = self.curve.random_uint();
        let r_a_point = self.curve.g_mul(&r_a)?;
        self.r_a = Some(r_a);
        self.r_a_point = Some(r_a_point);
        Ok(r_a_point)
    }

    pub fn exchange3(&mut self, r_b_point: &Point, s_b: [u8; 32]) -> Sm2Result<[u8; 32]> {
        let (x_1, y_1) = self.curve.to_affine(&self.r_a_point.unwrap())?;
        let w = ((self.curve.get_n().bits() as f64) / 2.0).ceil() - 1.0;
        let pow_w = BigUint::from_u32(2).unwrap().pow(w as u32);
        let x_1_bar = &pow_w + (x_1.to_biguint() & (&pow_w - BigUint::one()));
        let t_a = (&self.sk_a + x_1_bar * self.r_a.as_ref().unwrap()) % self.curve.get_n();

        if !self.curve.check_point(r_b_point)? {
            return Err(Sm2Error::CheckPointErr);
        }

        let (x_2, y_2) = self.curve.to_affine(r_b_point)?;
        let x_2_bar = &pow_w + (x_2.to_biguint() & (&pow_w - BigUint::one()));

        let h = BigUint::one();

        let coefficient = h * t_a;
        let point = self
            .curve
            .add(&self.pk_b, &self.curve.mul(&x_2_bar, r_b_point)?)?;

        let u = self.curve.mul(&coefficient, &point)?;
        if u.is_zero() {
            return Err(Sm2Error::ZeroPoint);
        }

        let (x_u, y_u) = self.curve.to_affine(&u)?;

        let mut prepend = Vec::new();
        let x_u_bytes = x_u.to_bytes();
        let y_u_bytes = y_u.to_bytes();
        prepend.extend_from_slice(&x_u_bytes);
        prepend.extend_from_slice(&y_u_bytes);

        prepend.extend_from_slice(&self.z_a);
        prepend.extend_from_slice(&self.z_b);

        let k_a = kdf(&prepend, self.klen);
        self.k_a = Some(k_a);

        let mut prepend: Vec<u8> = Vec::new();
        prepend.write_u16::<BigEndian>(0x02_u16).unwrap();
        prepend.extend_from_slice(&y_u_bytes);

        let mut temp: Vec<u8> = Vec::new();
        temp.extend_from_slice(&x_u_bytes);
        temp.extend_from_slice(&self.z_a);
        temp.extend_from_slice(&self.z_b);
        temp.extend_from_slice(&x_1.to_bytes());
        temp.extend_from_slice(&y_1.to_bytes());
        temp.extend_from_slice(&x_2.to_bytes());
        temp.extend_from_slice(&y_2.to_bytes());
        let temp_hash = Sm3Hash::new(&temp).get_hash();

        prepend.extend_from_slice(&temp_hash);
        let s_1 = Sm3Hash::new(&prepend).get_hash();
        if s_1 != s_b {
            return Err(Sm2Error::HashNotEqual);
        }

        let mut prepend: Vec<u8> = Vec::new();
        prepend.write_u16::<BigEndian>(0x03_u16).unwrap();
        prepend.extend_from_slice(&y_u_bytes);
        prepend.extend_from_slice(&temp_hash);

        Ok(Sm3Hash::new(&prepend).get_hash())
    }
}

impl ExchangeCtxB {
    pub fn new(
        klen: usize,
        id_a: &str,
        id_b: &str,
        pk_a: Point,
        pk_b: Point,
        sk_b: BigUint,
    ) -> Sm2Result<ExchangeCtxB> {
        Ok(ExchangeCtxB {
            klen,
            curve: EccCtx::new(),
            z_a: compute_z(id_a, &pk_a)?,
            z_b: compute_z(id_b, &pk_b)?,
            pk_a,
            sk_b,
            v: None,
            r_b: None,
            r_b_point: None,
            k_b: None,
        })
    }

    pub fn exchange2(&mut self, r_a_point: &Point) -> Sm2Result<(Point, [u8; 32])> {
        let r_b = self.curve.random_uint();
        self.r_b = Some(r_b);

        let r_b_point = self.curve.g_mul(self.r_b.as_ref().unwrap())?;
        self.r_b_point = Some(r_b_point);

        let (x_2, y_2) = self.curve.to_affine(&r_b_point)?;

        let w = ((self.curve.get_n().bits() as f64) / 2.0).ceil() - 1.0;
        let pow_w = BigUint::from_u32(2).unwrap().pow(w as u32);

        let x_2_bar = &pow_w + (x_2.to_biguint() & (&pow_w - BigUint::one()));

        let t_b = (&self.sk_b + x_2_bar * self.r_b.as_ref().unwrap()) % self.curve.get_n();

        if !self.curve.check_point(r_a_point)? {
            return Err(Sm2Error::CheckPointErr);
        }

        let (x_1, y_1) = self.curve.to_affine(r_a_point)?;
        let x_1_bar = &pow_w + (x_1.to_biguint() & (&pow_w - BigUint::one()));

        let h = BigUint::one();

        let coefficient = h * t_b;
        let point = self
            .curve
            .add(&self.pk_a, &self.curve.mul(&x_1_bar, r_a_point)?)?;

        let v = self.curve.mul(&coefficient, &point)?;
        if v.is_zero() {
            return Err(Sm2Error::ZeroPoint);
        }
        self.v = Some(v);

        let (x_v, y_v) = self.curve.to_affine(&v)?;

        let mut prepend = Vec::new();
        let x_v_bytes = x_v.to_bytes();
        let y_v_bytes = y_v.to_bytes();

        prepend.extend_from_slice(&x_v_bytes);
        prepend.extend_from_slice(&y_v_bytes);

        prepend.extend_from_slice(&self.z_a);
        prepend.extend_from_slice(&self.z_b);

        let k_b = kdf(&prepend, self.klen);
        self.k_b = Some(k_b);

        let mut prepend: Vec<u8> = Vec::new();
        prepend.write_u16::<BigEndian>(0x02_u16).unwrap();
        prepend.extend_from_slice(&y_v_bytes);

        let mut temp: Vec<u8> = Vec::new();
        temp.extend_from_slice(&x_v_bytes);
        temp.extend_from_slice(&self.z_a);
        temp.extend_from_slice(&self.z_b);
        temp.extend_from_slice(&x_1.to_bytes());
        temp.extend_from_slice(&y_1.to_bytes());
        temp.extend_from_slice(&x_2.to_bytes());
        temp.extend_from_slice(&y_2.to_bytes());
        let temp_hash = Sm3Hash::new(&temp).get_hash();

        prepend.extend_from_slice(&temp_hash);
        let s_b = Sm3Hash::new(&prepend).get_hash();
        Ok((r_b_point, s_b))
    }

    pub fn exchange4(&self, s_a: [u8; 32], r_a_point: &Point) -> Sm2Result<bool> {
        let (x_1, y_1) = self.curve.to_affine(r_a_point)?;
        let (x_2, y_2) = self.curve.to_affine(self.r_b_point.as_ref().unwrap())?;

        let (x_v, y_v) = self.curve.to_affine(self.v.as_ref().unwrap())?;
        let x_v_bytes = x_v.to_bytes();
        let y_v_bytes = y_v.to_bytes();

        let mut prepend: Vec<u8> = Vec::new();
        prepend.write_u16::<BigEndian>(0x03_u16).unwrap();
        prepend.extend_from_slice(&y_v_bytes);

        let mut temp: Vec<u8> = Vec::new();
        temp.extend_from_slice(&x_v_bytes);
        temp.extend_from_slice(&self.z_a);
        temp.extend_from_slice(&self.z_b);
        temp.extend_from_slice(&x_1.to_bytes());
        temp.extend_from_slice(&y_1.to_bytes());
        temp.extend_from_slice(&x_2.to_bytes());
        temp.extend_from_slice(&y_2.to_bytes());
        let temp_hash = Sm3Hash::new(&temp).get_hash();

        prepend.extend_from_slice(&temp_hash);
        let s_2 = Sm3Hash::new(&prepend).get_hash();
        if s_2 != s_a {
            return Err(Sm2Error::HashNotEqual);
        }
        Ok(s_2 == s_a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sm2::signature::SigCtx;

    #[test]
    fn sm2_compute_z_test() {
        let ctx = SigCtx::new();
        let (pk_a, _sk_a) = ctx.new_keypair().unwrap();
        let (pk_b, _sk_b) = ctx.new_keypair().unwrap();

        let id_a = "AAAAAAAAAAAAA";
        let id_b = "BBBBBBBBBBBBB";

        let za = compute_z(id_a, &pk_a);
        let zb = compute_z(id_b, &pk_b);
        println!("{za:x?}");
        println!("{zb:x?}");
    }

    #[test]
    fn sm2_key_exchange_user_test() {
        let ctx = SigCtx::new();

        let (pk_a, sk_a) = ctx.new_keypair().unwrap();
        let (pk_b, sk_b) = ctx.new_keypair().unwrap();

        let id_a = "AAAAAAAAAAAAA";
        let id_b = "BBBBBBBBBBBBB";

        let mut ctx1 = ExchangeCtxA::new(8, id_a, id_b, pk_a, pk_b, sk_a).unwrap();
        let mut ctx2 = ExchangeCtxB::new(8, id_a, id_b, pk_a, pk_b, sk_b).unwrap();

        let r_a_point = ctx1.exchange1().unwrap();
        let (r_b_point, s_b) = ctx2.exchange2(&r_a_point).unwrap();
        let s_a = ctx1.exchange3(&r_b_point, s_b).unwrap();
        let succ = ctx2.exchange4(s_a, &r_a_point).unwrap();

        assert!(succ);
        assert_eq!(ctx1.k_a, ctx2.k_b);
    }
}
