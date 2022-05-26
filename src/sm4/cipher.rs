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

use crate::sm4::error::{Sm4Error, Sm4Result};

static SBOX: [u8; 256] = [
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48,
];

fn split(input: u32) -> [u8; 4] {
    let i4: u8 = input as u8;
    let i3: u8 = (input >> 8) as u8;
    let i2: u8 = (input >> 16) as u8;
    let i1: u8 = (input >> 24) as u8;

    [i1, i2, i3, i4]
}

fn combine(input: &[u8]) -> u32 {
    let out: u32 = u32::from(input[3]);
    let out = out | (u32::from(input[2]) << 8);
    let out = out | (u32::from(input[1]) << 16);
    out | (u32::from(input[0]) << 24)
}

fn split_block(input: &[u8]) -> Sm4Result<[u32; 4]> {
    if input.len() != 16 {
        return Err(Sm4Error::ErrorBlockSize);
    }
    let mut out: [u32; 4] = [0; 4];
    for (i, v) in out.iter_mut().enumerate().take(4) {
        let start = 4 * i;
        let end = 4 * i + 4;
        *v = combine(&input[start..end])
    }
    Ok(out)
}

fn combine_block(input: &[u32]) -> Sm4Result<[u8; 16]> {
    let mut out: [u8; 16] = [0; 16];
    for i in 0..4 {
        let outi = split(input[i]);
        for j in 0..4 {
            out[i * 4 + j] = outi[j];
        }
    }
    Ok(out)
}

fn tau_trans(input: u32) -> u32 {
    let input = split(input);
    let mut out: [u8; 4] = [0; 4];
    for i in 0..4 {
        out[i] = SBOX[input[i] as usize];
    }
    combine(&out)
}

fn l_rotate(x: u32, i: u32) -> u32 {
    (x << (i % 32)) | (x >> (32 - (i % 32)))
}

fn l_trans(input: u32) -> u32 {
    let b = input;
    b ^ l_rotate(b, 2) ^ l_rotate(b, 10) ^ l_rotate(b, 18) ^ l_rotate(b, 24)
}

fn t_trans(input: u32) -> u32 {
    l_trans(tau_trans(input))
}

fn l_prime_trans(input: u32) -> u32 {
    let b = input;
    b ^ l_rotate(b, 13) ^ l_rotate(b, 23)
}

fn t_prime_trans(input: u32) -> u32 {
    l_prime_trans(tau_trans(input))
}

pub struct Sm4Cipher {
    // round key
    rk: Vec<u32>,
}

static FK: [u32; 4] = [0xa3b1_bac6, 0x56aa_3350, 0x677d_9197, 0xb270_22dc];

static CK: [u32; 32] = [
    0x0007_0e15,
    0x1c23_2a31,
    0x383f_464d,
    0x545b_6269,
    0x7077_7e85,
    0x8c93_9aa1,
    0xa8af_b6bd,
    0xc4cb_d2d9,
    0xe0e7_eef5,
    0xfc03_0a11,
    0x181f_262d,
    0x343b_4249,
    0x5057_5e65,
    0x6c73_7a81,
    0x888f_969d,
    0xa4ab_b2b9,
    0xc0c7_ced5,
    0xdce3_eaf1,
    0xf8ff_060d,
    0x141b_2229,
    0x3037_3e45,
    0x4c53_5a61,
    0x686f_767d,
    0x848b_9299,
    0xa0a7_aeb5,
    0xbcc3_cad1,
    0xd8df_e6ed,
    0xf4fb_0209,
    0x1017_1e25,
    0x2c33_3a41,
    0x484f_565d,
    0x646b_7279,
];

impl Sm4Cipher {
    pub fn new(key: &[u8]) -> Result<Sm4Cipher, Sm4Error> {
        let mut k: [u32; 4] = split_block(key)?;
        let mut cipher = Sm4Cipher { rk: Vec::new() };
        for i in 0..4 {
            k[i] ^= FK[i];
        }
        for i in 0..8 {
            k[0] ^= t_prime_trans(k[1] ^ k[2] ^ k[3] ^ CK[i * 4]);
            k[1] ^= t_prime_trans(k[2] ^ k[3] ^ k[0] ^ CK[i * 4 + 1]);
            k[2] ^= t_prime_trans(k[3] ^ k[0] ^ k[1] ^ CK[i * 4 + 2]);
            k[3] ^= t_prime_trans(k[0] ^ k[1] ^ k[2] ^ CK[i * 4 + 3]);
            cipher.rk.push(k[0]);
            cipher.rk.push(k[1]);
            cipher.rk.push(k[2]);
            cipher.rk.push(k[3]);
        }

        Ok(cipher)
    }

    pub fn encrypt(&self, block_in: &[u8]) -> Result<[u8; 16], Sm4Error> {
        let mut x: [u32; 4] = split_block(block_in)?;
        let rk = &self.rk;
        for i in 0..8 {
            x[0] ^= t_trans(x[1] ^ x[2] ^ x[3] ^ rk[i * 4]);
            x[1] ^= t_trans(x[2] ^ x[3] ^ x[0] ^ rk[i * 4 + 1]);
            x[2] ^= t_trans(x[3] ^ x[0] ^ x[1] ^ rk[i * 4 + 2]);
            x[3] ^= t_trans(x[0] ^ x[1] ^ x[2] ^ rk[i * 4 + 3]);
        }
        let y = [x[3], x[2], x[1], x[0]];
        combine_block(&y)
    }

    pub fn decrypt(&self, block_in: &[u8]) -> Result<[u8; 16], Sm4Error> {
        let mut x: [u32; 4] = split_block(block_in)?;
        let rk = &self.rk;
        for i in 0..8 {
            x[0] ^= t_trans(x[1] ^ x[2] ^ x[3] ^ rk[31 - i * 4]);
            x[1] ^= t_trans(x[2] ^ x[3] ^ x[0] ^ rk[31 - (i * 4 + 1)]);
            x[2] ^= t_trans(x[3] ^ x[0] ^ x[1] ^ rk[31 - (i * 4 + 2)]);
            x[3] ^= t_trans(x[0] ^ x[1] ^ x[2] ^ rk[31 - (i * 4 + 3)]);
        }
        let y = [x[3], x[2], x[1], x[0]];
        combine_block(&y)
    }
}

// Tests below

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn setup_cipher() {
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let cipher = Sm4Cipher::new(&key).unwrap();
        let rk = &cipher.rk;
        assert_eq!(rk[0], 0xf121_86f9);
        assert_eq!(rk[31], 0x9124_a012);
    }

    #[test]
    fn enc_and_dec() {
        let key: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let cipher = Sm4Cipher::new(&key).unwrap();

        let data: [u8; 16] = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let ct = cipher.encrypt(&data).unwrap();
        let standard_ct: [u8; 16] = [
            0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e,
            0x42, 0x46,
        ];

        // Check the example cipher text
        for i in 0..16 {
            assert_eq!(standard_ct[i], ct[i]);
        }

        // Check the result of decryption
        let pt = cipher.decrypt(&ct).unwrap();
        for i in 0..16 {
            assert_eq!(pt[i], data[i]);
        }
    }
}
