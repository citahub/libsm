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

use super::cipher::Sm4Cipher;
use crate::sm4::error::{Sm4Error, Sm4Result};

pub enum CipherMode {
    Cfb,
    Ofb,
    Ctr,
    Cbc,
}

pub struct Sm4CipherMode {
    cipher: Sm4Cipher,
    mode: CipherMode,
}

fn block_xor(a: &[u8], b: &[u8]) -> [u8; 16] {
    let mut out: [u8; 16] = [0; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn block_add_one(a: &mut [u8]) {
    let mut carry = 1;

    for i in 0..16 {
        let (t, c) = a[15 - i].overflowing_add(carry);
        a[15 - i] = t;
        if !c {
            return;
        }
        carry = c as u8;
    }
}

impl Sm4CipherMode {
    pub fn new(key: &[u8], mode: CipherMode) -> Sm4Result<Sm4CipherMode> {
        let cipher = Sm4Cipher::new(key)?;
        Ok(Sm4CipherMode { cipher, mode })
    }

    pub fn encrypt(&self, data: &[u8], iv: &[u8]) -> Sm4Result<Vec<u8>> {
        if iv.len() != 16 {
            return Err(Sm4Error::ErrorBlockSize);
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_encrypt(data, iv),
            CipherMode::Ofb => self.ofb_encrypt(data, iv),
            CipherMode::Ctr => self.ctr_encrypt(data, iv),
            CipherMode::Cbc => self.cbc_encrypt(data, iv),
        }
    }

    pub fn decrypt(&self, data: &[u8], iv: &[u8]) -> Sm4Result<Vec<u8>> {
        if iv.len() != 16 {
            return Err(Sm4Error::ErrorBlockSize);
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_decrypt(data, iv),
            CipherMode::Ofb => self.ofb_encrypt(data, iv),
            CipherMode::Ctr => self.ctr_encrypt(data, iv),
            CipherMode::Cbc => self.cbc_decrypt(data, iv),
        }
    }

    fn cfb_encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..])?;
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(&ct);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..])?;
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        Ok(out)
    }

    fn cfb_decrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..])?;
            let ct = &data[i * 16..i * 16 + 16];
            let pt = block_xor(&enc, ct);
            for i in pt.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(ct);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..])?;
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        Ok(out)
    }

    fn ofb_encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..])?;
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(&enc);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..])?;
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        Ok(out)
    }

    fn ctr_encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..])?;
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            block_add_one(&mut vec_buf[..]);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..])?;
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        Ok(out)
    }

    fn cbc_encrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let block_num = data.len() / 16;
        let remind = data.len() % 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf = [0; 16];
        vec_buf.copy_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let ct = block_xor(&vec_buf, &data[i * 16..i * 16 + 16]);
            let enc = self.cipher.encrypt(&ct)?;

            out.extend_from_slice(&enc);
            vec_buf = enc;
        }

        if remind != 0 {
            let mut last_block = [16 - remind as u8; 16];
            last_block[..remind].copy_from_slice(&data[block_num * 16..]);

            let ct = block_xor(&vec_buf, &last_block);
            let enc = self.cipher.encrypt(&ct)?;
            out.extend_from_slice(&enc);
        } else {
            let ff_padding = block_xor(&vec_buf, &[0x10; 16]);
            let enc = self.cipher.encrypt(&ff_padding)?;
            out.extend_from_slice(&enc);
        }

        Ok(out)
    }

    fn cbc_decrypt(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let data_len = data.len();
        let block_num = data_len / 16;
        if data_len % 16 != 0 {
            return Err(Sm4Error::ErrorDataLen);
        }

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf = [0; 16];
        vec_buf.copy_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.decrypt(&data[i * 16..i * 16 + 16])?;
            let ct = block_xor(&vec_buf, &enc);

            for j in ct.iter() {
                out.push(*j);
            }
            vec_buf.copy_from_slice(&data[i * 16..i * 16 + 16]);
        }

        let last_u8 = out[data_len - 1];
        if last_u8 > 0x10 || last_u8 == 0 {
            return Err(Sm4Error::InvalidLastU8);
        }
        out.resize(data_len - last_u8 as usize, 0);

        Ok(out)
    }
}

// TODO: AEAD in SM4
// pub struct SM4Gcm;

// Tests below

#[cfg(test)]
mod tests {
    use super::*;

    use rand::RngCore;

    fn rand_block() -> [u8; 16] {
        let mut rng = rand::thread_rng();
        let mut block: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut block[..]);
        block
    }

    fn rand_data(len: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut dat: Vec<u8> = Vec::new();
        dat.resize(len, 0);
        rng.fill_bytes(&mut dat[..]);
        dat
    }

    #[test]
    fn test_driver() {
        test_ciphermode(CipherMode::Ctr);
        test_ciphermode(CipherMode::Cfb);
        test_ciphermode(CipherMode::Ofb);
        test_ciphermode(CipherMode::Cbc);
    }

    fn test_ciphermode(mode: CipherMode) {
        let key = rand_block();
        let iv = rand_block();

        let cmode = Sm4CipherMode::new(&key, mode).unwrap();

        let pt = rand_data(10);
        let ct = cmode.encrypt(&pt[..], &iv).unwrap();
        let new_pt = cmode.decrypt(&ct[..], &iv).unwrap();
        assert_eq!(pt, new_pt);

        let pt = rand_data(100);
        let ct = cmode.encrypt(&pt[..], &iv).unwrap();
        let new_pt = cmode.decrypt(&ct[..], &iv).unwrap();
        assert_eq!(pt, new_pt);

        let pt = rand_data(1000);
        let ct = cmode.encrypt(&pt[..], &iv).unwrap();
        let new_pt = cmode.decrypt(&ct[..], &iv).unwrap();
        assert_eq!(pt, new_pt);
    }

    #[test]
    fn ctr_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Ctr).unwrap();
        let msg = b"hello world, this file is used for smx test\n";
        let lhs = cipher_mode.encrypt(msg, &iv).unwrap();
        let lhs: &[u8] = lhs.as_ref();

        let rhs: &[u8] = include_bytes!("example/text.sms4-ctr");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn cfb_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Cfb).unwrap();
        let msg = b"hello world, this file is used for smx test\n";
        let lhs = cipher_mode.encrypt(msg, &iv);
        let lhs: &[u8] = lhs.as_ref().unwrap();

        let rhs: &[u8] = include_bytes!("example/text.sms4-cfb");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn ofb_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Ofb).unwrap();
        let msg = b"hello world, this file is used for smx test\n";
        let lhs = cipher_mode.encrypt(msg, &iv);
        let lhs: &[u8] = lhs.as_ref().unwrap();

        let rhs: &[u8] = include_bytes!("example/text.sms4-ofb");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn cbc_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Cbc).unwrap();
        let msg = b"hello world, this file is used for smx test\n";
        let lhs = cipher_mode.encrypt(msg, &iv);
        let lhs: &[u8] = lhs.as_ref().unwrap();

        let rhs: &[u8] = include_bytes!("example/text.sms4-cbc");
        assert_eq!(lhs, rhs);
    }
}
