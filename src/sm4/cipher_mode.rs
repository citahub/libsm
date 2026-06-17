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
use crate::sm4::gcm::*;

pub enum CipherMode {
    Cfb,
    Ofb,
    Ctr,
    Cbc,
    Gcm,
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

fn block_xor_64(a: &[u8], b: &[u8]) -> [u8; 64] {
    let mut out: [u8; 64] = [0; 64];
    for i in 0..64 {
        out[i] = a[i] ^ b[i];
    }
    out
}

fn block_add_one(a: &mut [u8]) {
    for i in 0..16 {
        let (t, c) = a[15 - i].overflowing_add(1);
        a[15 - i] = t;
        if !c {
            return;
        }
    }
}

impl Sm4CipherMode {
    pub fn new(key: &[u8], mode: CipherMode) -> Sm4Result<Sm4CipherMode> {
        let cipher = Sm4Cipher::new(key)?;
        Ok(Sm4CipherMode { cipher, mode })
    }

    pub fn encrypt(&self, aad: &[u8], data: &[u8], iv: &[u8]) -> Sm4Result<Vec<u8>> {
        if iv.len() != 16 {
            return Err(Sm4Error::ErrorBlockSize);
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_encrypt(data, iv),
            CipherMode::Ofb => self.ofb_encrypt(data, iv),
            CipherMode::Ctr => self.ctr_encrypt(data, iv),
            CipherMode::Cbc => self.cbc_encrypt(data, iv),
            CipherMode::Gcm => self.gcm_encrypt(aad, data, iv),
        }
    }

    pub fn decrypt(&self, aad: &[u8], data: &[u8], iv: &[u8]) -> Sm4Result<Vec<u8>> {
        if iv.len() != 16 {
            return Err(Sm4Error::ErrorBlockSize);
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_decrypt(data, iv),
            CipherMode::Ofb => self.ofb_encrypt(data, iv),
            CipherMode::Ctr => self.ctr_encrypt(data, iv),
            CipherMode::Cbc => self.cbc_decrypt(data, iv),
            CipherMode::Gcm => self.gcm_decrypt(aad, data, iv),
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
        let block_num = data.len() / 64;
        let tail_len = data.len() - block_num * 64;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // 先扩充到 64bit
        let mut vec_buf_64: [u8; 64] = [0; 64];
        for z in 0..4 {
            for i in 0..16 {
                vec_buf_64[z * 16 + i] = vec_buf[i];
            }
            block_add_one(&mut vec_buf[..]);
        }

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt_sm4ni(&vec_buf_64)?;
            let ct = block_xor_64(&enc, &data[i * 64..i * 64 + 64]);
            for i in ct.iter() {
                out.push(*i);
            }

            vec_buf[..16].copy_from_slice(&vec_buf_64[48..64]);

            block_add_one(&mut vec_buf[..]);
            for z in 0..4 {
                for i in 0..16 {
                    vec_buf_64[z * 16 + i] = vec_buf[i];
                }
                block_add_one(&mut vec_buf[..]);
            }
        }

        // Last block
        let enc = self.cipher.encrypt_sm4ni(&vec_buf_64)?;
        for i in 0..tail_len {
            let b = data[block_num * 64 + i] ^ enc[i];
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

    fn galois_ctr(&self, data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        if data.is_empty() {
            Ok(vec![])
        } else {
            let block_num = data.len() / 16;
            let remind = data.len() % 16;

            let mut out: Vec<u8> = Vec::new();
            let mut cb = [0; 16];
            cb.copy_from_slice(iv);

            for i in 0..block_num {
                let yi = block_xor(&data[i * 16..i * 16 + 16], &self.cipher.encrypt(&cb)?);
                out.extend_from_slice(&yi);
                gcm_block_add_one(&mut cb);
            }

            for i in 0..remind {
                let enc = self.cipher.encrypt(&cb)?;
                let b = data[block_num * 16 + i] ^ enc[i];
                out.push(b);
            }
            Ok(out)
        }
    }

    fn gcm_encrypt(&self, aad: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let h = u128::from_be_bytes(self.cipher.encrypt(&[0; 16])?);

        // iv must be 128 bit, but we also consider 96 bit and others
        // as nist 800-38d specified
        let mut j0 = vec![];
        let iv_len = iv.len();
        if iv_len == 12 {
            j0.extend_from_slice(iv);
            j0.extend_from_slice(&[0, 0, 0, 1]);
        } else {
            let mut iv_padding = vec![];
            let s = 16 * ((iv_len + 15) / 16) - iv_len;
            iv_padding.extend_from_slice(iv);
            iv_padding.extend_from_slice(&vec![0; s + 8]);
            #[cfg(target_pointer_width = "32")]
            let iv_len = iv_len as u64;
            iv_padding.extend_from_slice(&(iv_len * 8).to_be_bytes());
            let j0_128 = galois_hash(h, &bytes_to_u128array(&iv_padding));
            j0.extend_from_slice(&j0_128.to_be_bytes());
        }

        let mut j0_enc = j0.clone();
        gcm_block_add_one(&mut j0_enc);
        let mut enc = self.galois_ctr(data, &j0_enc)?;

        let aad_len = aad.len();
        let enc_len = enc.len();
        let u = 16 * ((enc_len + 15) / 16) - enc_len;
        let v = 16 * ((aad_len + 15) / 16) - aad_len;

        let mut tag_padding = vec![];
        tag_padding.extend_from_slice(aad);
        tag_padding.extend_from_slice(&vec![0; v]);
        tag_padding.extend_from_slice(&enc);
        tag_padding.extend_from_slice(&vec![0; u]);
        #[cfg(target_pointer_width = "32")]
        let aad_len = aad_len as u64;
        tag_padding.extend_from_slice(&(aad_len * 8).to_be_bytes());
        #[cfg(target_pointer_width = "32")]
        let enc_len = enc_len as u64;
        tag_padding.extend_from_slice(&(enc_len * 8).to_be_bytes());
        let tag_hash = galois_hash(h, &bytes_to_u128array(&tag_padding));
        let tag_crt = self.galois_ctr(&tag_hash.to_be_bytes(), &j0)?;

        enc.extend_from_slice(&tag_crt);
        Ok(enc)
    }

    fn gcm_decrypt(&self, aad: &[u8], data: &[u8], iv: &[u8]) -> Result<Vec<u8>, Sm4Error> {
        let tag = &data[data.len() - 16..];
        let enc = &data[..data.len() - 16];

        let h = u128::from_be_bytes(self.cipher.encrypt(&[0; 16])?);

        // iv must be 128 bit, but we also consider 96 bit and others
        // as nist 800-38d specified
        let mut j0 = vec![];
        let iv_len = iv.len();
        if iv_len == 12 {
            j0.extend_from_slice(iv);
            j0.extend_from_slice(&[0, 0, 0, 1]);
        } else {
            let mut iv_padding = vec![];
            let s = 16 * ((iv_len + 15) / 16) - iv_len;
            iv_padding.extend_from_slice(iv);
            iv_padding.extend_from_slice(&vec![0; s + 8]);
            #[cfg(target_pointer_width = "32")]
            let iv_len = iv_len as u64;
            iv_padding.extend_from_slice(&(iv_len * 8).to_be_bytes());
            let j0_128 = galois_hash(h, &bytes_to_u128array(&iv_padding));
            j0.extend_from_slice(&j0_128.to_be_bytes());
        }

        let mut j0_enc = j0.clone();
        gcm_block_add_one(&mut j0_enc);
        let data = self.galois_ctr(enc, &j0_enc)?;

        let aad_len = aad.len();
        let enc_len = enc.len();
        let u = 16 * ((enc_len + 15) / 16) - enc_len;
        let v = 16 * ((aad_len + 15) / 16) - aad_len;

        let mut tag_padding = vec![];
        tag_padding.extend_from_slice(aad);
        tag_padding.extend_from_slice(&vec![0; v]);
        tag_padding.extend_from_slice(enc);
        tag_padding.extend_from_slice(&vec![0; u]);
        #[cfg(target_pointer_width = "32")]
        let aad_len = aad_len as u64;
        tag_padding.extend_from_slice(&(aad_len * 8).to_be_bytes());
        #[cfg(target_pointer_width = "32")]
        let enc_len = enc_len as u64;
        tag_padding.extend_from_slice(&(enc_len * 8).to_be_bytes());
        let tag_hash = galois_hash(h, &bytes_to_u128array(&tag_padding));
        let tag_crt = self.galois_ctr(&tag_hash.to_be_bytes(), &j0)?;

        if tag != tag_crt {
            Err(Sm4Error::InvalidTag)
        } else {
            Ok(data)
        }
    }
}

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
        test_ciphermode(CipherMode::Gcm);
    }

    fn test_ciphermode(mode: CipherMode) {
        let key = rand_block();
        let iv = rand_block();

        let cmode = Sm4CipherMode::new(&key, mode).unwrap();

        let pt = rand_data(10);
        let ct = cmode.encrypt(&[], &pt, &iv).unwrap();
        let new_pt = cmode.decrypt(&[], &ct, &iv).unwrap();
        assert_eq!(pt, new_pt);

        let pt = rand_data(100);
        let ct = cmode.encrypt(&[], &pt, &iv).unwrap();
        let new_pt = cmode.decrypt(&[], &ct, &iv).unwrap();
        assert_eq!(pt, new_pt);

        let pt = rand_data(1000);
        let ct = cmode.encrypt(&[], &pt, &iv).unwrap();
        let new_pt = cmode.decrypt(&[], &ct, &iv).unwrap();
        assert_eq!(pt, new_pt);
    }

    #[test]
    fn ctr_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Ctr).unwrap();
        let msg = b"hello world, this file is used for smx test\n";
        let lhs = cipher_mode.encrypt(&[], msg, &iv).unwrap();
        let lhs: &[u8] = lhs.as_ref();

        let rhs: &[u8] = include_bytes!("example/text.sms4-ctr");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn ctr_enc_long_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Ctr).unwrap();
        let msg = include_bytes!("example/textlong");
        let lhs = cipher_mode.encrypt(msg, &iv).unwrap();
        let lhs: &[u8] = lhs.as_ref();

        let rhs: &[u8] = include_bytes!("example/text.sms4-ctr.long");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn cfb_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Cfb).unwrap();
        let msg = b"hello world, this file is used for smx test\n";
        let lhs = cipher_mode.encrypt(&[], msg, &iv);
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
        let lhs = cipher_mode.encrypt(&[], msg, &iv);
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
        let lhs = cipher_mode.encrypt(&[], msg, &iv);
        let lhs: &[u8] = lhs.as_ref().unwrap();

        let rhs: &[u8] = include_bytes!("example/text.sms4-cbc");
        assert_eq!(lhs, rhs);
    }

    #[test]
    fn gcm_enc_test() {
        let key = hex::decode("1234567890abcdef1234567890abcdef").unwrap();
        let iv = hex::decode("fedcba0987654321fedcba0987654321").unwrap();
        let aad = hex::decode("feedfacedeadbeeffeedfacedeadbeefabaddad2").unwrap();

        let cipher_mode = Sm4CipherMode::new(&key, CipherMode::Gcm).unwrap();
        let msg = b"hello world, this file is used for smx test\n";
        let lhs = cipher_mode.encrypt(&aad, msg, &iv);
        let lhs: &[u8] = lhs.as_ref().unwrap();

        let rhs: &[u8] = include_bytes!("example/text.sms4-gcm");
        assert_eq!(lhs, rhs);
    }
}
