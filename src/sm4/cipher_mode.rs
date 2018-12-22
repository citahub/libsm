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

pub enum CipherMode {
    Cfb,
    Ofb,
    Ctr,
}

pub struct SM4CipherMode {
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
    let mut t;
    let mut carry = 1;

    for i in 0..16 {
        t = i32::from(a[15 - i]) + carry;
        if t == 256 {
            t = 0;
            carry = 1;
        } else {
            carry = 0
        }
        a[15 - i] = t as u8;
    }
}

impl SM4CipherMode {
    pub fn new(key: &[u8], mode: CipherMode) -> SM4CipherMode {
        let cipher = Sm4Cipher::new(key);
        SM4CipherMode { cipher, mode }
    }

    pub fn encrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        if iv.len() != 16 {
            panic!("the iv of sm4 must be 16-byte long");
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_encrypt(data, iv),
            CipherMode::Ofb => self.ofb_encrypt(data, iv),
            CipherMode::Ctr => self.ctr_encrypt(data, iv),
        }
    }

    pub fn decrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        if iv.len() != 16 {
            panic!("the iv of sm4 must be 16-byte long");
        }
        match self.mode {
            CipherMode::Cfb => self.cfb_decrypt(data, iv),
            CipherMode::Ofb => self.ofb_encrypt(data, iv),
            CipherMode::Ctr => self.ctr_encrypt(data, iv),
        }
    }

    fn cfb_encrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(&ct);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        out
    }

    fn cfb_decrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);
            let ct = &data[i * 16..i * 16 + 16];
            let pt = block_xor(&enc, ct);
            for i in pt.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(ct);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        out
    }

    fn ofb_encrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        let mut out: Vec<u8> = Vec::new();
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.clone_from_slice(iv);

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            vec_buf.clone_from_slice(&enc);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        out
    }

    fn ctr_encrypt(&self, data: &[u8], iv: &[u8]) -> Vec<u8> {
        let mut vec_buf: Vec<u8> = vec![0; 16];
        vec_buf.resize(16, 0);
        vec_buf.clone_from_slice(iv);
        let mut out: Vec<u8> = Vec::new();

        let block_num = data.len() / 16;
        let tail_len = data.len() - block_num * 16;

        // Normal
        for i in 0..block_num {
            let enc = self.cipher.encrypt(&vec_buf[..]);
            let ct = block_xor(&enc, &data[i * 16..i * 16 + 16]);
            for i in ct.iter() {
                out.push(*i);
            }
            block_add_one(&mut vec_buf[..]);
        }

        // Last block
        let enc = self.cipher.encrypt(&vec_buf[..]);
        for i in 0..tail_len {
            let b = data[block_num * 16 + i] ^ enc[i];
            out.push(b);
        }
        out
    }
}

// TODO: AEAD in SM4
// pub struct SM4Gcm;

// Tests below

#[cfg(test)]
mod tests {
    use super::*;

    use rand::os::OsRng;
    use rand::Rng;

    fn rand_block() -> [u8; 16] {
        let mut rng = OsRng::new().unwrap();
        let mut block: [u8; 16] = [0; 16];
        rng.fill_bytes(&mut block[..]);
        block
    }

    fn rand_data(len: usize) -> Vec<u8> {
        let mut rng = OsRng::new().unwrap();
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
    }

    fn test_ciphermode(mode: CipherMode) {
        let key = rand_block();
        let iv = rand_block();

        let cmode = SM4CipherMode::new(&key, mode);

        let pt = rand_data(10);
        let ct = cmode.encrypt(&pt[..], &iv);
        let new_pt = cmode.decrypt(&ct[..], &iv);
        assert_eq!(pt, new_pt);

        let pt = rand_data(100);
        let ct = cmode.encrypt(&pt[..], &iv);
        let new_pt = cmode.decrypt(&ct[..], &iv);
        assert_eq!(pt, new_pt);

        let pt = rand_data(1000);
        let ct = cmode.encrypt(&pt[..], &iv);
        let new_pt = cmode.decrypt(&ct[..], &iv);
        assert_eq!(pt, new_pt);
    }
}
