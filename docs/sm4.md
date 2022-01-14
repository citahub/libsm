# SM4

SM4 is a block cipher. CFB mode, OFB mode, CTR mode and CBC mode are implemented in libsm.

Here are their definitions:

```rust
pub enum CipherMode {
    Cfb,
    Ofb,
    Ctr,
    Cbc,
}
```

## Create Cipher

Choose a mode when creating a cipher. Then call the creating function.

Sample:

```rust
use libsm::sm4::{Mode, Cipher};
use rand::RngCore;

fn rand_block() -> [u8; 16] {
    let mut rng = rand::thread_rng();;
    let mut block: [u8; 16] = [0; 16];
    rng.fill_bytes(&mut block[..]);
    block
}

let key = rand_block();

let cipher = Cipher::new(&key, Mode::Cfb);
```

## Encryption and Decryption

Initialize a random IV(Initial Vector), which can be generated using the `rand_block()` function above.

Sample:

```rust
let iv = rand_block();
let plain_text = String::from("plain text");

// Encryption
let cipher_text: Vec<u8> = cipher.encrypt(plain_text.to_bytes(), &iv);

// Decryption
let plain_text: Vec<u8> = cipher.decrypt(&cipher_text[..], &iv);
```
