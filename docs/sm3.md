# SM3

SM3 is a hash function. To use SM3 in libsm:

1. Make sure that your data is `&[u8]`.

2. Create a `SM3Hash`. 

3. Get the digest.

Sample:

```rust
use libsm::sm3::Sm3Hash;

let string = String::from("sample");
let mut hash = Sm3Hash::new(string.as_bytes());
let digest: [u8;32] = hash.get_hash();
```

