# SM2

SM2 can be used in digital signature.

Algorithms below are related:

- Key generation
- Sign
- Verify
- Serialization and deserialization

## Create a New Contex

By creating a context, libsm will initialize all the parameters used in those algorithms, including ECC parameters.

```
use libsm::sm2::signature::{Pubkey, Seckey, Signature, SigCtx};
let ctx = SigCtx::new();
```

## Generate a Key pair

```
let (pk, sk) = ctx.new_keypair();
```

`pk` is a public key use for verifying. `sk` is a secret key used for signing.

The public key can be derived from the secret key.

```
let pk = ctx.pk_from_sk(&sk).unwrap();
```

## Sign and Verify

```
let signature = ctx.sign(msg, &sk, &pk);
let result: bool = ctx.verify(msg, &pk, &signature);
```

## Serialization and Deserialization
 
Keys and Signatures can be serialized to ``Vec<u8>``.

### Public Key

```
let pk_raw = ctx.serialize_pubkey(&pk, true);
let new_pk = ctx.load_pubkey(&pk_raw[..])?;
```

if you want to compress the public key, set the second parameter of `serialize_pubkey()` to `true`. An uncompressed public key will be 65 bytes, and the compressed key is 33 bytes.

The return value of `load_pubkey()` is ``Result<Pubkey, bool>``. If the public key is invalid, an error will be returned.

### Secret Key

```
let sk_raw = ctx.serialize_seckey(&sk);
let new_sk = ctx.load_seckey(&sk_raw[..])?;
```

The output size of `serialize_seckey()` is 32 bytes.

The return value of `load_seckey()` is `Result<Seckey, bool>`. An error will be returned if the secret key is invalid.

### Signature

Signatures can be encoded to DER format.

```
let der = signature.der_encode();
let parsed_sig = Signature::der_decode(&der[..])?;
```

