# Sonic UC-SE

This crate is a UC-secure and simulation extractable (SE) version of [Sonic](https://github.com/ebfull/sonic), an _updatable_ zk-SNARK protocol. We do this by using a generic transformation that turns any sound NIZK into a _simulation extractable_ NIZK -- in a UC-secure way. The transformation changes the NIZK's language from { (y,x) | y = H(x) } to { ((y,h), (x,r)) | y = H(x) OR h = g^r } and the proof consists of:
- an _updatable signature_ (based on a [fork of starsig](https://github.com/nglaeser/starsig)) on a one-time signature public key, 
- an _updatable encryption_ (based on [rust-elgamal](https://github.com/ZenGo-X/rust-elgamal)) of the base scheme's witness,
- a NIZK for the new language using the base protocol (Sonic) and the base statement/witness pair (i.e., using the left branch of the OR),
- a one-time signature ([lamport-sigs](https://lib.rs/crates/lamport_sigs)) on the above NIZK, the base statement y, and the above updatable signature, updatable ciphertext, and updatable encryption public key, using the secret key corresponding to the above one-time public key, and
- the public keys of the updatable and one-time signature schemes

**THIS IMPLEMENTATION IS A PROTOTYPE AND IS FULL OF BUGS, DO NOT USE IT IN PRODUCTION**

## Usage

```
cargo build

# run the UC-SE NIZK scheme
cargo run --example paper

# test the new building blocks
cargo test --test uc-se

# all tests
cargo test
```

Documentation:
```
cargo doc --open
```

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
