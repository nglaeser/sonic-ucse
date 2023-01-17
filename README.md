# UC SE Sonic

This crate is a UC-secure and simulation extractable (SE) version of [Sonic](https://github.com/ebfull/sonic), an _updatable_ zk-SNARK protocol. We do this by using a generic transformation that turns any sound NIZK into a _simulation extractable_ NIZK -- in a UC-secure way that works in the updatable setting. The transformation changes the NIZK's language from 

{ (x,w) | x = H(w) }

to 

{ ((x,c,h), (w,&omega;,r)) | c = Enc(pk, w; &omega;) &and; (x = H(w) &or; h = g<sup>r</sup>) }

and the proof is a tuple (&sigma;, c, &pi;, &sigma;<sub>OT</sub>, pk<sub>&ell;</sub>, pk<sub>OT</sub>) consisting of:

- **&sigma; &leftarrow; &Sigma;.Sign(sk<sub>&ell;</sub>, pk<sub>OT</sub>)**: an _updatable signature_ ([Schnorr over Jubjub](https://github.com/nglaeser/jubjub-schnorr)) on a one-time signature public key, 
- **c &leftarrow; UP.Enc(pk<sub>up</sub>, w; &omega;)**: an _updatable encryption_ ([ElGamal over Jubjub](https://github.com/nglaeser/jubjub-elgamal)) of the base scheme's witness,
- **&pi; &leftarrow; &Pi;.P(crs<sub>up</sub>, (x':=(x,c,&perp;), w':=(w,&omega;,&perp;))**: a NIZK for the new language using the base protocol ([Sonic](https://github.com/ebfull/sonic)) and the base statement/witness pair (i.e., using the left branch of the OR),
- **&sigma;<sub>OT</sub> &leftarrow; &Sigma;<sub>OT</sub>.Sign(sk<sub>OT</sub>, &pi; || x || c || pk<sub>&ell;</sub> || &sigma;)**: a strongly-unforgeable one-time signature (sOTS) ([schnorrkel](https://crates.io/crates/schnorrkel)) on the above NIZK, the base statement x, and the above updatable ciphertext, updatable encryption public key, and updatable signature, using the secret key corresponding to the above one-time public key, and
- **pk<sub>&ell;</sub>, pk<sub>OT</sub>**: the public keys of the updatable and one-time signature schemes.

The intuition is that the sOTS is used to sign the parts of the proof that must be non-malleable, and the updatable signature is used to certify the one-time public key. The OR trick adds simulation extractability, and the updatable encryption adds black-box simulation extractability.

**THIS IMPLEMENTATION IS A PROTOTYPE AND IS FULL OF BUGS, DO NOT USE IT IN PRODUCTION**

## Usage

```
cargo build

# run the UC-SE NIZK scheme (BB-Lamassu)
cargo run --example bb-lamassu

# compare to previous work
cargo run --example sonic

# test the new building blocks
cargo test --test uc-se

# all tests
cargo test
```

Because of some of the dependencies, we need to use the nightly toolchain. This should be taken care of by the `rust-toolchain.toml` file but can also be done manually by replacing calls to `cargo` with `cargo +nightly` above.

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

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.