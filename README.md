# UC SE Sonic

This crate is a UC-secure and simulation extractable (SE) version of [Sonic](https://github.com/ebfull/sonic) [1], an _updatable_ zk-SNARK protocol. We do this by using a generic transformation (_BB-Lamassu_ [3]) that turns any sound NIZK into a _simulation extractable_ NIZK -- in a UC-secure way that works in the updatable setting. 

## Lamassu

Previous work [2] gave a generic transformation called _Lamassu_ which lifts any sound NIZK into a simulation extractable NIZK, again in the updatable setting but in a _non-black-box_ and therefore _non-UC_ way. Lamassu changes the base NIZK's language from 

{ (x,w) | x = H(w) }

to 

{ ((x,h), (w,r)) | x = H(w) &or; h = g<sup>r</sup> }

with the proof being a tuple (&sigma;, &pi;, &sigma;<sub>OT</sub>, pk<sub>&ell;</sub>, pk<sub>OT</sub>), where

- **&sigma; &leftarrow; &Sigma;.Sign(sk<sub>&ell;</sub>, pk<sub>OT</sub>)**: an _updatable signature_ ([Schnorr over Jubjub](https://github.com/nglaeser/jubjub-schnorr)) on a one-time signature public key, 
- **&pi; &leftarrow; &Pi;.P(crs<sub>up</sub>, (x':=(x,&perp;), w':=(w,&perp;))**: a NIZK for the _new_ language using the base protocol ([Sonic](https://github.com/ebfull/sonic)) and the base statement/witness pair (i.e., using the left branch of the OR),
- **&sigma;<sub>OT</sub> &leftarrow; &Sigma;<sub>OT</sub>.Sign(sk<sub>OT</sub>, &pi; || x || c || pk<sub>&ell;</sub> || &sigma;)**: a strongly-unforgeable one-time signature (sOTS) ([schnorrkel](https://crates.io/crates/schnorrkel)) on the above NIZK, the base statement x, and the above updatable ciphertext, updatable encryption public key, and updatable signature, using the secret key corresponding to the above one-time public key, and
- **pk<sub>&ell;</sub>, pk<sub>OT</sub>**: the public keys of the updatable and one-time signature schemes.

The intuition is that the sOTS is used to sign the parts of the proof that must be non-malleable, and the updatable signature is used to certify the one-time public key. The OR trick adds simulation extractability.

## BB-Lamassu

The _BB-Lamassu_ transformation [3] is a version of Lamassu which is _fully black-box_. We introduce an updatable encryption of the underlying witness to enable _BB_ SE (while remaining compatible with updatable CRS) and require the updatable signature to also be BB-extractable. With the new elements compared to Lamassu indicated in bold, the NIZK's language changes from 

{ (x,w) | x = H(w) }

to 

{ ((x,**c**,h), (w,**&omega;**,r)) | **c = Enc(pk, w; &omega;)** &and; (x = H(w) &or; h = g<sup>r</sup>) }

and the proof is a tuple (&sigma;, **c**, &pi;, &sigma;<sub>OT</sub>, pk<sub>&ell;</sub>, pk<sub>OT</sub>) consisting of the elements from before plus:

- **c &leftarrow; UP.Enc(pk<sub>up</sub>, w; &omega;)**: an _updatable encryption_ ([ElGamal over Jubjub](https://github.com/nglaeser/jubjub-elgamal)) of the base scheme's witness, and
- **&pi; &leftarrow; &Pi;.P(crs<sub>up</sub>, (x':=(x,c,&perp;), w':=(w,&omega;,&perp;))**: the NIZK is now for the BB-Lamassu language, still using the base protocol ([Sonic](https://github.com/ebfull/sonic)) and the base statement/witness pair with the left branch of the OR.

## References

[1] Mary Maller, Sean Bowe, Markulf Kohlweiss, and Sarah Meiklejohn. _Sonic: Zero-Knowledge SNARKs from Linear-Size Universal and Updateable Structured Reference Strings_. Cryptology ePrint Archive paper [2019/099](https://eprint.iacr.org/2019/099).  
[2] Behzad Abdolmaleki, Sebastian Ramacher, and Daniel Slamanig. _Lift-and-Shift: Obtaining Simulation Extractable Subversion and Updatable SNARKs Generically_. Cryptology ePrint Archive paper [2020/062](https://eprint.iacr.org/2020/062).  
[3] Behzad Abdolmaleki, Noemi Glaeser, Sebastian Ramacher, and Daniel Slamanig. _Universally Composable NIZKs: Circuit Succinct, Non-Malleable and CRS-Updatable_. In submission.

---

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