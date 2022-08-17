#[cfg(test)]
mod tests {
    extern crate pairing;
    extern crate sonic_ucse;
    use sonic_ucse::srs::SRS;

    #[test]
    #[ignore]
    fn test_new_srs() {
        use pairing::bls12_381::{Bls12, Fr};
        use pairing::PrimeField;
        use std::time::Instant;

        let srs_x = Fr::from_str("23923").unwrap();
        let srs_alpha = Fr::from_str("23728792").unwrap();

        println!("making srs");
        let start = Instant::now();
        // pick d such that 3n < d < 4n, where n is the number of multiplication gates in the instance
        // let d = 830564; // no idea why the original sonic code picked this magic number
        let d = (7 / 2) * 1562; // 3.5*n for Pedersen with 384-bit input (in Table 4 of sonic)
        let _srs2 = SRS::<Bls12>::new(d, srs_x, srs_alpha);
        println!("done in {:?}", start.elapsed());
    }
    #[test]
    fn test_dummy_srs() {
        use pairing::bls12_381::{Bls12, Fr};
        use pairing::PrimeField;
        use std::time::Instant;

        let srs_x = Fr::from_str("23923").unwrap();
        let srs_alpha = Fr::from_str("23728792").unwrap();

        println!("making srs");
        let start = Instant::now();
        // pick d such that 3n < d < 4n, where n is the number of multiplication gates in the instance
        // let d = 830564; // no idea why the original sonic code picked this magic number
        let d = (7 / 2) * 1562; // 3.5*n for Pedersen with 384-bit input
        let _srs2 = SRS::<Bls12>::dummy(d, srs_x, srs_alpha);
        println!("done in {:?}", start.elapsed());
    }
}
