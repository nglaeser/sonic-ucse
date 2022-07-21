#[cfg(test)]
mod tests {
    extern crate sonic_ucse;

    use sonic_ucse::util::*;
    #[test]
    fn test_byte_arr_to_be_arr() {
        // assert_eq!([0b1011], byte_vec_to_bool_vec([11u8]));
        let bytes = [106u8, 11u8];
        let mut buf = [false; 2 * 8];
        byte_arr_to_be_arr(&bytes, 2, &mut buf);
        assert_eq!(
            // vec![0b01101010, 0b1011],
            [
                false, true, true, false, true, false, true, false, //
                false, false, false, false, true, false, true, true
            ],
            buf
        );
    }

    #[test]
    fn test_le_bytes_to_le_bits() {
        let bytes = [106u8, 11u8];
        let bytes_le = bytes.iter().rev().map(|x| *x).collect::<Vec<u8>>();

        let mut buf = [false; 2 * 8];
        le_bytes_to_le_bits(&bytes_le, 2, &mut buf);

        assert_eq!(
            [
                true, true, false, true, false, false, false, false, //
                false, true, false, true, false, true, true, false
            ],
            buf
        );

        let bytes_le = [2u8, 0u8, 0u8, 0u8];

        let mut buf = [false; 4 * 8];
        le_bytes_to_le_bits(&bytes_le, 4, &mut buf);
        assert_eq!(
            [
                false, true, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
                false, false, false, false, false, false, false, false, //
            ],
            buf
        );
    }

    #[test]
    fn test_byte_arr_to_le_bool_arr() {
        let bytes = [106u8, 11u8];
        let bytes_le = bytes.iter().rev().map(|x| *x).collect::<Vec<u8>>();
        assert_eq!(vec![11u8, 106u8], bytes_le);

        assert_eq!(0b10000000 >> 1, 0b01000000);
        assert!(!((0b10000000 >> 1) & 128u8 != 0u8));

        let mut buf = [false; 2 * 8];
        byte_arr_to_bool_arr(&bytes_le, 2, &mut buf);

        assert_eq!(
            [
                false, false, false, false, true, false, true, true, //
                false, true, true, false, true, false, true, false,
            ],
            buf
        );
    }

    #[test]
    fn test_le_bytes_to_sapling_scalar() {
        use pairing::PrimeFieldRepr;
        use rand::Rng;
        let bytes = rand::thread_rng().gen::<[u8; 32]>();
        let s_sapling = le_bytes_to_sapling_scalar(bytes);
        // let bytes2 = s_sapling
        //     .0
        //     .iter()
        //     .flat_map(|x| x.to_be_bytes())
        //     .collect::<Vec<u8>>();
        let mut bytes2: [u8; 32] = [0; 32];
        s_sapling.write_be(bytes2.as_mut_slice());
        let mut bytes2_le = [0; 32];
        let mut i = 0;
        for byte in bytes2.iter().rev() {
            bytes2_le[i] = *byte;
            i += 1;
        }

        assert_eq!(bytes.as_slice(), bytes2_le.as_slice());
    }
}
