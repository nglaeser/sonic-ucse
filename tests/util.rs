#[cfg(test)]
mod tests {
    extern crate sonic_ucse;

    use sonic_ucse::util::*;
    #[test]
    fn test_byte_arr_to_bool_arr() {
        let bytes = [106u8, 11u8];
        let mut buf = [false; 2 * 8];
        byte_arr_to_bool_arr(&bytes, 2, &mut buf);
        assert_eq!(
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
}
