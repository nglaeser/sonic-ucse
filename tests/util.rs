#[cfg(test)]
mod tests {
    extern crate sonic_ucse;

    use sonic_ucse::util::*;
    #[test]
    fn test_byte_vec_to_bool_vec() {
        // assert_eq!([0b1011], byte_vec_to_bool_vec([11u8]));
        let bytes = [106u8, 11u8];
        let mut buf = [false; 2 * 8];
        byte_arr_to_be_arr(&bytes, 2, &mut buf);
        assert_eq!(
            // vec![0b01101010, 0b1011],
            [
                false, true, true, false, true, false, true, false, false, false, false, false,
                true, false, true, true
            ],
            buf
        );
    }
}
