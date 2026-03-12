
extern "C" {
    // Field operations
    pub fn secp256k1_fp_reduce_c(x_ptr: *const u64, out_ptr: *mut u64);
    pub fn secp256k1_fp_add_c(x_ptr: *const u64, y_ptr: *const u64, out_ptr: *mut u64);
    pub fn secp256k1_fp_negate_c(x_ptr: *const u64, out_ptr: *mut u64);
    pub fn secp256k1_fp_mul_c(x_ptr: *const u64, y_ptr: *const u64, out_ptr: *mut u64);
    pub fn secp256k1_fp_mul_scalar_c(x_ptr: *const u64, scalar: u64, out_ptr: *mut u64);

    // Scalar operations
    pub fn secp256k1_fn_reduce_c(x_ptr: *const u64, out_ptr: *mut u64);
    pub fn secp256k1_fn_add_c(x_ptr: *const u64, y_ptr: *const u64, out_ptr: *mut u64);
    pub fn secp256k1_fn_neg_c(x_ptr: *const u64, out_ptr: *mut u64);
    pub fn secp256k1_fn_sub_c(x_ptr: *const u64, y_ptr: *const u64, out_ptr: *mut u64);
    pub fn secp256k1_fn_mul_c(x_ptr: *const u64, y_ptr: *const u64, out_ptr: *mut u64);
    pub fn secp256k1_fn_inv_c(x_ptr: *const u64, out_ptr: *mut u64);

    // Curve operation
    pub fn secp256k1_to_affine_c(p_ptr: *const u64, out_ptr: *mut u64);
    pub fn secp256k1_decompress_c(x_bytes_ptr: *const u8, y_is_odd: u8, out_ptr: *mut u64) -> u8;
    pub fn secp256k1_double_scalar_mul_with_g_c(k1_ptr: *const u64, k2_ptr: *const u64, p_ptr: *const u64, out_ptr: *mut u64) -> bool;
    pub fn secp256k1_ecdsa_verify_c(pk_ptr: *const u64, z_ptr: *const u64, r_ptr: *const u64, s_ptr: *const u64) -> bool;
}