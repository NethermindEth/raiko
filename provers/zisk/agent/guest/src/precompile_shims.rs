//! Shims bridging zisk-0.15.0 patched crates -> ziskos 0.16.0 syscall/fcall API.
//!
//! The patched crates (zisk-patch-hashes, zisk-patch-elliptic-curves, etc.) at
//! tag zisk-0.15.0 expect `#[no_mangle] extern "C"` symbols that were provided
//! by ziskos 0.15.0. In ziskos 0.16.0 (rev 6668726) the internal API changed:
//!   - SHA-256: `sha256f_compress_c` -> `syscall_sha256_f` (different calling convention)
//!   - secp256k1 field/scalar ops: now use `syscall_arith256_mod` (modular a*b+c)
//!   - secp256k1 fn_inv: now uses fcall mechanism
//!   - secp256k1 curve ops: now use higher-level zisklib functions
//!
//! This module provides the missing symbols by delegating to the new API.

use ziskos::syscalls::{
    syscall_arith256_mod, syscall_sha256_f, SyscallArith256ModParams, SyscallSha256Params,
};
use ziskos::zisklib::{
    fcall_secp256k1_fn_inv, fcall_secp256k1_fp_inv, secp256k1_double_scalar_mul_with_g,
    secp256k1_ecdsa_verify, secp256k1_lift_x, ZERO_256,
};

// secp256k1 constants (private in ziskos, so we must define them locally).
// Source: ziskos/entrypoint/src/zisklib/lib/secp256k1/constants.rs at rev 6668726.

/// secp256k1 base field modulus: p = 2^256 - 2^32 - 977
const P: [u64; 4] = [
    0xFFFFFFFEFFFFFC2F,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
    0xFFFFFFFFFFFFFFFF,
];
const P_MINUS_ONE: [u64; 4] = [P[0] - 1, P[1], P[2], P[3]];

/// secp256k1 scalar field order
const N: [u64; 4] = [
    0xBFD25E8CD0364141,
    0xBAAEDCE6AF48A03B,
    0xFFFFFFFFFFFFFFFE,
    0xFFFFFFFFFFFFFFFF,
];
const N_MINUS_ONE: [u64; 4] = [N[0] - 1, N[1], N[2], N[3]];

const ONE: [u64; 4] = [1, 0, 0, 0];

// ========================= SHA-256 =========================

/// Signature expected by zisk-patch-hashes 0.15.0:
///   `sha256f_compress_c(state_ptr: *mut u32, blocks_ptr: *const u8, num_blocks: usize)`
///
/// Delegates to ziskos 0.16.0 `syscall_sha256_f` one block at a time.
#[no_mangle]
pub unsafe extern "C" fn sha256f_compress_c(
    state_ptr: *mut u32,
    blocks_ptr: *const u8,
    num_blocks: usize,
) {
    let state = &mut *(state_ptr as *mut [u64; 4]);
    for i in 0..num_blocks {
        let block = &*(blocks_ptr.add(i * 64) as *const [u64; 8]);
        let mut params = SyscallSha256Params { state, input: block };
        syscall_sha256_f(&mut params);
    }
}

// ========================= secp256k1 field ops (mod P) =========================

/// d = (x * 1 + 0) mod P
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fp_reduce_c(x_ptr: *const u64, out_ptr: *mut u64) {
    let x = &*(x_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    let mut params = SyscallArith256ModParams {
        a: x, b: &ONE, c: &ZERO_256, module: &P, d: out,
    };
    syscall_arith256_mod(&mut params);
}

/// d = (x * 1 + y) mod P
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fp_add_c(
    x_ptr: *const u64, y_ptr: *const u64, out_ptr: *mut u64,
) {
    let x = &*(x_ptr as *const [u64; 4]);
    let y = &*(y_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    let mut params = SyscallArith256ModParams {
        a: x, b: &ONE, c: y, module: &P, d: out,
    };
    syscall_arith256_mod(&mut params);
}

/// d = (x * (P-1) + 0) mod P  =  -x mod P
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fp_negate_c(x_ptr: *const u64, out_ptr: *mut u64) {
    let x = &*(x_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    let mut params = SyscallArith256ModParams {
        a: x, b: &P_MINUS_ONE, c: &ZERO_256, module: &P, d: out,
    };
    syscall_arith256_mod(&mut params);
}

/// d = (x * y + 0) mod P
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fp_mul_c(
    x_ptr: *const u64, y_ptr: *const u64, out_ptr: *mut u64,
) {
    let x = &*(x_ptr as *const [u64; 4]);
    let y = &*(y_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    let mut params = SyscallArith256ModParams {
        a: x, b: y, c: &ZERO_256, module: &P, d: out,
    };
    syscall_arith256_mod(&mut params);
}

/// d = (x * [scalar, 0, 0, 0] + 0) mod P
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fp_mul_scalar_c(
    x_ptr: *const u64, scalar: u64, out_ptr: *mut u64,
) {
    let x = &*(x_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    let s = [scalar, 0, 0, 0];
    let mut params = SyscallArith256ModParams {
        a: x, b: &s, c: &ZERO_256, module: &P, d: out,
    };
    syscall_arith256_mod(&mut params);
}

// ========================= secp256k1 scalar ops (mod N) =========================

/// d = (x * 1 + 0) mod N
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fn_reduce_c(x_ptr: *const u64, out_ptr: *mut u64) {
    let x = &*(x_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    let mut params = SyscallArith256ModParams {
        a: x, b: &ONE, c: &ZERO_256, module: &N, d: out,
    };
    syscall_arith256_mod(&mut params);
}

/// d = (x * 1 + y) mod N
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fn_add_c(
    x_ptr: *const u64, y_ptr: *const u64, out_ptr: *mut u64,
) {
    let x = &*(x_ptr as *const [u64; 4]);
    let y = &*(y_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    let mut params = SyscallArith256ModParams {
        a: x, b: &ONE, c: y, module: &N, d: out,
    };
    syscall_arith256_mod(&mut params);
}

/// d = (x * (N-1) + 0) mod N  =  -x mod N
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fn_neg_c(x_ptr: *const u64, out_ptr: *mut u64) {
    let x = &*(x_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    let mut params = SyscallArith256ModParams {
        a: x, b: &N_MINUS_ONE, c: &ZERO_256, module: &N, d: out,
    };
    syscall_arith256_mod(&mut params);
}

/// d = (y * (N-1) + x) mod N  =  x - y mod N
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fn_sub_c(
    x_ptr: *const u64, y_ptr: *const u64, out_ptr: *mut u64,
) {
    let x = &*(x_ptr as *const [u64; 4]);
    let y = &*(y_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    let mut params = SyscallArith256ModParams {
        a: y, b: &N_MINUS_ONE, c: x, module: &N, d: out,
    };
    syscall_arith256_mod(&mut params);
}

/// d = (x * y + 0) mod N
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fn_mul_c(
    x_ptr: *const u64, y_ptr: *const u64, out_ptr: *mut u64,
) {
    let x = &*(x_ptr as *const [u64; 4]);
    let y = &*(y_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    let mut params = SyscallArith256ModParams {
        a: x, b: y, c: &ZERO_256, module: &N, d: out,
    };
    syscall_arith256_mod(&mut params);
}

/// Scalar field multiplicative inverse via ziskos fcall.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fn_inv_c(x_ptr: *const u64, out_ptr: *mut u64) {
    let x = &*(x_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    *out = fcall_secp256k1_fn_inv(x);
}

// ========================= secp256k1 curve ops =========================

/// Projective -> affine: (x, y, z) -> (x/z^2, y/z^3).
/// Input: 12 u64 limbs [x(4), y(4), z(4)], Output: 8 u64 limbs [x(4), y(4)].
#[no_mangle]
pub unsafe extern "C" fn secp256k1_to_affine_c(p_ptr: *const u64, out_ptr: *mut u64) {
    let px = &*(p_ptr as *const [u64; 4]);
    let py = &*((p_ptr.add(4)) as *const [u64; 4]);
    let pz = &*((p_ptr.add(8)) as *const [u64; 4]);

    let z_inv = fcall_secp256k1_fp_inv(pz);

    // z_inv2 = z_inv^2 mod P
    let mut z_inv2 = [0u64; 4];
    let mut params = SyscallArith256ModParams {
        a: &z_inv, b: &z_inv, c: &ZERO_256, module: &P, d: &mut z_inv2,
    };
    syscall_arith256_mod(&mut params);

    // z_inv3 = z_inv2 * z_inv mod P
    let mut z_inv3 = [0u64; 4];
    let mut params = SyscallArith256ModParams {
        a: &z_inv2, b: &z_inv, c: &ZERO_256, module: &P, d: &mut z_inv3,
    };
    syscall_arith256_mod(&mut params);

    // out_x = px * z_inv2 mod P
    let out_x = &mut *(out_ptr as *mut [u64; 4]);
    let mut params = SyscallArith256ModParams {
        a: px, b: &z_inv2, c: &ZERO_256, module: &P, d: out_x,
    };
    syscall_arith256_mod(&mut params);

    // out_y = py * z_inv3 mod P
    let out_y = &mut *((out_ptr.add(4)) as *mut [u64; 4]);
    let mut params = SyscallArith256ModParams {
        a: py, b: &z_inv3, c: &ZERO_256, module: &P, d: out_y,
    };
    syscall_arith256_mod(&mut params);
}

/// Decompress a secp256k1 point from its x-coordinate (32 big-endian bytes).
/// Returns 1 on success, 0 on failure.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_decompress_c(
    x_bytes_ptr: *const u8, y_is_odd: u8, out_ptr: *mut u64,
) -> u8 {
    let x_bytes = core::slice::from_raw_parts(x_bytes_ptr, 32);
    let x = bytes_be_to_u64_le(x_bytes);

    match secp256k1_lift_x(&x, y_is_odd != 0) {
        Ok(point) => {
            let out = core::slice::from_raw_parts_mut(out_ptr, 8);
            out.copy_from_slice(&point);
            1
        }
        Err(_) => 0,
    }
}

/// Double scalar multiplication: k1*G + k2*P.
/// Returns true if the result is not the point at infinity.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_double_scalar_mul_with_g_c(
    k1_ptr: *const u64, k2_ptr: *const u64, p_ptr: *const u64, out_ptr: *mut u64,
) -> bool {
    let k1 = &*(k1_ptr as *const [u64; 4]);
    let k2 = &*(k2_ptr as *const [u64; 4]);
    let p = &*(p_ptr as *const [u64; 8]);

    match secp256k1_double_scalar_mul_with_g(k1, k2, p) {
        Some(result) => {
            let out = &mut *(out_ptr as *mut [u64; 8]);
            *out = result;
            true
        }
        None => false,
    }
}

/// ECDSA verification. Returns true if signature (r, s) over hash z is valid for pk.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_ecdsa_verify_c(
    pk_ptr: *const u64, z_ptr: *const u64, r_ptr: *const u64, s_ptr: *const u64,
) -> bool {
    let pk = &*(pk_ptr as *const [u64; 8]);
    let z = &*(z_ptr as *const [u64; 4]);
    let r = &*(r_ptr as *const [u64; 4]);
    let s = &*(s_ptr as *const [u64; 4]);

    secp256k1_ecdsa_verify(pk, z, r, s)
}

// ========================= Helpers =========================

fn bytes_be_to_u64_le(bytes: &[u8]) -> [u64; 4] {
    let mut result = [0u64; 4];
    for i in 0..4 {
        for j in 0..8 {
            result[3 - i] |= (bytes[i * 8 + j] as u64) << (8 * (7 - j));
        }
    }
    result
}
