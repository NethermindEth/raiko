//! Direct secp256k1 field and scalar arithmetic via ziskos syscall_arith256_mod.
//!
//! All operations use `d = a·b + c mod m` (single syscall each).

use ziskos::syscalls::{syscall_arith256_mod, SyscallArith256ModParams};

// ========================= Constants =========================

/// secp256k1 base-field prime p (little-endian u64 limbs).
const P: [u64; 4] = [
    0xFFFFFFFE_FFFFFC2F,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_FFFFFFFF,
];

/// p − 1  (used for negation: (p-1)·x ≡ -x mod p).
const P_MINUS_ONE: [u64; 4] = [
    0xFFFFFFFE_FFFFFC2E,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_FFFFFFFF,
];

/// secp256k1 scalar-field order n (little-endian u64 limbs).
const N: [u64; 4] = [
    0xBFD25E8C_D0364141,
    0xBAAEDCE6_AF48A03B,
    0xFFFFFFFF_FFFFFFFE,
    0xFFFFFFFF_FFFFFFFF,
];

/// n − 1  (used for negation: (n-1)·x ≡ -x mod n).
const N_MINUS_ONE: [u64; 4] = [
    0xBFD25E8C_D0364140,
    0xBAAEDCE6_AF48A03B,
    0xFFFFFFFF_FFFFFFFE,
    0xFFFFFFFF_FFFFFFFF,
];

const ONE: [u64; 4] = [1, 0, 0, 0];
const ZERO: [u64; 4] = [0; 4];

// ========================= Core syscall wrapper =========================

/// d = (a · b + c) mod m  via a single `arith256_mod` syscall.
#[inline]
fn arith_mod(a: &[u64; 4], b: &[u64; 4], c: &[u64; 4], m: &[u64; 4]) -> [u64; 4] {
    let mut d = [0u64; 4];
    let mut params = SyscallArith256ModParams {
        a,
        b,
        c,
        module: m,
        d: &mut d,
    };
    syscall_arith256_mod(&mut params);
    d
}

// ========================= Field operations (mod P) =========================

/// Field reduce: x mod P.
#[inline]
pub(crate) fn fp_reduce(x: &[u64; 4]) -> [u64; 4] {
    arith_mod(x, &ONE, &ZERO, &P)
}

/// Field add: (x + y) mod P.
#[inline]
pub(crate) fn fp_add(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    arith_mod(x, &ONE, y, &P)
}

/// Field negate: (-x) mod P.
#[inline]
pub(crate) fn fp_negate(x: &[u64; 4]) -> [u64; 4] {
    arith_mod(&P_MINUS_ONE, x, &ZERO, &P)
}

/// Field multiply: (x * y) mod P.
#[inline]
pub(crate) fn fp_mul(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    arith_mod(x, y, &ZERO, &P)
}

/// Field multiply by small scalar: (x * s) mod P.
#[inline]
pub(crate) fn fp_mul_scalar(x: &[u64; 4], s: u64) -> [u64; 4] {
    let sv = [s, 0, 0, 0];
    arith_mod(x, &sv, &ZERO, &P)
}

// ========================= Scalar operations (mod N) =========================

/// Scalar reduce: x mod N.
#[inline]
pub(crate) fn fn_reduce(x: &[u64; 4]) -> [u64; 4] {
    arith_mod(x, &ONE, &ZERO, &N)
}

/// Scalar add: (x + y) mod N.
#[inline]
pub(crate) fn fn_add(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    arith_mod(x, &ONE, y, &N)
}

/// Scalar negate: (-x) mod N.
#[inline]
pub(crate) fn fn_negate(x: &[u64; 4]) -> [u64; 4] {
    arith_mod(&N_MINUS_ONE, x, &ZERO, &N)
}

/// Scalar subtract: (x - y) mod N.
#[inline]
pub(crate) fn fn_sub(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    // (N-1)·y + x mod N  =  -y + x  =  x - y  mod N
    arith_mod(&N_MINUS_ONE, y, x, &N)
}

/// Scalar multiply: (x * y) mod N.
#[inline]
pub(crate) fn fn_mul(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    arith_mod(x, y, &ZERO, &N)
}
