//! Shims bridging zisk-0.15.0 patched crates → ziskos 0.16.0 syscall API.
//!
//! All operations use **only** `syscall_arith256_mod` (d = a·b + c mod m).
//! EC operations use **Jacobian coordinates** internally so that point
//! addition / doubling never require modular inversions (~15-17 arith_mod
//! calls each).  A single inversion is performed at the end to convert
//! back to affine, reducing total syscalls per ecrecover from ~150 K
//! (affine approach) to ~7 K.
//!
//! NO fcalls, NO secp256k1_add/dbl syscalls.

use ziskos::syscalls::{
    syscall_arith256_mod, syscall_sha256_f, SyscallArith256ModParams, SyscallSha256Params,
};

// ========================= Constants =========================

/// secp256k1 base-field prime p (little-endian u64 limbs).
const P: [u64; 4] = [
    0xFFFFFFFE_FFFFFC2F,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_FFFFFFFF,
];

/// p − 1
const P_MINUS_ONE: [u64; 4] = [
    0xFFFFFFFE_FFFFFC2E,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_FFFFFFFF,
];

/// p − 2  (Fermat inverse exponent for the base field).
const P_MINUS_TWO: [u64; 4] = [
    0xFFFFFFFE_FFFFFC2D,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_FFFFFFFF,
];

/// (p + 1) / 4  (square-root exponent; p ≡ 3 mod 4).
const P_PLUS_ONE_DIV_4: [u64; 4] = [
    0xFFFFFFFF_BFFFFF0C,
    0xFFFFFFFF_FFFFFFFF,
    0xFFFFFFFF_FFFFFFFF,
    0x3FFFFFFF_FFFFFFFF,
];

/// secp256k1 scalar-field order n.
const N: [u64; 4] = [
    0xBFD25E8C_D0364141,
    0xBAAEDCE6_AF48A03B,
    0xFFFFFFFF_FFFFFFFE,
    0xFFFFFFFF_FFFFFFFF,
];

/// n − 1
const N_MINUS_ONE: [u64; 4] = [
    0xBFD25E8C_D0364140,
    0xBAAEDCE6_AF48A03B,
    0xFFFFFFFF_FFFFFFFE,
    0xFFFFFFFF_FFFFFFFF,
];

/// n − 2  (Fermat inverse exponent for the scalar field).
const N_MINUS_TWO: [u64; 4] = [
    0xBFD25E8C_D036413F,
    0xBAAEDCE6_AF48A03B,
    0xFFFFFFFF_FFFFFFFE,
    0xFFFFFFFF_FFFFFFFF,
];

const ONE: [u64; 4] = [1, 0, 0, 0];
const ZERO_256: [u64; 4] = [0; 4];

/// Curve equation constant b: y² = x³ + 7
const E_B: [u64; 4] = [7, 0, 0, 0];

/// Generator x-coordinate (little-endian u64).
const G_X: [u64; 4] = [
    0x59F2815B_16F81798,
    0x029BFCDB_2DCE28D9,
    0x55A06295_CE870B07,
    0x79BE667E_F9DCBBAC,
];

/// Generator y-coordinate (little-endian u64).
const G_Y: [u64; 4] = [
    0x9C47D08F_FB10D4B8,
    0xFD17B448_A6855419,
    0x5DA4FBFC_0E1108A8,
    0x483ADA77_26A3C465,
];

// ========================= SHA-256 shim =========================

/// Signature expected by zisk-patch-hashes 0.15.0:
///   `sha256f_compress_c(state: *mut u32, blocks: *const u8, num_blocks: usize)`
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
        let mut params = SyscallSha256Params {
            state,
            input: block,
        };
        syscall_sha256_f(&mut params);
    }
}

// ========================= Internal helpers =========================

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

/// Modular exponentiation via binary square-and-multiply (LSB-first).
///
/// Returns `base^exp mod modulus`.
fn mod_pow(base: &[u64; 4], exp: &[u64; 4], modulus: &[u64; 4]) -> [u64; 4] {
    let mut result = ONE;
    let mut b = *base;
    for i in 0..4 {
        for bit in 0..64 {
            if (exp[i] >> bit) & 1 == 1 {
                result = arith_mod(&result, &b, &ZERO_256, modulus);
            }
            b = arith_mod(&b, &b, &ZERO_256, modulus);
        }
    }
    result
}

/// Field multiplicative inverse: a^(p−2) mod p.
#[inline]
fn fp_inv(a: &[u64; 4]) -> [u64; 4] {
    mod_pow(a, &P_MINUS_TWO, &P)
}

/// Scalar multiplicative inverse: a^(n−2) mod n.
#[inline]
fn fn_inv_internal(a: &[u64; 4]) -> [u64; 4] {
    mod_pow(a, &N_MINUS_TWO, &N)
}

/// Modular square root: a^((p+1)/4) mod p.
#[inline]
fn fp_sqrt(a: &[u64; 4]) -> [u64; 4] {
    mod_pow(a, &P_PLUS_ONE_DIV_4, &P)
}

#[inline]
fn is_zero_256(x: &[u64; 4]) -> bool {
    (x[0] | x[1] | x[2] | x[3]) == 0
}

#[inline]
fn eq_256(a: &[u64; 4], b: &[u64; 4]) -> bool {
    a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3]
}

/// Returns `(limb_index, bit_index)` of the most significant set bit.
/// Panics on zero.
fn msb_position(x: &[u64; 4]) -> (usize, usize) {
    for i in (0..4).rev() {
        if x[i] != 0 {
            return (i, 63 - x[i].leading_zeros() as usize);
        }
    }
    panic!("msb_position: zero input");
}

/// Maximum MSB position across two non-zero-together values.
fn msb_position_max(a: &[u64; 4], b: &[u64; 4]) -> (usize, usize) {
    let (al, ab) = if is_zero_256(a) {
        (0usize, 0usize)
    } else {
        msb_position(a)
    };
    let (bl, bb) = if is_zero_256(b) {
        (0usize, 0usize)
    } else {
        msb_position(b)
    };
    if al > bl || (al == bl && ab >= bb) {
        (al, ab)
    } else {
        (bl, bb)
    }
}

/// Convert 32 big-endian bytes → 4 little-endian u64 limbs.
fn bytes_be_to_u64_le(bytes: &[u8]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in 0..4 {
        for j in 0..8 {
            r[3 - i] |= (bytes[i * 8 + j] as u64) << (8 * (7 - j));
        }
    }
    r
}

/// Field subtraction: (a - b) mod p.
#[inline]
fn fp_sub(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    arith_mod(b, &P_MINUS_ONE, a, &P)
}

/// Field multiplication: (a * b) mod p.
#[inline]
fn fp_mul(a: &[u64; 4], b: &[u64; 4]) -> [u64; 4] {
    arith_mod(a, b, &ZERO_256, &P)
}

/// Field squaring: a² mod p.
#[inline]
fn fp_sqr(a: &[u64; 4]) -> [u64; 4] {
    arith_mod(a, a, &ZERO_256, &P)
}

/// EC point addition in affine coordinates (P1 ≠ P2, both non-identity).
/// secp256k1: y² = x³ + 7, a = 0.
///
/// λ = (y2 - y1) / (x2 - x1)
/// x3 = λ² - x1 - x2
/// y3 = λ(x1 - x3) - y1
fn ec_add_affine(p1x: &[u64; 4], p1y: &[u64; 4], p2x: &[u64; 4], p2y: &[u64; 4]) -> [u64; 8] {
    let dx = fp_sub(p2x, p1x);
    let dy = fp_sub(p2y, p1y);
    let dx_inv = fp_inv(&dx);
    let lambda = fp_mul(&dy, &dx_inv);
    let l2 = fp_sqr(&lambda);
    let x3 = fp_sub(&fp_sub(&l2, p1x), p2x);
    let diff = fp_sub(p1x, &x3);
    let y3 = fp_sub(&fp_mul(&lambda, &diff), p1y);
    [x3[0], x3[1], x3[2], x3[3], y3[0], y3[1], y3[2], y3[3]]
}

/// Scalar subtraction in the scalar field: (x − y) mod n.
fn fn_sub_internal(x: &[u64; 4], y: &[u64; 4]) -> [u64; 4] {
    arith_mod(y, &N_MINUS_ONE, x, &N)
}

// =================== Jacobian coordinate helpers ====================
//
// Jacobian:  (X, Y, Z)  with affine x = X/Z², y = Y/Z³.
// Identity is Z = 0.
// Avoids modular inversions during add/double (~15-17 arith_mod each).
// A single inversion is performed at the end to convert back to affine.

/// Affine [x(4), y(4)] → Jacobian [X(4), Y(4), Z(4)].
#[inline]
fn affine_to_jacobian(p: &[u64; 8]) -> [u64; 12] {
    [p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], 1, 0, 0, 0]
}

/// Check if a Jacobian point is identity (Z = 0).
#[inline]
fn jacobian_is_identity(p: &[u64; 12]) -> bool {
    (p[8] | p[9] | p[10] | p[11]) == 0
}

/// Jacobian → affine:  x = X·Z⁻²,  y = Y·Z⁻³.
fn jacobian_to_affine(p: &[u64; 12]) -> [u64; 8] {
    let x = [p[0], p[1], p[2], p[3]];
    let y = [p[4], p[5], p[6], p[7]];
    let z = [p[8], p[9], p[10], p[11]];
    let z_inv = fp_inv(&z);
    let z_inv2 = fp_sqr(&z_inv);
    let z_inv3 = fp_mul(&z_inv2, &z_inv);
    let ax = fp_mul(&x, &z_inv2);
    let ay = fp_mul(&y, &z_inv3);
    [ax[0], ax[1], ax[2], ax[3], ay[0], ay[1], ay[2], ay[3]]
}

/// EC point doubling in Jacobian coordinates for secp256k1 (a = 0).
///
/// M = 3·X₁²,  S = 4·X₁·Y₁²
/// X₃ = M² − 2·S
/// Y₃ = M·(S − X₃) − 8·Y₁⁴
/// Z₃ = 2·Y₁·Z₁
///
/// Cost: ~15 arith_mod (no inversion).
fn ec_dbl_jacobian(p: &[u64; 12]) -> [u64; 12] {
    let x1 = [p[0], p[1], p[2], p[3]];
    let y1 = [p[4], p[5], p[6], p[7]];
    let z1 = [p[8], p[9], p[10], p[11]];

    let x1_sq = fp_sqr(&x1);
    let m = arith_mod(&x1_sq, &[3, 0, 0, 0], &ZERO_256, &P);
    let y1_sq = fp_sqr(&y1);
    let xy2 = fp_mul(&x1, &y1_sq);
    let s = arith_mod(&xy2, &[4, 0, 0, 0], &ZERO_256, &P);
    let m_sq = fp_sqr(&m);
    let two_s = arith_mod(&s, &[2, 0, 0, 0], &ZERO_256, &P);
    let x3 = fp_sub(&m_sq, &two_s);
    let s_x3 = fp_sub(&s, &x3);
    let y1_4 = fp_sqr(&y1_sq);
    let eight_y1_4 = arith_mod(&y1_4, &[8, 0, 0, 0], &ZERO_256, &P);
    let y3 = fp_sub(&fp_mul(&m, &s_x3), &eight_y1_4);
    let yz = fp_mul(&y1, &z1);
    let z3 = arith_mod(&yz, &[2, 0, 0, 0], &ZERO_256, &P);

    [
        x3[0], x3[1], x3[2], x3[3], y3[0], y3[1], y3[2], y3[3], z3[0], z3[1], z3[2], z3[3],
    ]
}

/// Mixed Jacobian–affine addition:  Jac(X₁,Y₁,Z₁) + Aff(x₂,y₂) → Jac.
///
/// H = x₂·Z₁² − X₁,  R = y₂·Z₁³ − Y₁
/// X₃ = R² − H³ − 2·X₁·H²
/// Y₃ = R·(X₁·H² − X₃) − Y₁·H³
/// Z₃ = Z₁·H
///
/// Falls back to doubling when H = 0 ∧ R = 0 (same point).
/// Returns identity ([0;12]) when H = 0 ∧ R ≠ 0 (negation).
///
/// Cost: ~17 arith_mod (no inversion).
fn ec_add_mixed(jac: &[u64; 12], ax: &[u64; 4], ay: &[u64; 4]) -> [u64; 12] {
    let x1 = [jac[0], jac[1], jac[2], jac[3]];
    let y1 = [jac[4], jac[5], jac[6], jac[7]];
    let z1 = [jac[8], jac[9], jac[10], jac[11]];

    let z1_sq = fp_sqr(&z1);
    let z1_cu = fp_mul(&z1_sq, &z1);
    let u2 = fp_mul(ax, &z1_sq);
    let s2 = fp_mul(ay, &z1_cu);
    let h = fp_sub(&u2, &x1);
    let r = fp_sub(&s2, &y1);

    if is_zero_256(&h) {
        return if is_zero_256(&r) {
            ec_dbl_jacobian(jac) // same point → double
        } else {
            [0u64; 12] // negation → identity
        };
    }

    let h_sq = fp_sqr(&h);
    let h_cu = fp_mul(&h_sq, &h);
    let x1h2 = fp_mul(&x1, &h_sq);
    let r_sq = fp_sqr(&r);
    // H³ + 2·X₁·H²  via MAC:  (X₁·H² × 2 + H³) mod P
    let rhs = arith_mod(&x1h2, &[2, 0, 0, 0], &h_cu, &P);
    let x3 = fp_sub(&r_sq, &rhs);
    let diff = fp_sub(&x1h2, &x3);
    let r_diff = fp_mul(&r, &diff);
    let y1h3 = fp_mul(&y1, &h_cu);
    let y3 = fp_sub(&r_diff, &y1h3);
    let z3 = fp_mul(&z1, &h);

    [
        x3[0], x3[1], x3[2], x3[3], y3[0], y3[1], y3[2], y3[3], z3[0], z3[1], z3[2], z3[3],
    ]
}

/// Scalar multiplication: k · P.  Returns `None` when the result is identity.
///
/// Uses Jacobian coordinates internally — single inversion at the end.
fn scalar_mul_internal(k: &[u64; 4], p: &[u64; 8]) -> Option<[u64; 8]> {
    if is_zero_256(k) {
        return None;
    }

    let (max_limb, max_bit) = msb_position(k);

    // k == 1 → just return P
    if max_limb == 0 && max_bit == 0 {
        return Some(*p);
    }

    let px = [p[0], p[1], p[2], p[3]];
    let py = [p[4], p[5], p[6], p[7]];

    // Accumulator starts at P in Jacobian (MSB is always 1)
    let mut jac = affine_to_jacobian(p);
    let mut is_id = false;
    let msb_pos = max_limb * 64 + max_bit;

    for bit_idx in (0..msb_pos).rev() {
        let limb = bit_idx / 64;
        let bit = bit_idx % 64;

        // Double
        if !is_id {
            jac = ec_dbl_jacobian(&jac);
            is_id = jacobian_is_identity(&jac);
        }

        // Conditionally add P
        if (k[limb] >> bit) & 1 == 1 {
            if is_id {
                jac = affine_to_jacobian(p);
                is_id = false;
            } else {
                jac = ec_add_mixed(&jac, &px, &py);
                is_id = jacobian_is_identity(&jac);
            }
        }
    }

    if is_id {
        None
    } else {
        Some(jacobian_to_affine(&jac))
    }
}

/// Double scalar multiplication  k1·G + k2·P  (Shamir's trick).
///
/// Lookup table {G, P, G+P} is kept in affine; accumulator runs in
/// Jacobian.  Only **one** modular inversion at the end.
fn double_scalar_mul_internal(k1: &[u64; 4], k2: &[u64; 4], p: &[u64; 8]) -> Option<[u64; 8]> {
    if is_zero_256(k1) && is_zero_256(k2) {
        return None;
    }
    if is_zero_256(k1) {
        return scalar_mul_internal(k2, p);
    }
    if is_zero_256(k2) {
        let g = [
            G_X[0], G_X[1], G_X[2], G_X[3], G_Y[0], G_Y[1], G_Y[2], G_Y[3],
        ];
        return scalar_mul_internal(k1, &g);
    }

    let px = [p[0], p[1], p[2], p[3]];
    let py = [p[4], p[5], p[6], p[7]];

    // Handle degenerate cases where P shares the same x-coordinate as G.
    if eq_256(&G_X, &px) {
        if eq_256(&G_Y, &py) {
            // P == G → (k1+k2)·G
            let sum = arith_mod(k1, &ONE, k2, &N);
            let g = [
                G_X[0], G_X[1], G_X[2], G_X[3], G_Y[0], G_Y[1], G_Y[2], G_Y[3],
            ];
            return scalar_mul_internal(&sum, &g);
        } else {
            // P == −G → (k1−k2)·G
            let diff = fn_sub_internal(k1, k2);
            let g = [
                G_X[0], G_X[1], G_X[2], G_X[3], G_Y[0], G_Y[1], G_Y[2], G_Y[3],
            ];
            return scalar_mul_internal(&diff, &g);
        }
    }

    // Precompute G + P in affine (one inversion, amortised over ~256 loop iterations).
    let gp_aff = ec_add_affine(&G_X, &G_Y, &px, &py);
    let gp_x = [gp_aff[0], gp_aff[1], gp_aff[2], gp_aff[3]];
    let gp_y = [gp_aff[4], gp_aff[5], gp_aff[6], gp_aff[7]];

    // Both scalars == 1 → G + P
    if eq_256(k1, &ONE) && eq_256(k2, &ONE) {
        return Some(gp_aff);
    }

    // ---------- Shamir's trick: Jacobian accumulator, affine table ----------
    let (max_limb, max_bit) = msb_position_max(k1, k2);
    let k1_msb = (k1[max_limb] >> max_bit) & 1;
    let k2_msb = (k2[max_limb] >> max_bit) & 1;

    let g_aff = [
        G_X[0], G_X[1], G_X[2], G_X[3], G_Y[0], G_Y[1], G_Y[2], G_Y[3],
    ];

    let mut jac = [0u64; 12];
    let mut is_id = true;
    match (k1_msb, k2_msb) {
        (0, 1) => {
            jac = affine_to_jacobian(p);
            is_id = false;
        }
        (1, 0) => {
            jac = affine_to_jacobian(&g_aff);
            is_id = false;
        }
        (1, 1) => {
            jac = affine_to_jacobian(&gp_aff);
            is_id = false;
        }
        _ => {}
    }

    let msb_pos = max_limb * 64 + max_bit;
    for bit_idx in (0..msb_pos).rev() {
        let limb = bit_idx / 64;
        let bit = bit_idx % 64;
        let k1_b = (k1[limb] >> bit) & 1;
        let k2_b = (k2[limb] >> bit) & 1;

        // Double the accumulator
        if !is_id {
            jac = ec_dbl_jacobian(&jac);
            is_id = jacobian_is_identity(&jac);
        }

        // Add table entry for this bit-pair
        match (k1_b, k2_b) {
            (0, 0) => { /* nothing */ }
            (0, 1) => {
                if is_id {
                    jac = affine_to_jacobian(p);
                    is_id = false;
                } else {
                    jac = ec_add_mixed(&jac, &px, &py);
                    is_id = jacobian_is_identity(&jac);
                }
            }
            (1, 0) => {
                if is_id {
                    jac = affine_to_jacobian(&g_aff);
                    is_id = false;
                } else {
                    jac = ec_add_mixed(&jac, &G_X, &G_Y);
                    is_id = jacobian_is_identity(&jac);
                }
            }
            (1, 1) => {
                if is_id {
                    jac = affine_to_jacobian(&gp_aff);
                    is_id = false;
                } else {
                    jac = ec_add_mixed(&jac, &gp_x, &gp_y);
                    is_id = jacobian_is_identity(&jac);
                }
            }
            _ => unreachable!(),
        }
    }

    if is_id {
        None
    } else {
        Some(jacobian_to_affine(&jac))
    }
}

/// Standard ECDSA verification.
fn ecdsa_verify_internal(pk: &[u64; 8], z: &[u64; 4], r: &[u64; 4], s: &[u64; 4]) -> bool {
    if is_zero_256(r) || is_zero_256(s) {
        return false;
    }

    let s_inv = fn_inv_internal(s);
    let u1 = arith_mod(z, &s_inv, &ZERO_256, &N);
    let u2 = arith_mod(r, &s_inv, &ZERO_256, &N);

    match double_scalar_mul_internal(&u1, &u2, pk) {
        None => false,
        Some(r_point) => {
            let rx = [r_point[0], r_point[1], r_point[2], r_point[3]];
            let rx_mod_n = arith_mod(&rx, &ONE, &ZERO_256, &N);
            eq_256(&rx_mod_n, r)
        }
    }
}

// ========================= secp256k1 field ops (mod P) =========================

/// d = (x · 1 + 0) mod P — field reduction.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fp_reduce_c(x_ptr: *const u64, out_ptr: *mut u64) {
    let x = &*(x_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    *out = arith_mod(x, &ONE, &ZERO_256, &P);
}

/// d = (x · 1 + y) mod P — field addition.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fp_add_c(
    x_ptr: *const u64,
    y_ptr: *const u64,
    out_ptr: *mut u64,
) {
    let x = &*(x_ptr as *const [u64; 4]);
    let y = &*(y_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    *out = arith_mod(x, &ONE, y, &P);
}

/// d = x · (P−1) mod P  =  −x mod P — field negation.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fp_negate_c(x_ptr: *const u64, out_ptr: *mut u64) {
    let x = &*(x_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    *out = arith_mod(x, &P_MINUS_ONE, &ZERO_256, &P);
}

/// d = (x · y + 0) mod P — field multiplication.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fp_mul_c(
    x_ptr: *const u64,
    y_ptr: *const u64,
    out_ptr: *mut u64,
) {
    let x = &*(x_ptr as *const [u64; 4]);
    let y = &*(y_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    *out = arith_mod(x, y, &ZERO_256, &P);
}

/// d = (x · scalar + 0) mod P — field scalar multiplication.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fp_mul_scalar_c(
    x_ptr: *const u64,
    scalar: u64,
    out_ptr: *mut u64,
) {
    let x = &*(x_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    let s = [scalar, 0, 0, 0];
    *out = arith_mod(x, &s, &ZERO_256, &P);
}

// ========================= secp256k1 scalar ops (mod N) =========================

/// d = (x · 1 + 0) mod N — scalar reduction.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fn_reduce_c(x_ptr: *const u64, out_ptr: *mut u64) {
    let x = &*(x_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    *out = arith_mod(x, &ONE, &ZERO_256, &N);
}

/// d = (x · 1 + y) mod N — scalar addition.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fn_add_c(
    x_ptr: *const u64,
    y_ptr: *const u64,
    out_ptr: *mut u64,
) {
    let x = &*(x_ptr as *const [u64; 4]);
    let y = &*(y_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    *out = arith_mod(x, &ONE, y, &N);
}

/// d = x · (N−1) mod N  =  −x mod N — scalar negation.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fn_neg_c(x_ptr: *const u64, out_ptr: *mut u64) {
    let x = &*(x_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    *out = arith_mod(x, &N_MINUS_ONE, &ZERO_256, &N);
}

/// d = y · (N−1) + x  mod N  =  x − y  mod N — scalar subtraction.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fn_sub_c(
    x_ptr: *const u64,
    y_ptr: *const u64,
    out_ptr: *mut u64,
) {
    let x = &*(x_ptr as *const [u64; 4]);
    let y = &*(y_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    *out = arith_mod(y, &N_MINUS_ONE, x, &N);
}

/// d = (x · y + 0) mod N — scalar multiplication.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fn_mul_c(
    x_ptr: *const u64,
    y_ptr: *const u64,
    out_ptr: *mut u64,
) {
    let x = &*(x_ptr as *const [u64; 4]);
    let y = &*(y_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    *out = arith_mod(x, y, &ZERO_256, &N);
}

/// Scalar inverse via Fermat's little theorem: x^(n−2) mod n.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_fn_inv_c(x_ptr: *const u64, out_ptr: *mut u64) {
    let x = &*(x_ptr as *const [u64; 4]);
    let out = &mut *(out_ptr as *mut [u64; 4]);
    *out = fn_inv_internal(x);
}

// ========================= secp256k1 curve ops =========================

/// Projective → affine conversion.
///
/// k256 uses **standard** (homogeneous) projective coordinates:
///   affine = (X/Z, Y/Z)
///
/// Input:  12 u64 limbs  [X(4), Y(4), Z(4)]
/// Output:  8 u64 limbs  [x(4), y(4)]
#[no_mangle]
pub unsafe extern "C" fn secp256k1_to_affine_c(p_ptr: *const u64, out_ptr: *mut u64) {
    let px = &*(p_ptr as *const [u64; 4]);
    let py = &*((p_ptr.add(4)) as *const [u64; 4]);
    let pz = &*((p_ptr.add(8)) as *const [u64; 4]);

    let z_inv = fp_inv(pz);

    let out_x = &mut *(out_ptr as *mut [u64; 4]);
    *out_x = arith_mod(px, &z_inv, &ZERO_256, &P);

    let out_y = &mut *((out_ptr.add(4)) as *mut [u64; 4]);
    *out_y = arith_mod(py, &z_inv, &ZERO_256, &P);
}

/// Decompress a secp256k1 point from its x-coordinate (32 big-endian bytes)
/// and a parity flag.  Returns 1 on success, 0 on failure.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_decompress_c(
    x_bytes_ptr: *const u8,
    y_is_odd: u8,
    out_ptr: *mut u64,
) -> u8 {
    let x_bytes = core::slice::from_raw_parts(x_bytes_ptr, 32);
    let x = bytes_be_to_u64_le(x_bytes);

    // y² = x³ + 7
    let x_sq = arith_mod(&x, &x, &ZERO_256, &P);
    let x_cb = arith_mod(&x_sq, &x, &ZERO_256, &P);
    let y_sq = arith_mod(&x_cb, &ONE, &E_B, &P);

    // Candidate y = y_sq^((p+1)/4) mod p
    let y = fp_sqrt(&y_sq);

    // Verify: y² must equal y_sq (otherwise not a quadratic residue)
    let check = arith_mod(&y, &y, &ZERO_256, &P);
    if !eq_256(&check, &y_sq) {
        return 0;
    }

    // Fix parity
    let parity = (y[0] & 1) as u8;
    let final_y = if parity != y_is_odd {
        arith_mod(&y, &P_MINUS_ONE, &ZERO_256, &P)
    } else {
        y
    };

    let out = core::slice::from_raw_parts_mut(out_ptr, 8);
    out[0..4].copy_from_slice(&x);
    out[4..8].copy_from_slice(&final_y);
    1
}

/// Double scalar multiplication:  k1·G + k2·P.
///
/// Returns `true` when the result **is** the point at infinity (identity),
/// `false` when the output buffer contains a valid affine point.
///
/// This matches the convention expected by the k256 `lincomb()` caller
/// which names the return value `is_identity`.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_double_scalar_mul_with_g_c(
    k1_ptr: *const u64,
    k2_ptr: *const u64,
    p_ptr: *const u64,
    out_ptr: *mut u64,
) -> bool {
    let k1 = &*(k1_ptr as *const [u64; 4]);
    let k2 = &*(k2_ptr as *const [u64; 4]);
    let p = &*(p_ptr as *const [u64; 8]);

    match double_scalar_mul_internal(k1, k2, p) {
        Some(result) => {
            let out = &mut *(out_ptr as *mut [u64; 8]);
            *out = result;
            false // NOT identity — output buffer is valid
        }
        None => true, // IS identity
    }
}

/// ECDSA verification.
///
/// Returns `true` when signature `(r, s)` over message hash `z` is valid for
/// public key `pk`.
#[no_mangle]
pub unsafe extern "C" fn secp256k1_ecdsa_verify_c(
    pk_ptr: *const u64,
    z_ptr: *const u64,
    r_ptr: *const u64,
    s_ptr: *const u64,
) -> bool {
    let pk = &*(pk_ptr as *const [u64; 8]);
    let z = &*(z_ptr as *const [u64; 4]);
    let r = &*(r_ptr as *const [u64; 4]);
    let s = &*(s_ptr as *const [u64; 4]);

    ecdsa_verify_internal(pk, z, r, s)
}
