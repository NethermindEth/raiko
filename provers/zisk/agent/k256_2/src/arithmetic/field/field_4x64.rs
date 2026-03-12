//! Field element modulo the curve internal modulus using 64-bit limbs.
//! On zisk targets, all arithmetic is delegated to syscall_arith256_mod.

use crate::FieldBytes;
use elliptic_curve::{
    bigint::U256,
    subtle::{Choice, ConditionallySelectable, ConstantTimeEq, CtOption},
    zeroize::Zeroize,
};

/// Scalars modulo SECP256k1 modulus (2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1).
/// Uses 4 64-bit limbs (little-endian)
#[derive(Clone, Copy, Debug)]
pub struct FieldElement4x64(pub(crate) [u64; 4]);

impl FieldElement4x64 {
    /// Zero element.
    pub const ZERO: Self = Self([0, 0, 0, 0]);

    /// Multiplicative identity.
    pub const ONE: Self = Self([1, 0, 0, 0]);

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    /// Does not check the result for being in the correct range.
    pub(crate) const fn from_bytes_unchecked(bytes: &[u8; 32]) -> Self {
        let w0 = (bytes[31] as u64)
            | ((bytes[30] as u64) << 8)
            | ((bytes[29] as u64) << 16)
            | ((bytes[28] as u64) << 24)
            | ((bytes[27] as u64) << 32)
            | ((bytes[26] as u64) << 40)
            | ((bytes[25] as u64) << 48)
            | ((bytes[24] as u64) << 56);

        let w1 = (bytes[23] as u64)
            | ((bytes[22] as u64) << 8)
            | ((bytes[21] as u64) << 16)
            | ((bytes[20] as u64) << 24)
            | ((bytes[19] as u64) << 32)
            | ((bytes[18] as u64) << 40)
            | ((bytes[17] as u64) << 48)
            | ((bytes[16] as u64) << 56);

        let w2 = (bytes[15] as u64)
            | ((bytes[14] as u64) << 8)
            | ((bytes[13] as u64) << 16)
            | ((bytes[12] as u64) << 24)
            | ((bytes[11] as u64) << 32)
            | ((bytes[10] as u64) << 40)
            | ((bytes[9] as u64) << 48)
            | ((bytes[8] as u64) << 56);

        let w3 = (bytes[7] as u64)
            | ((bytes[6] as u64) << 8)
            | ((bytes[5] as u64) << 16)
            | ((bytes[4] as u64) << 24)
            | ((bytes[3] as u64) << 32)
            | ((bytes[2] as u64) << 40)
            | ((bytes[1] as u64) << 48)
            | ((bytes[0] as u64) << 56);

        Self([w0, w1, w2, w3])
    }

    /// Attempts to parse the given byte array as an SEC1-encoded field element.
    ///
    /// Returns None if the byte array does not contain a big-endian integer in the range
    /// [0, p).
    #[inline]
    pub fn from_bytes(bytes: &FieldBytes) -> CtOption<Self> {
        let res = Self::from_bytes_unchecked(bytes.as_ref());
        let overflow = res.get_overflow();
        CtOption::new(res, !overflow)
    }

    pub const fn from_u64(val: u64) -> Self {
        Self([val, 0, 0, 0])
    }

    /// Create from a U256 value without range checking.
    pub const fn from_u256_unchecked(value: U256) -> Self {
        let words = value.as_words();
        Self([words[0], words[1], words[2], words[3]])
    }

    /// Convert from a U256 value with range checking.
    pub fn from_u256(value: U256) -> CtOption<Self> {
        let res = Self::from_u256_unchecked(value);
        let overflow = res.get_overflow();
        CtOption::new(res, !overflow)
    }

    /// Convert to U256.
    #[inline(always)]
    pub const fn to_u256(self) -> U256 {
        U256::from_words(self.0)
    }

    /// Returns the SEC1 encoding of this field element.
    pub fn to_bytes(self) -> FieldBytes {
        let mut ret = FieldBytes::default();

        for i in 0..8 {
            ret[i] = (self.0[3] >> (56 - i * 8)) as u8;
        }

        for i in 0..8 {
            ret[8 + i] = (self.0[2] >> (56 - i * 8)) as u8;
        }

        for i in 0..8 {
            ret[16 + i] = (self.0[1] >> (56 - i * 8)) as u8;
        }

        for i in 0..8 {
            ret[24 + i] = (self.0[0] >> (56 - i * 8)) as u8;
        }

        ret
    }

    /// Checks if the field element is greater or equal to the modulus.
    fn get_overflow(&self) -> Choice {
        let m = self.0[1] & self.0[2] & self.0[3];
        let x = (m == 0xFF_FF_FF_FF_FF_FF_FF_FFu64)
                & (self.0[0] >= 0xFF_FF_FF_FE_FF_FF_FC_2Fu64);
        Choice::from(x as u8)
    }

    /// Brings the field element's magnitude to 1, but does not necessarily normalize it.
    pub fn normalize_weak(&self) -> Self {
        Self(crate::zisk::fp_reduce(&self.0))
    }

    /// Fully normalizes the field element.
    pub fn normalize(&self) -> Self {
        Self(crate::zisk::fp_reduce(&self.0))
    }

    /// Checks if the field element becomes zero if normalized.
    pub fn normalizes_to_zero(&self) -> Choice {
        self.normalize().is_zero()
    }

    /// Determine if this `FieldElement4x64` is zero.
    ///
    /// # Returns
    ///
    /// If zero, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_zero(&self) -> Choice {
        Choice::from(((self.0[0] | self.0[1] | self.0[2] | self.0[3]) == 0) as u8)
    }

    /// Determine if this `FieldElement4x64` is odd in the SEC1 sense: `self mod 2 == 1`.
    ///
    /// # Returns
    ///
    /// If odd, return `Choice(1)`.  Otherwise, return `Choice(0)`.
    pub fn is_odd(&self) -> Choice {
        (self.0[0] as u8 & 1).into()
    }

    /// The maximum number `m` for which the value fits.
    #[cfg(debug_assertions)]
    pub const fn max_magnitude() -> u32 {
        2047u32
    }

    /// Returns -self
    pub fn negate(&self, _magnitude: u32) -> Self {
        Self(crate::zisk::fp_negate(&self.0))
    }

    /// Returns self + rhs mod p.
    pub fn add(&self, rhs: &Self) -> Self {
        Self(crate::zisk::fp_add(&self.0, &rhs.0))
    }

    /// Multiplies by a single-limb integer.
    pub fn mul_single(&self, rhs: u32) -> Self {
        Self(crate::zisk::fp_mul_scalar(&self.0, rhs as u64))
    }

    /// Returns self * rhs mod p
    #[inline(always)]
    pub fn mul(&self, rhs: &Self) -> Self {
        Self(crate::zisk::fp_mul(&self.0, &rhs.0))
    }

    /// Returns self * self
    pub fn square(&self) -> Self {
        Self(crate::zisk::fp_mul(&self.0, &self.0))
    }
}

impl Default for FieldElement4x64 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl ConditionallySelectable for FieldElement4x64 {
    #[inline(always)]
    fn conditional_select(
        a: &FieldElement4x64,
        b: &FieldElement4x64,
        choice: Choice,
    ) -> FieldElement4x64 {
        FieldElement4x64([
            u64::conditional_select(&a.0[0], &b.0[0], choice),
            u64::conditional_select(&a.0[1], &b.0[1], choice),
            u64::conditional_select(&a.0[2], &b.0[2], choice),
            u64::conditional_select(&a.0[3], &b.0[3], choice),
        ])
    }
}

impl ConstantTimeEq for FieldElement4x64 {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0[0].ct_eq(&other.0[0])
            & self.0[1].ct_eq(&other.0[1])
            & self.0[2].ct_eq(&other.0[2])
            & self.0[3].ct_eq(&other.0[3])
    }
}

impl Zeroize for FieldElement4x64 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
