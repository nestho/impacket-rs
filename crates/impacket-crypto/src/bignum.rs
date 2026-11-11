//! `bignum`: Pure-Rust arbitrary-precision unsigned integer arithmetic (`BigUint`).
//!
//! Provides zero-dependency big-integer math for RSA (PKCS#1 v1.5) and Diffie-Hellman (Oakley Groups)
//! used by Kerberos PKINIT (`RFC 4556`) and Active Directory certificate authentication (`MS-PKCA`).

use std::cmp::Ordering;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct BigUint {
    /// Little-endian 64-bit limbs (limbs[0] is least significant).
    pub limbs: Vec<u64>,
}

impl BigUint {
    pub fn zero() -> Self {
        Self { limbs: Vec::new() }
    }

    pub fn one() -> Self {
        Self { limbs: vec![1] }
    }

    pub fn from_u64(val: u64) -> Self {
        if val == 0 {
            Self::zero()
        } else {
            Self { limbs: vec![val] }
        }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.is_empty() || self.limbs.iter().all(|&x| x == 0)
    }

    fn normalize(&mut self) {
        while let Some(&0) = self.limbs.last() {
            self.limbs.pop();
        }
    }

    pub fn bit_length(&self) -> usize {
        if self.limbs.is_empty() {
            return 0;
        }
        let top_idx = self.limbs.len() - 1;
        let top = self.limbs[top_idx];
        top_idx * 64 + (64 - top.leading_zeros() as usize)
    }

    pub fn test_bit(&self, bit: usize) -> bool {
        let limb_idx = bit / 64;
        let bit_idx = bit % 64;
        if limb_idx >= self.limbs.len() {
            false
        } else {
            (self.limbs[limb_idx] & (1u64 << bit_idx)) != 0
        }
    }

    pub fn set_bit(&mut self, bit: usize) {
        let limb_idx = bit / 64;
        let bit_idx = bit % 64;
        if limb_idx >= self.limbs.len() {
            self.limbs.resize(limb_idx + 1, 0);
        }
        self.limbs[limb_idx] |= 1u64 << bit_idx;
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = Vec::with_capacity((bytes.len() + 7) / 8);
        for chunk in bytes.rchunks(8) {
            let mut buf = [0u8; 8];
            let offset = 8 - chunk.len();
            buf[offset..].copy_from_slice(chunk);
            limbs.push(u64::from_be_bytes(buf));
        }
        let mut res = Self { limbs };
        res.normalize();
        res
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        if self.is_zero() {
            return vec![0];
        }
        let mut out = Vec::with_capacity(self.limbs.len() * 8);
        for limb in self.limbs.iter().rev() {
            out.extend_from_slice(&limb.to_be_bytes());
        }
        // Trim leading zeros
        let start = out.iter().position(|&b| b != 0).unwrap_or(out.len() - 1);
        out[start..].to_vec()
    }

    pub fn to_be_bytes_padded(&self, len: usize) -> Vec<u8> {
        let raw = self.to_be_bytes();
        if raw.len() >= len {
            if raw.len() > len {
                raw[raw.len() - len..].to_vec()
            } else {
                raw
            }
        } else {
            let mut out = vec![0u8; len - raw.len()];
            out.extend_from_slice(&raw);
            out
        }
    }

    pub fn shl(&self, shift: usize) -> Self {
        if self.is_zero() || shift == 0 {
            return self.clone();
        }
        let limb_shift = shift / 64;
        let bit_shift = shift % 64;

        let mut res = vec![0u64; self.limbs.len() + limb_shift + 1];
        let mut carry = 0u64;

        for (i, &limb) in self.limbs.iter().enumerate() {
            let target = i + limb_shift;
            if bit_shift == 0 {
                res[target] = limb;
            } else {
                res[target] = (limb << bit_shift) | carry;
                carry = limb >> (64 - bit_shift);
            }
        }
        if carry != 0 {
            let target = self.limbs.len() + limb_shift;
            res[target] = carry;
        }

        let mut out = Self { limbs: res };
        out.normalize();
        out
    }

    pub fn shr1(&mut self) {
        let mut carry = 0u64;
        for limb in self.limbs.iter_mut().rev() {
            let next_carry = *limb & 1;
            *limb = (*limb >> 1) | (carry << 63);
            carry = next_carry;
        }
        self.normalize();
    }

    pub fn add(&self, other: &Self) -> Self {
        let n = self.limbs.len().max(other.limbs.len());
        let mut limbs = Vec::with_capacity(n + 1);
        let mut carry = 0u128;

        for i in 0..n {
            let a = self.limbs.get(i).copied().unwrap_or(0) as u128;
            let b = other.limbs.get(i).copied().unwrap_or(0) as u128;
            let sum = a + b + carry;
            limbs.push(sum as u64);
            carry = sum >> 64;
        }
        if carry != 0 {
            limbs.push(carry as u64);
        }

        let mut res = Self { limbs };
        res.normalize();
        res
    }

    pub fn sub(&self, other: &Self) -> Self {
        let mut limbs = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i128;

        for i in 0..self.limbs.len() {
            let a = self.limbs[i] as i128;
            let b = other.limbs.get(i).copied().unwrap_or(0) as i128;
            let diff = a - b - borrow;
            if diff < 0 {
                limbs.push((diff + (1i128 << 64)) as u64);
                borrow = 1;
            } else {
                limbs.push(diff as u64);
                borrow = 0;
            }
        }

        let mut res = Self { limbs };
        res.normalize();
        res
    }

    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let mut res = vec![0u64; self.limbs.len() + other.limbs.len()];

        for (i, &a) in self.limbs.iter().enumerate() {
            let mut carry = 0u128;
            for (j, &b) in other.limbs.iter().enumerate() {
                let cur = (a as u128) * (b as u128) + (res[i + j] as u128) + carry;
                res[i + j] = cur as u64;
                carry = cur >> 64;
            }
            res[i + other.limbs.len()] += carry as u64;
        }

        let mut out = Self { limbs: res };
        out.normalize();
        out
    }

    pub fn div_rem(&self, divisor: &Self) -> (Self, Self) {
        if divisor.is_zero() {
            panic!("BigUint: division by zero");
        }
        if self < divisor {
            return (Self::zero(), self.clone());
        }

        let s_bits = self.bit_length();
        let d_bits = divisor.bit_length();
        let mut shift = s_bits - d_bits;
        let mut cur_d = divisor.shl(shift);
        let mut rem = self.clone();
        let mut quot = Self::zero();

        loop {
            if rem >= cur_d {
                rem = rem.sub(&cur_d);
                quot.set_bit(shift);
            }
            if shift == 0 {
                break;
            }
            shift -= 1;
            cur_d.shr1();
        }

        (quot, rem)
    }

    pub fn rem(&self, modulus: &Self) -> Self {
        self.div_rem(modulus).1
    }

    /// Modular exponentiation: `base^exp mod modulus` using square-and-multiply.
    pub fn mod_pow(&self, exp: &Self, modulus: &Self) -> Self {
        if modulus.is_zero() {
            panic!("BigUint::mod_pow: modulus is zero");
        }
        if exp.is_zero() {
            return Self::one().rem(modulus);
        }

        let mut result = Self::one();
        let mut base = self.rem(modulus);
        let bit_len = exp.bit_length();

        for bit in 0..bit_len {
            if exp.test_bit(bit) {
                result = result.mul(&base).rem(modulus);
            }
            base = base.mul(&base).rem(modulus);
        }

        result
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.limbs.len() != other.limbs.len() {
            return self.limbs.len().cmp(&other.limbs.len());
        }
        for (a, b) in self.limbs.iter().rev().zip(other.limbs.iter().rev()) {
            if a != b {
                return a.cmp(b);
            }
        }
        Ordering::Equal
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biguint_arithmetic() {
        let a = BigUint::from_u64(0xFFFF_FFFF_FFFF_FFFF);
        let b = BigUint::from_u64(1);
        let c = a.add(&b);
        assert_eq!(c.limbs, vec![0, 1]);
        assert_eq!(c.sub(&b), a);

        let d = c.mul(&BigUint::from_u64(2));
        assert_eq!(d.limbs, vec![0, 2]);

        let (q, r) = d.div_rem(&c);
        assert_eq!(q, BigUint::from_u64(2));
        assert!(r.is_zero());
    }

    #[test]
    fn test_biguint_mod_pow() {
        // 3^5 mod 7 = 243 mod 7 = 5
        let base = BigUint::from_u64(3);
        let exp = BigUint::from_u64(5);
        let m = BigUint::from_u64(7);
        assert_eq!(base.mod_pow(&exp, &m), BigUint::from_u64(5));

        // 7^13 mod 11: 7^1 = 7, 7^2=5, 7^4=3, 7^8=9. 7^13 = 7^(8+4+1) = 9*3*7 = 189 mod 11 = 2
        let base2 = BigUint::from_u64(7);
        let exp2 = BigUint::from_u64(13);
        let m2 = BigUint::from_u64(11);
        assert_eq!(base2.mod_pow(&exp2, &m2), BigUint::from_u64(2));
    }
}
