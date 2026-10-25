//! # BlindAgent Rust Cryptographic Core
//! 
//! Constant-time Galois Field GF(2^8) and Shamir's Secret Sharing (SSS) engine.
//! Mathematical irreducible polynomial: P(x) = x^8 + x^4 + x^3 + x + 1 (0x11B)

#![no_std]

pub const GF256_POLY: u8 = 0x1B;

/// Constant-time addition in GF(2^8) (XOR)
#[inline(always)]
pub fn gf256_add(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Constant-time subtraction in GF(2^8)
#[inline(always)]
pub fn gf256_sub(a: u8, b: u8) -> u8 {
    a ^ b
}

/// Constant-time Russian Peasant multiplication in GF(2^8) modulo 0x11B
pub fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p: u8 = 0;
    for _ in 0..8 {
        let mask = ((b & 1) as i8).wrapping_neg() as u8;
        p ^= a & mask;

        let hi_bit = ((a >> 7) as i8).wrapping_neg() as u8;
        a = (a << 1) ^ (GF256_POLY & hi_bit);
        b >>= 1;
    }
    p
}

/// Constant-time Multiplicative Inverse via Fermat's Little Theorem: a^254
pub fn gf256_inv(a: u8) -> u8 {
    let a2 = gf256_mul(a, a);
    let a3 = gf256_mul(a2, a);
    let a6 = gf256_mul(a3, a3);
    let a7 = gf256_mul(a6, a);
    let a14 = gf256_mul(a7, a7);
    let a15 = gf256_mul(a14, a);
    let a30 = gf256_mul(a15, a15);
    let a31 = gf256_mul(a30, a);
    let a62 = gf256_mul(a31, a31);
    let a63 = gf256_mul(a62, a);
    let a126 = gf256_mul(a63, a63);
    let a127 = gf256_mul(a126, a);
    gf256_mul(a127, a127)
}

/// Constant-time division in GF(2^8)
pub fn gf256_div(a: u8, b: u8) -> u8 {
    if b == 0 {
        return 0;
    }
    gf256_mul(a, gf256_inv(b))
}

/// Polynomial evaluation over GF(2^8) via Horner's method
pub fn gf256_poly_eval(poly: &[u8], x: u8) -> u8 {
    if poly.is_empty() {
        return 0;
    }
    let mut result = poly[poly.len() - 1];
    for &coeff in poly[..poly.len() - 1].iter().rev() {
        result = gf256_add(gf256_mul(result, x), coeff);
    }
    result
}

/// Affine Homomorphic Blinding Transform: out[i] = (in[i] * alpha) ^ beta
pub fn blind_affine(input: &[u8], alpha: u8, beta: u8, output: &mut [u8]) {
    assert_eq!(input.len(), output.len());
    for (inp, out) in input.iter().zip(output.iter_mut()) {
        *out = gf256_add(gf256_mul(*inp, alpha), beta);
    }
}

/// Invert Affine Homomorphic Blinding Transform
pub fn unblind_affine(input: &[u8], alpha: u8, beta: u8, output: &mut [u8]) {
    assert_eq!(input.len(), output.len());
    let inv_alpha = gf256_inv(alpha);
    for (inp, out) in input.iter().zip(output.iter_mut()) {
        *out = gf256_mul(gf256_sub(*inp, beta), inv_alpha);
    }
}
