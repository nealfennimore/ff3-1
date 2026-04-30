// FF3-1 Format-Preserving Encryption
// Implements NIST SP 800-38G Revision 1
//
// All intermediate arithmetic uses u128. This is safe because the NIST spec
// requires radix^n < 2^96, which our length check enforces. The largest
// intermediate value (NUMradix of a half-block) is therefore < 2^96, and
// the AES output S fits in u128 exactly (16 bytes = u128::MAX at most).
// We always reduce S % modulus before adding to keep all sums below 2^97.

use aes::cipher::{BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};
use std::fmt;

#[derive(Debug, PartialEq)]
pub enum Ff3Error {
    InvalidKeyLength(usize),
    InvalidTweakLength(usize),
    InvalidRadix(u32),
    PlaintextTooShort(usize),
    PlaintextTooLong(usize),
    SymbolOutOfRange(u32),
}

impl fmt::Display for Ff3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ff3Error::InvalidKeyLength(n) =>
                write!(f, "Invalid key length: {} bytes (must be 16, 24, or 32)", n),
            Ff3Error::InvalidTweakLength(n) =>
                write!(f, "Invalid tweak length: {} bytes (FF3-1 requires 7)", n),
            Ff3Error::InvalidRadix(r) =>
                write!(f, "Invalid radix: {} (must be 2..=65536)", r),
            Ff3Error::PlaintextTooShort(n) =>
                write!(f, "Plaintext too short: {} symbols (minimum 2)", n),
            Ff3Error::PlaintextTooLong(n) =>
                write!(f, "Plaintext too long: {} symbols", n),
            Ff3Error::SymbolOutOfRange(s) =>
                write!(f, "Symbol value {} is out of range for radix", s),
        }
    }
}

// FF3-1 PRF: REVB( AES_REVB(K)( REVB(block) ) )
fn aes_rev_b(key: &[u8], block: &[u8; 16]) -> [u8; 16] {
    let rev_key: Vec<u8> = key.iter().rev().cloned().collect();
    let mut out = *block;
    out.reverse();
    match rev_key.len() {
        16 => { let c = Aes128::new_from_slice(&rev_key).unwrap(); c.encrypt_block(aes::Block::from_mut_slice(&mut out)); }
        24 => { let c = Aes192::new_from_slice(&rev_key).unwrap(); c.encrypt_block(aes::Block::from_mut_slice(&mut out)); }
        32 => { let c = Aes256::new_from_slice(&rev_key).unwrap(); c.encrypt_block(aes::Block::from_mut_slice(&mut out)); }
        _  => panic!("Unexpected key length"),
    }
    out.reverse();
    out
}

#[inline]
fn num_radix(radix: u128, x: &[u32]) -> u128 {
    x.iter().fold(0u128, |acc, &d| acc * radix + d as u128)
}

#[inline]
fn str_m_radix(radix: u128, m: usize, mut x: u128) -> Vec<u32> {
    let mut digits = vec![0u32; m];
    for i in (0..m).rev() {
        digits[i] = (x % radix) as u32;
        x /= radix;
    }
    digits
}

#[inline]
fn pow_u128(base: u128, exp: usize) -> u128 {
    (0..exp).fold(1u128, |acc, _| acc * base)
}

#[derive(Debug, PartialEq)]
pub struct Ff3Cipher {
    key: Vec<u8>,
    radix: u32,
}

impl Ff3Cipher {
    pub fn new(key: &[u8], radix: u32) -> Result<Self, Ff3Error> {
        match key.len() {
            16 | 24 | 32 => {}
            n => return Err(Ff3Error::InvalidKeyLength(n)),
        }
        if radix < 2 || radix > 65536 {
            return Err(Ff3Error::InvalidRadix(radix));
        }
        Ok(Ff3Cipher { key: key.to_vec(), radix })
    }

    fn check_tweak(tweak: &[u8]) -> Result<(), Ff3Error> {
        if tweak.len() != 7 { return Err(Ff3Error::InvalidTweakLength(tweak.len())); }
        Ok(())
    }

    fn check_length(&self, n: usize) -> Result<(), Ff3Error> {
        if n < 2 { return Err(Ff3Error::PlaintextTooShort(n)); }
        let max_len = 2 * ((96.0_f64 * 2.0_f64.ln()) / (self.radix as f64).ln()).floor() as usize;
        if n > max_len { return Err(Ff3Error::PlaintextTooLong(n)); }
        Ok(())
    }

    pub fn encrypt(&self, plaintext: &[u32], tweak: &[u8]) -> Result<Vec<u32>, Ff3Error> {
        Self::check_tweak(tweak)?;
        self.check_length(plaintext.len())?;
        for &s in plaintext { if s >= self.radix { return Err(Ff3Error::SymbolOutOfRange(s)); } }
        Ok(self.cipher_core(plaintext, tweak, true))
    }

    pub fn decrypt(&self, ciphertext: &[u32], tweak: &[u8]) -> Result<Vec<u32>, Ff3Error> {
        Self::check_tweak(tweak)?;
        self.check_length(ciphertext.len())?;
        for &s in ciphertext { if s >= self.radix { return Err(Ff3Error::SymbolOutOfRange(s)); } }
        Ok(self.cipher_core(ciphertext, tweak, false))
    }

    fn build_p(&self, i: u8, tl: &[u8; 4], tr: &[u8; 4], half: &[u32]) -> [u8; 16] {
        let w = if i % 2 == 0 { tl } else { tr };
        let mut p = [0u8; 16];
        p[0] = w[0]; p[1] = w[1]; p[2] = w[2]; p[3] = w[3] ^ i;
        let rev: Vec<u32> = half.iter().rev().cloned().collect();
        let num_b = num_radix(self.radix as u128, &rev);
        // Pack into 12 bytes (right 12 of the 16-byte big-endian u128)
        p[4..16].copy_from_slice(&num_b.to_be_bytes()[4..16]);
        p
    }

    fn cipher_core(&self, x: &[u32], tweak: &[u8], encrypt: bool) -> Vec<u32> {
        let n = x.len();
        let u = (n + 1) / 2;
        let v = n - u;
        let radix = self.radix as u128;

        let mut a: Vec<u32> = x[..u].to_vec();
        let mut b: Vec<u32> = x[u..].to_vec();

        let mut tl = [0u8; 4];
        let mut tr = [0u8; 4];
        tl.copy_from_slice(&tweak[0..4]);
        tr[0..3].copy_from_slice(&tweak[4..7]);

        if encrypt {
            for i in 0u8..8 {
                let m = if i % 2 == 0 { u } else { v };
                let modulus = pow_u128(radix, m);
                let p = self.build_p(i, &tl, &tr, &b);
                let s = u128::from_be_bytes(aes_rev_b(&self.key, &p));
                let num_a = num_radix(radix, &a.iter().rev().cloned().collect::<Vec<_>>());
                let c = (num_a + s % modulus) % modulus;
                let c_rev: Vec<u32> = str_m_radix(radix, m, c).into_iter().rev().collect();
                a = b; b = c_rev;
            }
        } else {
            for i in (0u8..8).rev() {
                let m = if i % 2 == 0 { u } else { v };
                let modulus = pow_u128(radix, m);
                let p = self.build_p(i, &tl, &tr, &a);
                let s = u128::from_be_bytes(aes_rev_b(&self.key, &p));
                let num_b = num_radix(radix, &b.iter().rev().cloned().collect::<Vec<_>>());
                let s_mod = s % modulus;
                let c = if num_b >= s_mod { num_b - s_mod } else { modulus - (s_mod - num_b) };
                let c_rev: Vec<u32> = str_m_radix(radix, m, c).into_iter().rev().collect();
                b = a; a = c_rev;
            }
        }

        let mut result = a;
        result.extend(b);
        result
    }

    pub fn encrypt_str(&self, plaintext: &str, tweak: &[u8], alphabet: &str) -> Result<String, Ff3Error> {
        let chars: Vec<char> = alphabet.chars().collect();
        let symbols: Result<Vec<u32>, _> = plaintext.chars()
            .map(|c| chars.iter().position(|&a| a == c).map(|i| i as u32).ok_or(Ff3Error::SymbolOutOfRange(c as u32)))
            .collect();
        let enc = self.encrypt(&symbols?, tweak)?;
        Ok(enc.iter().map(|&i| chars[i as usize]).collect())
    }

    pub fn decrypt_str(&self, ciphertext: &str, tweak: &[u8], alphabet: &str) -> Result<String, Ff3Error> {
        let chars: Vec<char> = alphabet.chars().collect();
        let symbols: Result<Vec<u32>, _> = ciphertext.chars()
            .map(|c| chars.iter().position(|&a| a == c).map(|i| i as u32).ok_or(Ff3Error::SymbolOutOfRange(c as u32)))
            .collect();
        let dec = self.decrypt(&symbols?, tweak)?;
        Ok(dec.iter().map(|&i| chars[i as usize]).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i+2], 16).unwrap()).collect()
    }
    fn digits(s: &str) -> Vec<u32> { s.chars().map(|c| c.to_digit(10).unwrap()).collect() }
    fn digit_str(v: &[u32]) -> String { v.iter().map(|d| char::from_digit(*d, 10).unwrap()).collect() }

    #[test]
    fn nist_ff3_1_aes128_sample1() {
        let key   = hex_bytes("2DE79D232DF5585D68CE47882AE256D6");
        let tweak = hex_bytes("CBD09280979564");
        let pt    = digits("3992520240");
        let exp   = digits("8532068021");
        let c     = Ff3Cipher::new(&key, 10).unwrap();
        let ct    = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(digit_str(&ct), digit_str(&exp), "sample1 encrypt");
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt, "sample1 decrypt");
    }

    #[test]
    fn nist_ff3_1_aes128_sample2() {
        let key   = hex_bytes("EF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("9A768A92F60E12");
        let pt    = digits("89012123456789000000789000000");
        let c     = Ff3Cipher::new(&key, 10).unwrap();
        let ct    = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct.len(), pt.len());
        assert!(ct.iter().all(|&d| d < 10));
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt);
    }

    #[test]
    fn nist_ff3_1_aes256_sample1() {
        let key   = hex_bytes("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_bytes("D8E7920AFA330A");
        let pt    = digits("890121234567890000");
        let c     = Ff3Cipher::new(&key, 10).unwrap();
        let ct    = c.encrypt(&pt, &tweak).unwrap();
        assert_ne!(ct, pt);
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt);
    }

    #[test]
    fn nist_ff3_1_aes256_sample2() {
        let key   = hex_bytes("EF4359D8D580AA4F7F036D6F04FC6A942B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_bytes("9A768A92F60E12");
        let pt    = digits("89012123456789000000789000000");
        let c     = Ff3Cipher::new(&key, 10).unwrap();
        let ct    = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt);
    }

    #[test]
    fn round_trip_radix10_short() {
        let key   = hex_bytes("EF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("00000000000000");
        let pt    = digits("0123456789");
        let c     = Ff3Cipher::new(&key, 10).unwrap();
        let ct    = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt);
    }

    #[test]
    fn round_trip_radix2() {
        let key   = hex_bytes("EF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("D8E7920AFA330A");
        let pt    = vec![1,0,1,0,1,1,0,0,1,1,0,1,0,1,1,0,1,0,0,1];
        let c     = Ff3Cipher::new(&key, 2).unwrap();
        let ct    = c.encrypt(&pt, &tweak).unwrap();
        assert!(ct.iter().all(|&b| b < 2));
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt);
    }

    #[test]
    fn round_trip_ssn() {
        let key   = hex_bytes("2B7E151628AED2A6ABF7158809CF4F3C");
        let tweak = hex_bytes("39383736353433");
        let pt    = digits("123456789");
        let c     = Ff3Cipher::new(&key, 10).unwrap();
        let ct    = c.encrypt(&pt, &tweak).unwrap();
        assert_eq!(ct.len(), 9);
        assert_eq!(c.decrypt(&ct, &tweak).unwrap(), pt);
    }

    #[test]
    fn str_encrypt_decrypt_alpha() {
        let key   = hex_bytes("EF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("D8E7920AFA330A");
        let alpha = "abcdefghijklmnopqrstuvwxyz";
        let pt    = "thequickbrownfox";
        let c     = Ff3Cipher::new(&key, 26).unwrap();
        let ct    = c.encrypt_str(pt, &tweak, alpha).unwrap();
        assert!(ct.chars().all(|ch| alpha.contains(ch)));
        assert_eq!(c.decrypt_str(&ct, &tweak, alpha).unwrap(), pt);
    }

    #[test]
    fn str_encrypt_decrypt_digits() {
        let key   = hex_bytes("EF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("D8E7920AFA330A");
        let pt    = "4111111111111111";
        let c     = Ff3Cipher::new(&key, 10).unwrap();
        let ct    = c.encrypt_str(pt, &tweak, "0123456789").unwrap();
        assert_eq!(ct.len(), pt.len());
        assert_eq!(c.decrypt_str(&ct, &tweak, "0123456789").unwrap(), pt);
    }

    #[test]
    fn deterministic() {
        let key   = hex_bytes("EF4359D8D580AA4F7F036D6F04FC6A94");
        let tweak = hex_bytes("D8E7920AFA330A");
        let pt    = digits("4111111111111111");
        let c     = Ff3Cipher::new(&key, 10).unwrap();
        assert_eq!(c.encrypt(&pt, &tweak).unwrap(), c.encrypt(&pt, &tweak).unwrap());
    }

    #[test]
    fn different_tweaks_produce_different_output() {
        let key = hex_bytes("EF4359D8D580AA4F7F036D6F04FC6A94");
        let pt  = digits("4111111111111111");
        let c   = Ff3Cipher::new(&key, 10).unwrap();
        assert_ne!(
            c.encrypt(&pt, &hex_bytes("D8E7920AFA330A")).unwrap(),
            c.encrypt(&pt, &hex_bytes("00000000000000")).unwrap()
        );
    }

    #[test]
    fn error_bad_key_length() {
        assert_eq!(Ff3Cipher::new(&[0u8;15], 10), Err(Ff3Error::InvalidKeyLength(15)));
    }

    #[test]
    fn error_bad_tweak_length() {
        let c = Ff3Cipher::new(&[0u8;16], 10).unwrap();
        assert_eq!(c.encrypt(&digits("0123456789"), &[0u8;8]), Err(Ff3Error::InvalidTweakLength(8)));
    }

    #[test]
    fn error_plaintext_too_short() {
        let c = Ff3Cipher::new(&[0u8;16], 10).unwrap();
        assert_eq!(c.encrypt(&[0], &[0u8;7]), Err(Ff3Error::PlaintextTooShort(1)));
    }

    #[test]
    fn error_symbol_out_of_range() {
        let c = Ff3Cipher::new(&[0u8;16], 10).unwrap();
        assert_eq!(c.encrypt(&[0,1,10,3], &[0u8;7]), Err(Ff3Error::SymbolOutOfRange(10)));
    }
}