// wasm.rs — wasm-bindgen wrapper for FF3-1
//
// Mirrors the FF1 WASM API as closely as possible so the two crates
// are interchangeable from JavaScript.
//
// Usage from JavaScript/TypeScript:
//
//   import init, { Ff3 } from "./pkg/ff3_1.js";
//   await init();
//
//   const cipher = new Ff3("2DE79D232DF5585D68CE47882AE256D6", 10);
//   const ct = cipher.encryptStr("3992520240", "CBD09280979564hex", "0123456789");
//
// Note: FF3-1 requires a tweak of exactly 7 bytes. Both a UTF-8 string tweak
// and a hex-encoded binary tweak are supported. The string variant uses the
// raw UTF-8 bytes of the string, so keep tweaks to 7 characters when using
// encryptStr / decryptStr, or use the hex variants for precise control.

use wasm_bindgen::prelude::*;
use crate::Ff3Cipher;

fn to_js_err(e: crate::Ff3Error) -> JsValue {
    JsValue::from_str(&e.to_string())
}

/// FF3-1 Format-Preserving Encryption cipher.
///
/// FF3-1 requires a tweak of **exactly 7 bytes**. Use `encryptStrHexTweak`
/// for full control over the tweak bytes, or ensure your UTF-8 tweak string
/// is exactly 7 bytes long when using `encryptStr`.
///
/// ```js
/// const cipher = new Ff3("2DE79D232DF5585D68CE47882AE256D6", 10);
/// const ct = cipher.encryptStrHexTweak("3992520240", "CBD09280979564", "0123456789");
/// ```
#[wasm_bindgen]
pub struct Ff3 {
    inner: Ff3Cipher,
}

#[wasm_bindgen]
impl Ff3 {
    /// Create a new FF3-1 cipher.
    ///
    /// @param keyHex - AES key as a hex string (32, 48, or 64 hex chars = 128/192/256 bits)
    /// @param radix  - Numeral base, 2–65536.
    ///
    /// Throws if the key length or radix is invalid.
    #[wasm_bindgen(constructor)]
    pub fn new(key_hex: &str, radix: u32) -> Result<Ff3, JsValue> {
        let key = hex_decode(key_hex).map_err(|e| JsValue::from_str(&e))?;
        let inner = Ff3Cipher::new(&key, radix).map_err(to_js_err)?;
        Ok(Ff3 { inner })
    }

    // -----------------------------------------------------------------------
    // String interface — tweak must be exactly 7 UTF-8 bytes
    // -----------------------------------------------------------------------

    /// Encrypt a string using a custom alphabet.
    ///
    /// @param plaintext - String to encrypt. Every character must be in `alphabet`.
    /// @param tweak     - Must be exactly 7 bytes when encoded as UTF-8.
    /// @param alphabet  - Character set whose length equals `radix`.
    ///
    /// Throws if the tweak is not exactly 7 bytes.
    #[wasm_bindgen(js_name = encryptStr)]
    pub fn encrypt_str(&self, plaintext: &str, tweak: &str, alphabet: &str) -> Result<String, JsValue> {
        self.inner
            .encrypt_str(plaintext, tweak.as_bytes(), alphabet)
            .map_err(to_js_err)
    }

    /// Decrypt a string using a custom alphabet.
    ///
    /// @param ciphertext - String to decrypt. Every character must be in `alphabet`.
    /// @param tweak      - Must match the tweak used during encryption (exactly 7 bytes).
    /// @param alphabet   - Must match the alphabet used during encryption.
    #[wasm_bindgen(js_name = decryptStr)]
    pub fn decrypt_str(&self, ciphertext: &str, tweak: &str, alphabet: &str) -> Result<String, JsValue> {
        self.inner
            .decrypt_str(ciphertext, tweak.as_bytes(), alphabet)
            .map_err(to_js_err)
    }

    // -----------------------------------------------------------------------
    // Hex tweak interface — recommended for precise 7-byte tweak control
    // -----------------------------------------------------------------------

    /// Encrypt a string with a hex-encoded 7-byte tweak.
    ///
    /// @param plaintext - String to encrypt.
    /// @param tweakHex  - Exactly 14 hex characters (= 7 bytes).
    /// @param alphabet  - Character set whose length equals `radix`.
    ///
    /// Example:
    /// ```js
    /// cipher.encryptStrHexTweak("4111111111111111", "D8E7920AFA330A", "0123456789");
    /// ```
    #[wasm_bindgen(js_name = encryptStrHexTweak)]
    pub fn encrypt_str_hex_tweak(
        &self,
        plaintext: &str,
        tweak_hex: &str,
        alphabet: &str,
    ) -> Result<String, JsValue> {
        let tweak = hex_decode(tweak_hex).map_err(|e| JsValue::from_str(&e))?;
        self.inner
            .encrypt_str(plaintext, &tweak, alphabet)
            .map_err(to_js_err)
    }

    /// Decrypt a string with a hex-encoded 7-byte tweak.
    #[wasm_bindgen(js_name = decryptStrHexTweak)]
    pub fn decrypt_str_hex_tweak(
        &self,
        ciphertext: &str,
        tweak_hex: &str,
        alphabet: &str,
    ) -> Result<String, JsValue> {
        let tweak = hex_decode(tweak_hex).map_err(|e| JsValue::from_str(&e))?;
        self.inner
            .decrypt_str(ciphertext, &tweak, alphabet)
            .map_err(to_js_err)
    }

    // -----------------------------------------------------------------------
    // Numeric symbol interface (Uint32Array)
    // -----------------------------------------------------------------------

    /// Encrypt a Uint32Array of symbol values.
    ///
    /// @param symbols  - Symbol values, each in [0, radix).
    /// @param tweakHex - Exactly 14 hex characters (= 7 bytes).
    #[wasm_bindgen(js_name = encrypt)]
    pub fn encrypt(&self, symbols: &[u32], tweak_hex: &str) -> Result<Vec<u32>, JsValue> {
        let tweak = hex_decode(tweak_hex).map_err(|e| JsValue::from_str(&e))?;
        self.inner.encrypt(symbols, &tweak).map_err(to_js_err)
    }

    /// Decrypt a Uint32Array of symbol values.
    ///
    /// @param symbols  - Symbol values, each in [0, radix).
    /// @param tweakHex - Must match the tweak used during encryption.
    #[wasm_bindgen(js_name = decrypt)]
    pub fn decrypt(&self, symbols: &[u32], tweak_hex: &str) -> Result<Vec<u32>, JsValue> {
        let tweak = hex_decode(tweak_hex).map_err(|e| JsValue::from_str(&e))?;
        self.inner.decrypt(symbols, &tweak).map_err(to_js_err)
    }

    // -----------------------------------------------------------------------
    // Alphabet constants
    // -----------------------------------------------------------------------

    /// Standard decimal digit alphabet: "0123456789"
    #[wasm_bindgen(getter, js_name = DIGITS)]
    pub fn digits() -> String { "0123456789".to_string() }

    /// Standard lowercase alphabet: "abcdefghijklmnopqrstuvwxyz"
    #[wasm_bindgen(getter, js_name = ALPHA_LOWER)]
    pub fn alpha_lower() -> String { "abcdefghijklmnopqrstuvwxyz".to_string() }

    /// Alphanumeric alphabet (radix 36): "0123456789abcdefghijklmnopqrstuvwxyz"
    #[wasm_bindgen(getter, js_name = ALPHANUM)]
    pub fn alphanum() -> String { "0123456789abcdefghijklmnopqrstuvwxyz".to_string() }
}

// ---------------------------------------------------------------------------
// Hex decode utility
// ---------------------------------------------------------------------------

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if s.len() % 2 != 0 {
        return Err(format!("Hex string has odd length: {}", s.len()));
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = hex_char(pair[0])?;
            let lo = hex_char(pair[1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn hex_char(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("Invalid hex character: {}", c as char)),
    }
}

// ---------------------------------------------------------------------------
// WASM tests (run with: wasm-pack test --headless --chrome)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    wasm_bindgen_test_configure!(run_in_browser);

    #[wasm_bindgen_test]
    fn acvp_vector_via_wasm() {
        // ACVP draft vector: AES-128, radix=10, 7-byte tweak
        let cipher = Ff3::new("2DE79D232DF5585D68CE47882AE256D6", 10).unwrap();
        let ct = cipher.encrypt_str_hex_tweak("3992520240", "CBD09280979564", "0123456789").unwrap();
        assert_eq!(ct, "8532068021");
        let pt = cipher.decrypt_str_hex_tweak(&ct, "CBD09280979564", "0123456789").unwrap();
        assert_eq!(pt, "3992520240");
    }

    #[wasm_bindgen_test]
    fn round_trip_credit_card() {
        let cipher = Ff3::new("2DE79D232DF5585D68CE47882AE256D6", 10).unwrap();
        let ccn   = "4111111111111111";
        let tweak = "D8E7920AFA330A"; // 7 bytes
        let ct = cipher.encrypt_str_hex_tweak(ccn, tweak, Ff3::digits().as_str()).unwrap();
        assert_eq!(ct.len(), ccn.len());
        let pt = cipher.decrypt_str_hex_tweak(&ct, tweak, Ff3::digits().as_str()).unwrap();
        assert_eq!(pt, ccn);
    }

    #[wasm_bindgen_test]
    fn round_trip_alpha() {
        let cipher = Ff3::new("2DE79D232DF5585D68CE47882AE256D6", 26).unwrap();
        let pt    = "secretmsg";
        let tweak = "D8E7920AFA330A";
        let ct = cipher.encrypt_str_hex_tweak(pt, tweak, Ff3::alpha_lower().as_str()).unwrap();
        let rt = cipher.decrypt_str_hex_tweak(&ct, tweak, Ff3::alpha_lower().as_str()).unwrap();
        assert_eq!(rt, pt);
    }

    #[wasm_bindgen_test]
    fn uint32_array_interface() {
        let cipher  = Ff3::new("2DE79D232DF5585D68CE47882AE256D6", 10).unwrap();
        let symbols = vec![3u32, 9, 9, 2, 5, 2, 0, 2, 4, 0];
        let tweak   = "CBD09280979564";
        let ct = cipher.encrypt(&symbols, tweak).unwrap();
        let pt = cipher.decrypt(&ct, tweak).unwrap();
        assert_eq!(pt, symbols);
    }

    #[wasm_bindgen_test]
    fn wrong_tweak_length_throws() {
        let cipher = Ff3::new("2DE79D232DF5585D68CE47882AE256D6", 10).unwrap();
        // 8-byte tweak (FF3, not FF3-1) should throw
        let result = cipher.encrypt_str_hex_tweak("3992520240", "D8E7920AFA330A73", "0123456789");
        assert!(result.is_err());
    }

    #[wasm_bindgen_test]
    fn invalid_key_throws() {
        let result = Ff3::new("deadbeef", 10); // 4 bytes — too short
        assert!(result.is_err());
    }
}