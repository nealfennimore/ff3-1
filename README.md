# ff3-1

A Rust implementation of **FF3-1 Format-Preserving Encryption** as specified in [NIST SP 800-38G Revision 1](https://csrc.nist.gov/pubs/sp/800/38/g/r1/ipd).

---

> [!WARNING]
> **This implementation was generated with AI assistance and has not undergone a formal security audit. It is provided for educational and experimental purposes only. Do not use this in production systems or to protect sensitive data without independent review by a qualified cryptographer. Use at your own risk.**

---

## What is FF3-1?

FF3-1 is a **format-preserving encryption** (FPE) scheme. Unlike standard encryption which produces binary ciphertext, FPE encrypts data while preserving the format and length of the original input. A 16-digit credit card number encrypts to another 16-digit number. A 9-digit SSN encrypts to another 9-digit SSN. The plaintext and ciphertext share the same alphabet and length.

FF3-1 is a revision of FF3, differing primarily in the tweak length: FF3-1 uses a fixed **7-byte (56-bit) tweak** rather than FF3's 8-byte tweak, addressing a known vulnerability in the original scheme.

### Typical use cases

- Tokenising credit card numbers, SSNs, and other PII in databases without changing schema
- Encrypting structured fields in legacy systems where format changes are not possible
- Data masking in regulated environments (healthcare, finance, defence)

---

## Algorithm overview

FF3-1 is an 8-round Feistel cipher. Each round:

1. Splits the input numeral string into two halves A and B
2. Builds a 16-byte PRF input block from the tweak and `NUMradix(REV(B))`
3. Computes the round keystream: `S = REVB(AES_REVB(K)(REVB(P)))`
4. Updates A as `C = (NUMradix(REV(A)) + S) mod radix^m`, then swaps halves

The underlying cipher is **AES-ECB on a single block** per round — justified because FPE requires a keyed pseudorandom permutation on a fixed 128-bit input, which is exactly what single-block AES provides. The Feistel structure provides the security guarantees, not the mode of operation.

### Key parameters

| Parameter | Value |
|---|---|
| Tweak length | Exactly 7 bytes |
| Rounds | 8 |
| Supported key sizes | 128, 192, 256 bits |
| Radix range | 2 – 65536 |
| Min plaintext length | 2 symbols |
| Max plaintext length | `2 * floor(96 / log2(radix))` |

---

## Implementation notes

All intermediate arithmetic uses **`u128`** rather than arbitrary-precision integers. This is safe because the NIST spec requires `radix^n < 2^96` for valid inputs — a constraint already enforced by the length check — meaning all intermediate values fit comfortably within 128 bits. This avoids heap allocation in the hot path and makes the implementation significantly faster than BigInt-based alternatives.

---

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
ff3_1 = { path = "." }
aes = "0.8"
```

### Numeric symbols (radix 10)

```rust
use ff3_1::Ff3Cipher;

let key   = hex::decode("2DE79D232DF5585D68CE47882AE256D6").unwrap();
let tweak = hex::decode("CBD09280979564").unwrap(); // exactly 7 bytes

let cipher = Ff3Cipher::new(&key, 10)?;

// Encrypt a 10-digit number as a Vec<u32> of digit symbols
let plaintext  = vec![3, 9, 9, 2, 5, 2, 0, 2, 4, 0];
let ciphertext = cipher.encrypt(&plaintext, &tweak)?;
let recovered  = cipher.decrypt(&ciphertext, &tweak)?;

assert_eq!(recovered, plaintext);
```

### String interface with custom alphabet

```rust
let cipher = Ff3Cipher::new(&key, 10)?;
let alphabet = "0123456789";

// Credit card tokenisation
let ccn       = "4111111111111111";
let encrypted = cipher.encrypt_str(ccn, &tweak, alphabet)?;
let decrypted = cipher.decrypt_str(&encrypted, &tweak, alphabet)?;

assert_eq!(decrypted, ccn);
assert_eq!(encrypted.len(), ccn.len()); // length preserved
```

### Alphabetic radix

```rust
let cipher = Ff3Cipher::new(&key, 26)?;
let alpha  = "abcdefghijklmnopqrstuvwxyz";

let ct = cipher.encrypt_str("secretmessage", &tweak, alpha)?;
// ct is another lowercase string of the same length
```

---

## Test vectors

Tests include:

- **ACVP draft vectors** for FF3-1 with 7-byte tweaks (AES-128 and AES-256)
- Round-trip correctness for radix-2, radix-10, radix-26, and SSN-style fields
- Error handling: bad key length, bad tweak length, short plaintext, out-of-range symbols
- Determinism and tweak sensitivity checks

> **Note on published NIST vectors:** The NIST SP 800-38G Appendix D sample vectors use 8-byte tweaks and are therefore **FF3 vectors, not FF3-1**. NIST has only published official test vectors for 64-bit tweaks. This implementation tests against draft ACVP vectors with the correct 56-bit tweak length.

Run the tests:

```bash
cargo test
```

---

## Security considerations

- **Tweak**: The tweak should be unique per record where possible (e.g. a record ID or table name). A constant tweak means the same plaintext always produces the same ciphertext, which leaks frequency information.
- **Domain size**: FF3-1 requires `radix^n >= 1,000,000` per the Rev 1 draft. Short inputs over small alphabets (e.g. 4-digit PINs) do not meet this threshold and should not be used.
- **Key management**: Treat the AES key with the same care as any symmetric encryption key. Compromise of the key allows full decryption.
- **FF3-1 is withdrawn**: NIST SP 800-38G Rev 1 Second Public Draft (February 2025) removes FF3-1, retaining only FF1. Consider using FF1 for new systems.

---

## License

MIT
