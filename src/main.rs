use ff3_1::Ff3Cipher;

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn main() {
    // --- Example 1: Numeric (credit card style) ---
    let key   = hex_to_bytes("EF4359D8D580AA4F7F036D6F04FC6A94");
    let tweak = hex_to_bytes("D8E7920AFA330A"); // 7 bytes, FF3-1 standard
    let cipher = Ff3Cipher::new(&key, 10).expect("valid key");

    let plaintext  = "4111111111111111";
    let alphabet   = "0123456789";

    let encrypted  = cipher.encrypt_str(plaintext, &tweak, alphabet).unwrap();
    let decrypted  = cipher.decrypt_str(&encrypted, &tweak, alphabet).unwrap();

    println!("=== FF3-1 Demo ===");
    println!("Key:       EF4359D8D580AA4F7F036D6F04FC6A94");
    println!("Tweak:     D8E7920AFA330A");
    println!();
    println!("[Numeric radix-10]");
    println!("  Plaintext : {}", plaintext);
    println!("  Encrypted : {}", encrypted);
    println!("  Decrypted : {}", decrypted);
    println!("  Round-trip: {}", if decrypted == plaintext { "PASS" } else { "FAIL" });
    println!();

    // --- Example 2: Alphabetic (lowercase a-z) ---
    let alpha_cipher = Ff3Cipher::new(&key, 26).expect("valid key");
    let alpha_alphabet = "abcdefghijklmnopqrstuvwxyz";
    let alpha_pt = "secretmessage";

    let alpha_ct  = alpha_cipher.encrypt_str(alpha_pt, &tweak, alpha_alphabet).unwrap();
    let alpha_dec = alpha_cipher.decrypt_str(&alpha_ct, &tweak, alpha_alphabet).unwrap();

    println!("[Alphabetic radix-26]");
    println!("  Plaintext : {}", alpha_pt);
    println!("  Encrypted : {}", alpha_ct);
    println!("  Decrypted : {}", alpha_dec);
    println!("  Round-trip: {}", if alpha_dec == alpha_pt { "PASS" } else { "FAIL" });
    println!();

    // --- Example 3: SSN-style 9-digit field ---
    let ssn_pt = "123456789";
    let ssn_ct  = cipher.encrypt_str(ssn_pt, &tweak, alphabet).unwrap();
    let ssn_dec = cipher.decrypt_str(&ssn_ct, &tweak, alphabet).unwrap();

    println!("[SSN-style radix-10, 9 digits]");
    println!("  Plaintext : {}", ssn_pt);
    println!("  Encrypted : {}", ssn_ct);
    println!("  Decrypted : {}", ssn_dec);
    println!("  Round-trip: {}", if ssn_dec == ssn_pt { "PASS" } else { "FAIL" });
}
