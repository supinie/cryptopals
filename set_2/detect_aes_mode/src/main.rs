use crypto_library::{aes_mode_detector, aes_oracle};

fn main() {
    for _ in 0..1000 {
        let plaintext = [0u8; 2 * 16 + 16 - 5];
        let (mode, ciphertext) = aes_oracle(&plaintext);

        let guessed_mode = aes_mode_detector(&ciphertext);

        assert_eq!(mode, guessed_mode);
        println!("guessed mode correctly");
    }
}
