use crypto_library::{bytes_to_hex, repeating_xor};

fn main() {
    let input = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";

    let key = "ICE";

    let ciphertext = repeating_xor(key.as_bytes(), input.as_bytes());
    let cipher_hex = bytes_to_hex(&ciphertext);

    println!("{ciphertext:?}");
    println!("{cipher_hex}");
}
