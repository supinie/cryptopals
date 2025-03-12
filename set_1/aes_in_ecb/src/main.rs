use crypto_library::{Mode, aes_128_ecb, get_challenge};

fn main() {
    let challenge = get_challenge();
    let plaintext_bytes = aes_128_ecb("YELLOW SUBMARINE".as_bytes(), &challenge, &Mode::Decrypt);
    let plaintext = String::from_utf8_lossy(plaintext_bytes.as_slice());
    println!("{:?}", plaintext);
}
