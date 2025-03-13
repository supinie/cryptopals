use crypto_library::{Mode, aes_128_cbc, get_challenge};

fn main() {
    let challenge = get_challenge();

    let plaintext_bytes = aes_128_cbc(
        "YELLOW SUBMARINE".as_bytes(),
        &challenge,
        &[0u8; 16],
        &Mode::Decrypt,
    );
    let plaintext = String::from_utf8_lossy(&plaintext_bytes);
    println!("{:?}", plaintext);
}
