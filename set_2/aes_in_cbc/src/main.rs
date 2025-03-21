use crypto_library::{Mode, PKCS7, aes_128_cbc, get_challenge};

fn main() {
    let challenge = get_challenge();

    let mut plaintext_bytes = aes_128_cbc(
        "YELLOW SUBMARINE".as_bytes(),
        &challenge,
        &[0u8; 16],
        &Mode::Decrypt,
    )
    .unpad();
    let plaintext = String::from_utf8_lossy(&plaintext_bytes);
    println!("{:?}", plaintext);
}
