use crypto_library::hex_to_bytes;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn main() {
    let challenge = File::open("src/challenge.txt").unwrap();
    let reader = BufReader::new(challenge);

    for (i, line) in reader.lines().enumerate() {
        let potential_ciphertext = hex_to_bytes(&line.expect("Valid UTF-8 string")).unwrap();
        let unique_blocks = potential_ciphertext
            .chunks(16)
            .enumerate()
            .map(|(i, chunk)| (chunk, i))
            .collect::<HashMap<&[u8], usize>>();

        if unique_blocks.len() != potential_ciphertext.len() / 16 {
            println!("Line {i} likely aes_128_ecb ciphertext",);
        }
    }
}
