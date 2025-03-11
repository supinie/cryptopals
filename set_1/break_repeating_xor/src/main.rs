use crypto_library::b64_to_bytes;
use frequency_analysis::break_repeating_xor;
use std::fs::File;
use std::io::Read;

fn main() {
    let mut challenge = String::new();

    match File::open("src/challenge.txt") {
        Ok(mut file) => {
            file.read_to_string(&mut challenge).unwrap();
        }
        Err(error) => {
            panic!("Error opening file: {}", error);
        }
    };

    let mut chall_chars: Vec<char> = challenge.chars().collect();
    chall_chars.retain(|&c| c != '\n');

    let chall_bytes = b64_to_bytes(&chall_chars);
    break_repeating_xor(&chall_bytes);
}
