use frequency_analysis::freq_analysis;
use std::str;

fn main() {
    let input_str: &str = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let output = freq_analysis(input_str).unwrap();
    println!("key: {} | score: {}", output.key as char, output.value);
    println!("plaintext: {}", str::from_utf8(&output.plaintext).unwrap());
}
