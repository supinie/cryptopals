use crypto_library::hex_to_bytes;
use frequency_analysis::{Score, freq_analysis};
use std::fs::File;
use std::io::{BufRead, BufReader};

fn main() {
    let challenge = File::open("src/challenge.txt").unwrap();
    let reader = BufReader::new(challenge);
    let mut scores: Vec<Score> = Vec::new();

    for line in reader.lines() {
        let line = line.unwrap();
        scores.push(freq_analysis(&hex_to_bytes(&line).unwrap()));
    }

    scores.sort_by(|a, b| a.value.partial_cmp(&b.value).unwrap());

    println!(
        "key: {} | score: {}",
        scores[0].key as char, scores[0].value
    );
    println!(
        "plaintext: {}",
        String::from_utf8_lossy(&scores[0].plaintext)
    );
}
