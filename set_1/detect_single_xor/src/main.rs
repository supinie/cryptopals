use frequency_analysis::{Score, freq_analysis};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::str;

fn main() {
    let challenge = File::open("src/challenge.txt").unwrap();
    let reader = BufReader::new(challenge);
    let mut scores: Vec<Score> = Vec::new();

    for line in reader.lines() {
        let line = line.unwrap();
        scores.push(freq_analysis(&line).unwrap());
    }

    scores.sort_by(|a, b| a.value.partial_cmp(&b.value).unwrap());

    println!(
        "key: {} | score: {}",
        scores[0].key as char, scores[0].value
    );
    println!(
        "plaintext: {}",
        str::from_utf8(&scores[0].plaintext).unwrap()
    );
}
