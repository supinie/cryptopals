use crypto_library::{b64_to_bytes, repeating_xor, test_hamming_distance};
use frequency_analysis::freq_analysis;
use std::fs::File;
use std::io::Read;

fn partition_vec(input: &[u8], n: usize) -> Vec<Vec<u8>> {
    let mut output = vec![Vec::new(); n];
    for (i, &value) in input.iter().enumerate() {
        output[i % n].push(value);
    }

    output
}

fn main() {
    // let x: &str = "this is a test";
    // let y: &str = "wokka wokka!!!";

    // let hamming = hamming_distance(x.as_bytes(), y.as_bytes());
    // println!("{hamming}");

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

    let mut distances: Vec<(f64, usize)> = Vec::new();
    for keysize in 2..40 {
        distances.push((test_hamming_distance(&chall_bytes, keysize), keysize));
    }

    distances.sort_by(|(a, _), (b, _)| a.partial_cmp(b).unwrap());

    let mut potential_keys = Vec::new();

    for i in 0..3 {
        let split_chall = partition_vec(&chall_bytes, distances[i].1);

        let mut cracked_key = Vec::new();
        for block in split_chall {
            cracked_key.push(freq_analysis(&block));
        }

        potential_keys.push(cracked_key);
    }

    for potential_key in potential_keys {
        let mut key = Vec::new();
        for score in potential_key {
            key.push(score.key as char);
        }
        let key_str: String = key.into_iter().collect();
        let plaintext_bytes = repeating_xor(&key_str, &challenge);
        let plaintext = std::str::from_utf8(&plaintext_bytes).unwrap();

        println!("{}", key_str);
        println!("{}", plaintext);
    }
}
