use crypto_library::{hamming_distance, test_hamming_distance};
use std::fs::File;
use std::io::Read;

fn main() {
    let x: &str = "this is a test";
    let y: &str = "wokka wokka!!!";

    let hamming = hamming_distance(x.as_bytes(), y.as_bytes());
    println!("{hamming}");

    let test = test_hamming_distance(x, 3);
    println!("{test}");

    let mut challenge = String::new();

    match File::open("src/challenge.txt") {
        Ok(mut file) => {
            file.read_to_string(&mut challenge).unwrap();
        }
        Err(error) => {
            panic!("Error opening file: {}", error);
        }
    };

    let mut distances: Vec<(f64, usize)> = Vec::new();
    for keysize in 2..40 {
        distances.push((test_hamming_distance(&challenge, keysize), keysize));
    }

    // pick every keysize-th element, keysize-th + 1 etc. and break single xor
}
