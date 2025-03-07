use crypto_library::{hamming_distance, test_hamming_distance};

fn main() {
    let x: &str = "this is a test";
    let y: &str = "wokka wokka!!!";

    let hamming = hamming_distance(x.as_bytes(), y.as_bytes());
    println!("{hamming}");

    let test = test_hamming_distance(x, 3);
    println!("{test}");
}
