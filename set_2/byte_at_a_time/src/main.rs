use crypto_library::byte_at_a_time;

fn main() {
    let test = byte_at_a_time();
    println!("{test:?}");
    let plaintext = String::from_utf8_lossy(&test);
    println!("{plaintext}");
}
