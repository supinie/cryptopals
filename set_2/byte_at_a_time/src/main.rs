use crypto_library::byte_at_a_time;

fn main() {
    let plaintext = byte_at_a_time();
    println!("{}", String::from_utf8_lossy(&plaintext));
}
