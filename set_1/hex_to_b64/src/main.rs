use crypto_library::hex_to_b64;

fn main() {
    let input_str: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64 = hex_to_b64(input_str).unwrap();
    println!("final: ");
    println!("{}", b64);
}
