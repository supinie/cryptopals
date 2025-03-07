use crypto_library::bytes_to_hex;
use crypto_library::hex_to_bytes;
use crypto_library::xor_bytes;

fn main() {
    let input_str: &str = "1c0111001f010100061a024b53535009181c";
    let fixed_str: &str = "686974207468652062756c6c277320657965";
    let bytes_input = hex_to_bytes(input_str);
    let bytes_fixed = hex_to_bytes(fixed_str);
    let xor_bytes = xor_bytes(bytes_input, bytes_fixed);
    let xor_hex = bytes_to_hex(xor_bytes);
    println!("final: ");
    println!("{}", xor_hex);
}
