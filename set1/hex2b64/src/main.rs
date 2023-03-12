use base64::{engine::general_purpose, Engine as _};

fn main() {
    let input_str: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let bytes = hex2bytes(input_str);
    let b64 = bytes2b64(bytes);
    println!("{}", b64);
}

pub fn hex2bytes(hex: &str) -> Vec<u8> {
    let bytes: Vec<u8> = hex.as_bytes().to_vec();
    return bytes;
}

pub fn bytes2b64(bytes: Vec<u8>) -> String {
    let b64 = general_purpose::STANDARD.encode(&bytes);
    return b64;
}
