const B64_ARRAY: [char; 64] = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P','Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'];

const PADDING: char = '=';


fn main() {
    let input_str: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let b64 = hex2b64(input_str);
    println!("{}", b64);
}

pub fn hex2b64(hex: &str) -> String {
    let bytes = hex2bytes(hex);
    let b64 = bytes2b64(bytes);
    return b64;
}

fn hex2bytes(hex: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for byte in hex.chars() {
        let byte_result = u8::from_str_radix(&byte.to_string(), 16);
        match byte_result {
            Ok(value) => bytes.push(value),
            Err(error) => ()
        }
    }
    println!("{:?}", bytes);
    return bytes;
}

fn bytes2b64(bytes: Vec<u8>) -> String {
    let mut b64: Vec<char> = Vec::new();
    for octet_array in bytes.as_slice().chunks(6) {
        b64.extend(encode_chunks(octet_array));
    }

    return b64.into_iter().collect::<String>();
}

fn encode_chunks(chunks: &[u8]) -> Vec<char> {
    let mut b64 = Vec::new();
    match chunks.len() {
        3 => {
            b64.push(B64_ARRAY[(chunks[0] >> 2) as usize]);
            b64.push(B64_ARRAY[(((chunks[0] & 0b00000011) << 4) | chunks[1] >> 4) as usize]);
            b64.push(B64_ARRAY[(((chunks[1] & 0b00001111) << 2) | chunks[2] >> 6) as usize]);
            b64.push(B64_ARRAY[(chunks[2] & 0b00111111) as usize]);
        },
        2 => {
            b64.push(B64_ARRAY[(chunks[0] >> 2) as usize]);
            b64.push(B64_ARRAY[(((chunks[0] & 0b00000011) << 4) | chunks[1] >> 4) as usize]);
            b64.push(B64_ARRAY[((chunks[1] & 0b00001111) << 2) as usize]);
            b64.push(PADDING);
        },
        1 => {
            b64.push(B64_ARRAY[(chunks[0] >> 2) as usize]);
            b64.push(B64_ARRAY[((chunks[0] & 0b00000011) << 4) as usize]);
            b64.push(PADDING);
            b64.push(PADDING);
        },
        _ => {}
    }
    return b64;
}
