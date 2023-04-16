use std::char;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

const B64_ARRAY: [char; 64] = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P','Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'];

const PADDING: char = '=';

pub fn hex_2_b64(hex: &str) -> String {
    let bytes = hex_2_bytes(hex);
    let b64 = bytes_2_b64(bytes);
    return b64;
}

pub fn hex_2_bytes(hex: &str) -> Vec<u8> {
    let mut bytes: Vec<u8> = Vec::new();
    for byte in hex.chars() {
        bytes.push(hex_2_u8(byte).unwrap());
    }
    return bytes.chunks(2).map(|c| (c[0] << 4) + c[1]).collect::<Vec<u8>>();
}

fn hex_2_u8(byte: char) -> Result<u8> {
    match byte.to_digit(16) {
        Some(i) => Ok(i as u8),
        _ => Err(format!("invalid hex char {}", byte).into()),
    }
}

fn bytes_2_b64(bytes: Vec<u8>) -> String {
    let mut b64_vec: Vec<char> = Vec::new();
    for octet_array in bytes.as_slice().chunks(3) {
        b64_vec.extend(encode_chunks(octet_array));
    }

    let b64_string = b64_vec.into_iter().collect::<String>();
    return b64_string;
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
