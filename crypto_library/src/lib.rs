#![warn(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::checked_conversions,
    clippy::implicit_saturating_sub,
    clippy::panic,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    clippy::pedantic,
    clippy::nursery,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
#![allow(clippy::too_long_first_doc_paragraph)]

use itertools::Itertools;
use std::{char, fmt::Write};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

const B64_ARRAY: [char; 64] = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
    'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4',
    '5', '6', '7', '8', '9', '+', '/',
];

const PADDING: char = '=';

pub fn hex_to_b64(hex: &str) -> Result<String> {
    let bytes = hex_to_bytes(hex)?;
    Ok(bytes_to_b64(&bytes))
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>> {
    let mut bytes: Vec<u8> = Vec::new();
    for byte in hex.chars() {
        bytes.push(hex_to_u8(byte)?);
    }
    Ok(bytes
        .chunks(2)
        .map(|c| (c[0] << 4) + c[1])
        .collect::<Vec<u8>>())
}

#[must_use]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut acc, byte| {
        write!(acc, "{byte:02x?}").unwrap();
        acc
    })
}

fn hex_to_u8(byte: char) -> Result<u8> {
    #[allow(clippy::cast_possible_truncation)]
    byte.to_digit(16).map_or_else(
        || Err(format!("invalid hex char {byte}").into()),
        |i| Ok(i as u8),
    )
}

fn bytes_to_b64(bytes: &[u8]) -> String {
    let mut b64_vec: Vec<char> = Vec::new();
    for octet_array in bytes.chunks(3) {
        b64_vec.extend(encode_chunk(octet_array));
    }

    b64_vec.into_iter().collect::<String>()
}

pub fn b64_to_bytes(b64: &[char]) -> Vec<u8> {
    let mut bytes_vec: Vec<u8> = Vec::new();
    for octet_array in b64.chunks(4) {
        bytes_vec.extend(decode_chunk(octet_array));
    }

    bytes_vec
}

pub fn encode_chunk(chunk: &[u8]) -> Vec<char> {
    let mut b64 = Vec::new();
    match chunk.len() {
        3 => {
            b64.push(B64_ARRAY[(chunk[0] >> 2) as usize]);
            b64.push(B64_ARRAY[(((chunk[0] & 0b0000_0011) << 4) | chunk[1] >> 4) as usize]);
            b64.push(B64_ARRAY[(((chunk[1] & 0b0000_1111) << 2) | chunk[2] >> 6) as usize]);
            b64.push(B64_ARRAY[(chunk[2] & 0b0011_1111) as usize]);
        }
        2 => {
            b64.push(B64_ARRAY[(chunk[0] >> 2) as usize]);
            b64.push(B64_ARRAY[(((chunk[0] & 0b000_00011) << 4) | chunk[1] >> 4) as usize]);
            b64.push(B64_ARRAY[((chunk[1] & 0b0000_1111) << 2) as usize]);
            b64.push(PADDING);
        }
        1 => {
            b64.push(B64_ARRAY[(chunk[0] >> 2) as usize]);
            b64.push(B64_ARRAY[((chunk[0] & 0b0000_0011) << 4) as usize]);
            b64.push(PADDING);
            b64.push(PADDING);
        }
        _ => {}
    }
    b64
}

pub fn decode_chunk(encoded: &[char]) -> Vec<u8> {
    let mut buffer = [0u8; 4];

    for (i, &c) in encoded.iter().enumerate() {
        buffer[i] = if c == PADDING {
            0
        } else {
            B64_ARRAY.iter().position(|&x| x == c).unwrap() as u8
        };
    }

    let mut bytes = Vec::new();

    bytes.push((buffer[0] << 2) | (buffer[1] >> 4));
    if encoded[2] != PADDING {
        bytes.push((buffer[1] << 4) | (buffer[2] >> 2));
    }
    if encoded[3] != PADDING {
        bytes.push((buffer[2] << 6) | buffer[3]);
    }

    bytes
}

#[must_use]
pub fn xor_bytes(bytes_1: &[u8], bytes_2: &[u8]) -> Vec<u8> {
    bytes_1
        .iter()
        .zip(bytes_2.iter())
        .map(|(&byte_1, &byte_2)| byte_1 ^ byte_2)
        .collect()
}

#[must_use]
pub fn repeating_xor(key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let n = plaintext.len() / key.len();
    let long_key = key.repeat(n + 1);

    xor_bytes(&long_key, plaintext)
}

pub fn hamming_distance(x: &[u8], y: &[u8]) -> u32 {
    x.iter()
        .zip(y)
        .fold(0, |a, (b, c)| a + (b ^ c).count_ones() as u32)
}

pub fn test_hamming_distance(ciphertext: &[u8], keysize: usize) -> f64 {
    let chunks: Vec<&[u8]> = (0..4)
        .map(|i| &ciphertext[i * keysize..(i + 1) * keysize])
        .collect();
    let avg: f64 = chunks
        .iter()
        .combinations(2)
        .map(|pair| hamming_distance(pair[0], pair[1]) as f64)
        .sum::<f64>()
        / 6.0;
    avg / keysize as f64
}
