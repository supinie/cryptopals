#![warn(
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::checked_conversions,
    clippy::implicit_saturating_sub,
    clippy::panic_in_result_fn,
    clippy::unwrap_used,
    clippy::pedantic,
    clippy::nursery,
    rust_2018_idioms,
    unused_lifetimes,
    unused_qualifications
)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::missing_panics_doc)]

use aes::cipher::{consts::U16, generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes128;
use itertools::Itertools;
use std::fs::File;
use std::io::Read;
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
    bytes
        .iter()
        .enumerate()
        .fold(String::new(), |mut acc, (i, byte)| {
            if i > 0 {
                write!(acc, " ").unwrap();
            }
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

#[must_use]
pub fn b64_to_bytes(b64: &[char]) -> Vec<u8> {
    let mut bytes_vec: Vec<u8> = Vec::new();
    for octet_array in b64.chunks(4) {
        bytes_vec.extend(decode_chunk(octet_array));
    }

    bytes_vec
}

#[must_use]
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

#[must_use]
pub fn decode_chunk(encoded: &[char]) -> Vec<u8> {
    let mut buffer = [0u8; 4];

    #[allow(clippy::cast_possible_truncation)]
    for (i, &c) in encoded.iter().enumerate() {
        buffer[i] = if c == PADDING {
            0
        } else {
            B64_ARRAY
                .iter()
                .position(|&x| x == c)
                .expect("Only valid b64 chars") as u8
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

#[must_use]
pub fn hamming_distance(x: &[u8], y: &[u8]) -> u32 {
    x.iter()
        .zip(y)
        .fold(0, |a, (b, c)| a + (b ^ c).count_ones())
}

#[must_use]
#[allow(clippy::cast_precision_loss)]
pub fn test_hamming_distance(ciphertext: &[u8], keysize: usize) -> f64 {
    let chunks: Vec<&[u8]> = (0..4)
        .map(|i| &ciphertext[i * keysize..(i + 1) * keysize])
        .collect();
    let avg: f64 = chunks
        .iter()
        .combinations(2)
        .map(|pair| f64::from(hamming_distance(pair[0], pair[1])))
        .sum::<f64>()
        / 6.0;
    avg / keysize as f64
}

#[must_use]
pub fn get_challenge() -> Vec<u8> {
    let mut challenge = String::new();

    match File::open("src/challenge.txt") {
        Ok(mut file) => {
            file.read_to_string(&mut challenge)
                .expect("Valid text document");
        }
        Err(error) => {
            panic!("Error opening file: {error}");
        }
    };
    let mut chall_chars: Vec<char> = challenge.chars().collect();
    chall_chars.retain(|&c| c != '\n');

    b64_to_bytes(&chall_chars)
}

pub enum Mode {
    Encrypt,
    Decrypt,
}

fn aes_block(key: &[u8], block: &mut GenericArray<u8, U16>, mode: &Mode) {
    let key: &GenericArray<u8, U16> = GenericArray::from_slice(key);
    let cipher = Aes128::new(key);

    match mode {
        Mode::Encrypt => cipher.encrypt_block(block),
        Mode::Decrypt => cipher.decrypt_block(block),
    }
}

fn as_blocks(bytes: &[u8]) -> Vec<GenericArray<u8, U16>> {
    bytes
        .chunks(16)
        .map(|chunk| GenericArray::from_slice(chunk).to_owned())
        .collect()
}

fn generic_arr_to_vec(gen_arr: Vec<GenericArray<u8, U16>>) -> Vec<u8> {
    gen_arr.iter().flatten().map(ToOwned::to_owned).collect()
}

#[must_use]
pub fn aes_128_ecb(key: &[u8], bytes: &[u8], mode: &Mode) -> Vec<u8> {
    let mut blocks = as_blocks(bytes);

    for block in blocks.iter_mut() {
        aes_block(key, block, mode);
    }

    generic_arr_to_vec(blocks)
}

pub trait PKCS7 {
    fn pad(&mut self, size: usize);
}

impl PKCS7 for Vec<u8> {
    fn pad(&mut self, size: usize) {
        assert!(
            self.len() < size,
            "Length with padding must be longer than given block"
        );
        let mut required_bytes = vec![4u8; size - self.len()];

        self.append(&mut required_bytes);
    }
}

fn xor_generic_arr(x: &[u8], y: &[u8]) -> GenericArray<u8, U16> {
    *GenericArray::from_slice(&xor_bytes(x, y))
}

pub fn aes_128_cbc(key: &[u8], bytes: &[u8], iv: &[u8], mode: &Mode) -> Vec<u8> {
    assert_eq!(iv.len(), 16);

    let mut blocks = as_blocks(bytes);
    let mut temp = iv;

    for block in blocks.iter_mut() {
        *block = xor_generic_arr(block.as_slice(), temp);
        aes_block(key, block, mode);
        temp = block.as_slice();
    }

    generic_arr_to_vec(blocks)
}
