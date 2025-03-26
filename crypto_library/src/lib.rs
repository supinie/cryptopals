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
use rand::prelude::*;
use std::collections::HashMap;
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
    }
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

fn generic_arr_to_vec(gen_arr: &[GenericArray<u8, U16>]) -> Vec<u8> {
    gen_arr.iter().flatten().map(ToOwned::to_owned).collect()
}

#[must_use]
pub fn aes_128_ecb(key: &[u8], bytes: &[u8], mode: &Mode) -> Vec<u8> {
    let mut blocks = as_blocks(bytes);

    for block in &mut blocks {
        aes_block(key, block, mode);
    }

    generic_arr_to_vec(&blocks)
}

pub trait PKCS7 {
    #[must_use]
    fn pad(&self, size: usize) -> Vec<u8>;
    #[must_use]
    fn unpad(&self) -> Vec<u8>;
}

impl PKCS7 for Vec<u8> {
    #[allow(clippy::cast_possible_truncation)]
    fn pad(&self, block_size: usize) -> Self {
        let padding = block_size - self.len() % block_size;
        let required_bytes = vec![(padding) as u8; padding];

        [&self[..], &required_bytes[..]].concat()
    }

    fn unpad(&self) -> Self {
        let last = self.last();
        if let Some(padding_amount) = last {
            let data_len = self.len() - *padding_amount as usize;
            if self[data_len..].iter().all(|x| x == padding_amount) {
                return self[..data_len].to_vec();
            }
        }
        panic!("Invalid padding");
    }
}

impl PKCS7 for &[u8] {
    #[allow(clippy::cast_possible_truncation)]
    fn pad(&self, block_size: usize) -> Vec<u8> {
        self.to_vec().pad(block_size)
    }

    fn unpad(&self) -> Vec<u8> {
        self.to_vec().unpad()
    }
}

fn xor_generic_arr(x: &[u8], y: &[u8]) -> GenericArray<u8, U16> {
    *GenericArray::from_slice(&xor_bytes(x, y))
}

#[must_use]
pub fn aes_128_cbc(key: &[u8], bytes: &[u8], iv: &[u8], mode: &Mode) -> Vec<u8> {
    assert_eq!(iv.len(), 16);

    let mut blocks = as_blocks(bytes);
    let mut temp = iv.to_vec();

    for block in &mut blocks {
        match mode {
            Mode::Encrypt => {
                *block = xor_generic_arr(block.as_slice(), &temp);
                aes_block(key, block, mode);
                temp = block.to_vec();
            }
            Mode::Decrypt => {
                let ct = *block;
                aes_block(key, block, mode);
                *block = xor_generic_arr(block.as_slice(), &temp);
                temp = ct.to_vec();
            }
        }
    }

    generic_arr_to_vec(&blocks)
}

#[must_use]
pub fn random_aes_key() -> [u8; 16] {
    rand::random()
}

#[must_use]
pub fn aes_oracle(bytes: &[u8]) -> (String, Vec<u8>) {
    let key = random_aes_key();
    println!("{key:?}");

    let mut prefix = Vec::<u8>::new();
    let mut suffix = Vec::<u8>::new();

    let mut rng = rand::rng();
    for _ in 0..rng.random_range(5..=10) {
        prefix.push(rand::random());
    }

    for _ in 0..rng.random_range(5..=10) {
        suffix.push(rand::random());
    }

    let input = [&prefix, bytes, &suffix].concat().pad(16);

    if rand::random() {
        ("ECB".to_owned(), aes_128_ecb(&key, &input, &Mode::Encrypt))
    } else {
        let iv = random_aes_key();
        (
            "CBC".to_owned(),
            aes_128_cbc(&key, &input, &iv, &Mode::Encrypt),
        )
    }
}

#[must_use]
pub fn aes_mode_detector(ciphertext: &[u8]) -> String {
    let blocks: Vec<&[u8]> = ciphertext.chunks(16).collect();

    if blocks[1] == blocks[2] {
        "ECB".to_owned()
    } else {
        "CBC".to_owned()
    }
}

const ECB_ORACLE_KEY: [u8; 16] = [
    64, 89, 210, 107, 64, 254, 205, 40, 194, 186, 65, 174, 63, 112, 222, 159,
];

fn aes_ecb_oracle(bytes: &[u8]) -> Vec<u8> {
    let input = bytes.to_owned().pad(16);
    aes_128_ecb(&ECB_ORACLE_KEY, &input, &Mode::Encrypt)
}

fn generate_attacker_prefix(length: usize) -> Vec<u8> {
    vec![b"A"[0]; length]
}

fn generate_text(prefix: &[u8]) -> Vec<u8> {
    let mut text = prefix.to_owned();
    text.extend_from_slice(&get_challenge());
    text
}

fn find_blocksize(oracle: &dyn Fn(&[u8]) -> Vec<u8>) -> (usize, usize) {
    let l_1 = oracle(&generate_text(&generate_attacker_prefix(1))).len();
    for i in 2.. {
        let l_n = oracle(&generate_text(&generate_attacker_prefix(i))).len();
        if l_n > l_1 {
            // return (blocksize, suffix_len)
            return (l_n - l_1, l_1 - i);
        }
    }
    (0, 0)
}

fn generate_last_byte_dict(prefix: &[u8], block: usize, blocksize: usize) -> HashMap<Vec<u8>, u8> {
    let mut potential_blocks = HashMap::new();
    for i in 0..=255 {
        let mut plaintext = prefix.to_owned();
        plaintext.push(i);
        plaintext.extend_from_slice(&get_challenge()[block * (blocksize - 1)..]);
        let ct_block = aes_ecb_oracle(&plaintext)[0..blocksize].to_vec();
        potential_blocks.insert(ct_block, i);
    }
    potential_blocks
}

#[must_use]
pub fn byte_at_a_time() -> Vec<u8> {
    let mut plaintext = Vec::new();

    let (blocksize, suffix_len) = find_blocksize(&aes_ecb_oracle);
    assert_eq!(blocksize, 16);

    let test = [0u8; 60];
    let mode = aes_mode_detector(&aes_ecb_oracle(&test));
    assert_eq!(mode, "ECB".to_owned());

    let mut block = 0;
    while plaintext.len() < suffix_len - 1 {
        for i in 1..blocksize {
            if plaintext.len() == suffix_len {
                break;
            }
            let mut prefix = generate_attacker_prefix(blocksize - i);
            let mut input = prefix.clone();
            input.extend_from_slice(&get_challenge()[block * (blocksize - 1)..]);
            let target_block = &aes_ecb_oracle(&input)[0..blocksize];
            prefix.extend_from_slice(&plaintext[block * (blocksize - 1)..]);
            let target_dict = generate_last_byte_dict(&prefix, block, blocksize);
            if let Some(byte) = target_dict.get(target_block) {
                plaintext.push(*byte);
            } else {
                panic!("Target block not found");
            }
        }
        block += 1;
    }
    plaintext
}

fn random_prefix() -> Vec<u8> {
    let length = rand::rng().random_range(1..16);
    let mut prefix = Vec::new();

    for _ in 0..length {
        prefix.push(rand::random::<u8>());
    }

    prefix
}

fn find_harder_blocksize(oracle: &dyn Fn(&[u8]) -> Vec<u8>, prefix: &[u8]) -> (usize, usize) {
    let l_1 = oracle(&generate_text(
        &[prefix, &generate_attacker_prefix(1)].concat(),
    ))
    .len();
    for i in 2.. {
        let l_n = oracle(&generate_text(
            &[prefix, &generate_attacker_prefix(i)].concat(),
        ))
        .len();
        if l_n > l_1 {
            // return (blocksize, prefix + suffix len)
            return (l_n - l_1, l_1 - i);
        }
    }
    (0, 0)
}

fn find_prefix_len(oracle: &dyn Fn(&[u8]) -> Vec<u8>, prefix: &[u8]) -> usize {
    for i in 1.. {
        let ct_1 = oracle(&generate_text(
            &[prefix, &generate_attacker_prefix(i)].concat(),
        ));
        let ct_2 = oracle(&generate_text(
            &[prefix, &generate_attacker_prefix(i + 1)].concat(),
        ));
        if ct_1[..16] == ct_2[..16] {
            return 16 - i;
        }
    }
    0
}

#[must_use]
pub fn prefix_byte_at_a_time() -> Vec<u8> {
    let mut plaintext: Vec<u8> = Vec::new();

    let fixed_prefix = random_prefix();

    let (blocksize, pre_post_ffix_len) = find_harder_blocksize(&aes_ecb_oracle, &fixed_prefix);
    assert_eq!(blocksize, 16);
    let prefix_len = find_prefix_len(&aes_ecb_oracle, &fixed_prefix);
    let suffix_len = pre_post_ffix_len - prefix_len;

    let mut block = 0;
    while plaintext.len() < suffix_len - 1 {
        for i in 1..blocksize - prefix_len {
            if plaintext.len() == suffix_len {
                break;
            }
            let chosen_prefix = &[
                fixed_prefix.clone(),
                generate_attacker_prefix(blocksize - prefix_len - i),
            ][..]
                .concat();

            let target_block = &aes_ecb_oracle(
                &[
                    chosen_prefix.to_owned(),
                    get_challenge()[block * (blocksize - prefix_len - 1)..].to_vec(),
                ][..]
                    .concat()[..],
            )[..blocksize];

            let target_dict = generate_last_byte_dict(
                &[
                    chosen_prefix.clone(),
                    plaintext[block * (blocksize - prefix_len - 1)..].to_vec(),
                ][..]
                    .concat(),
                0,
                blocksize,
            );
            if let Some(byte) = target_dict.get(target_block) {
                plaintext.push(*byte);
            } else {
                panic!("Target block not found");
            }
        }
        block += 1;
    }
    plaintext
}
