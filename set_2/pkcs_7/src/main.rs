use crypto_library::{PKCS7, bytes_to_hex};

fn main() {
    let mut block = "YELLOW SUBMARINE".as_bytes().pad(20);

    println!("{:?}", bytes_to_hex(&block));

    println!("{:?}", bytes_to_hex(&block.unpad()));
}
