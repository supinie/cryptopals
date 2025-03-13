use crypto_library::{PKCS7, bytes_to_hex};

fn main() {
    let mut block = "YELLOW SUBMARINE".as_bytes().to_owned();

    block.pad(20);

    println!("{:?}", bytes_to_hex(&block));

    block.unpad();

    println!("{:?}", bytes_to_hex(&block));
}
