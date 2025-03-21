use crypto_library::{PKCS7, aes_128_ecb, random_aes_key};

fn parse_encoded(input: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut object = Vec::new();

    let entries: Vec<&[u8]> = input.split(|&character| b'&' == character).collect();

    entries.iter().for_each(|&entry| {
        entry
            .split(|character| b"=".contains(character))
            .collect::<Vec<_>>()
            .chunks_exact(2)
            .for_each(|pair| {
                object.push((pair[0].to_vec(), pair[1].to_vec()));
            });
    });

    object
}

fn parse_obj(object: &Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
    let mut output = Vec::new();
    for (key, value) in object {
        if !output.is_empty() {
            output.extend_from_slice(b"&");
        }
        output.extend_from_slice(key);
        output.extend_from_slice(b"=");
        output.extend_from_slice(value);
    }

    output
}

fn strip_metachars(input: &[u8]) -> Vec<u8> {
    input
        .split(|character| b"=&".contains(character))
        .flatten()
        .copied()
        .collect()
}

// fn uid(input: &[u8]) -> [u8; 8] {
//     let mut hasher = DefaultHasher::new();
//     input.hash(&mut hasher);
//     hasher.finish().to_le_bytes()
// }

fn profile_for(email: &[u8]) -> Vec<u8> {
    parse_obj(&Vec::from([
        (b"email".to_vec(), strip_metachars(email)),
        (b"uid".to_vec(), b"10".to_vec()),
        (b"role".to_vec(), b"user".to_vec()),
    ]))
}

fn encrypt_encoded_user(user: &[u8], key: &[u8]) -> Vec<u8> {
    aes_128_ecb(key, &user.pad(16), &crypto_library::Mode::Encrypt)
}

fn decrypt_user(ct: &[u8], key: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let bytes = aes_128_ecb(key, ct, &crypto_library::Mode::Decrypt).unpad();
    parse_encoded(&bytes)
}

fn construct_admin() -> Vec<(Vec<u8>, Vec<u8>)> {
    let user = b"foooo@bar.com";
    let mut user_2: Vec<u8> = Vec::new();
    user_2.extend_from_slice(&user[..10]);
    user_2.extend_from_slice(&b"admin".to_vec().pad(16));
    user_2.extend_from_slice(&user[10..]);

    let key = random_aes_key();
    let ct_1 = encrypt_encoded_user(&profile_for(user), &key);
    let ct_2 = encrypt_encoded_user(&profile_for(&user_2), &key);

    let admin_ct = [&ct_1[..32], &ct_2[16..32]].concat();
    decrypt_user(&admin_ct, &key)
}

fn main() {
    // let test = parse_encoded(b"foo=bar&baz=quz&zap=zazzle");
    // let test_2 = parse_obj(&test);
    // println!("{test:?}");
    // println!("{test_2:?}");

    // let test_user = profile_for(b"foo_1@bar.com&role=admin");
    // let user_string = String::from_utf8_lossy(&test_user);
    // println!("{user_string}");
    // let key = random_aes_key();
    // let ct = encrypt_encoded_user(&test_user, &key);
    // let output_user = parse_obj(&decrypt_user(&ct, &key));
    // let output_string = String::from_utf8_lossy(&output_user);
    // println!("{output_string}");

    let malicious_admin = parse_obj(&construct_admin());
    let string_admin = String::from_utf8_lossy(&malicious_admin);
    println!("{string_admin}");
}
