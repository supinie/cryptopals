use std::{
    collections::BTreeMap,
    hash::{DefaultHasher, Hash, Hasher},
};

fn parse_str(input: &str) -> BTreeMap<String, String> {
    let mut object = BTreeMap::new();

    let entries: Vec<&str> = input.split('&').collect();

    entries.iter().for_each(|entry| {
        if let Some((key, value)) = entry.split_once("=") {
            object.insert(key.to_string(), value.to_string());
        } else {
            panic!("Invalid input, must be key value pairs");
        }
    });

    object
}

fn parse_obj(object: &BTreeMap<String, String>) -> String {
    let mut output = String::new();
    for (key, value) in object {
        if &output != "" {
            output.push_str("&");
        }
        output.push_str(key);
        output.push_str("=");
        output.push_str(value);
    }

    output
}

fn strip_metachars(input: &str) -> String {
    input.replace(&['&', '='][..], "")
}

fn uid(input: &str) -> u64 {
    let mut hasher = DefaultHasher::new();
    input.hash(&mut hasher);
    hasher.finish()
}

fn profile_for(email: &str) -> String {
    parse_obj(&BTreeMap::from([
        ("email".to_string(), strip_metachars(email)),
        ("uid".to_string(), uid(email).to_string()),
        ("role".to_string(), "user".to_string()),
    ]))
}

fn main() {
    // let test = parse_str("foo=bar&baz=quz&zap=zazzle");
    // let test_2 = parse_obj(&test);
    // println!("{test:?}");
    // println!("{test_2}");

    let test_user = profile_for("foo_1@bar.com&role=admin");
    println!("{test_user:?}");
}
