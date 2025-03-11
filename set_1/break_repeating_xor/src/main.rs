use crypto_library::get_challenge;
use frequency_analysis::break_repeating_xor;

fn main() {
    let challenge = get_challenge();
    break_repeating_xor(&challenge);
}
