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
#![allow(clippy::missing_panics_doc)]

use crypto_library::xor_bytes;
use std::collections::HashMap;

#[derive(Debug)]
pub struct Score {
    pub value: f64,
    pub key: u8,
    pub plaintext: Vec<u8>,
}

fn score_text(text: &[u8]) -> f64 {
    let frequencies: HashMap<char, f64> = HashMap::from([
        ('a', 0.077_432_086_275_501_65),
        ('b', 0.014_022_415_866_975_27),
        ('c', 0.026_656_706_673_293_59),
        ('d', 0.049_207_857_023_118_75),
        ('e', 0.134_645_189_940_798_83),
        ('f', 0.025_036_247_121_552_113),
        ('g', 0.017_007_472_935_972_733),
        ('h', 0.057_198_398_950_671_57),
        ('i', 0.062_947_942_369_282_44),
        ('j', 0.001_267_546_400_727_001),
        ('k', 0.005_084_890_317_533_608),
        ('l', 0.037_061_762_742_370_46),
        ('m', 0.030_277_007_414_117_114),
        ('n', 0.071_253_165_189_823_16),
        ('o', 0.073_800_021_762_977_65),
        ('p', 0.017_513_315_119_093_483),
        ('q', 0.000_949_924_564_813_970_7),
        ('r', 0.061_071_620_783_055_46),
        ('s', 0.061_262_782_073_188_304),
        ('t', 0.087_604_807_853_493_99),
        ('u', 0.030_426_995_503_298_266),
        ('v', 0.011_137_350_857_431_91),
        ('w', 0.021_680_631_243_989_45),
        ('x', 0.001_988_077_417_381_560_7),
        ('y', 0.022_836_421_813_561_863),
        ('z', 0.000_629_361_785_975_819_5),
    ]);

    let mut score: f64 = 0.0;
    for (letter, freq) in frequencies {
        #[allow(clippy::cast_precision_loss)]
        let actual_freq: f64 = bytecount::count(text, letter as u8) as f64 / text.len() as f64;
        let err = (actual_freq - freq).abs();
        score += err;
    }

    score
}

#[must_use]
pub fn freq_analysis(bytes: &[u8]) -> Score {
    let mut min_score = Score {
        value: f64::INFINITY,
        key: 0,
        plaintext: vec![0u8],
    };

    for i in 0..u8::MAX {
        let key = vec![i; bytes.len()];

        let plaintext = xor_bytes(&key, bytes);
        let score = score_text(&plaintext);
        #[allow(clippy::float_cmp)]
        if min_score.value.min(score) == score {
            min_score = Score {
                value: score,
                key: i,
                plaintext,
            };
        }
    }

    min_score
}
