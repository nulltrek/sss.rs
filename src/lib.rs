const LOG_TABLE: [i16; 256] = [
    0x00, 0xff, 0xc8, 0x08, 0x91, 0x10, 0xd0, 0x36, 0x5a, 0x3e, 0xd8, 0x43, 0x99, 0x77, 0xfe, 0x18,
    0x23, 0x20, 0x07, 0x70, 0xa1, 0x6c, 0x0c, 0x7f, 0x62, 0x8b, 0x40, 0x46, 0xc7, 0x4b, 0xe0, 0x0e,
    0xeb, 0x16, 0xe8, 0xad, 0xcf, 0xcd, 0x39, 0x53, 0x6a, 0x27, 0x35, 0x93, 0xd4, 0x4e, 0x48, 0xc3,
    0x2b, 0x79, 0x54, 0x28, 0x09, 0x78, 0x0f, 0x21, 0x90, 0x87, 0x14, 0x2a, 0xa9, 0x9c, 0xd6, 0x74,
    0xb4, 0x7c, 0xde, 0xed, 0xb1, 0x86, 0x76, 0xa4, 0x98, 0xe2, 0x96, 0x8f, 0x02, 0x32, 0x1c, 0xc1,
    0x33, 0xee, 0xef, 0x81, 0xfd, 0x30, 0x5c, 0x13, 0x9d, 0x29, 0x17, 0xc4, 0x11, 0x44, 0x8c, 0x80,
    0xf3, 0x73, 0x42, 0x1e, 0x1d, 0xb5, 0xf0, 0x12, 0xd1, 0x5b, 0x41, 0xa2, 0xd7, 0x2c, 0xe9, 0xd5,
    0x59, 0xcb, 0x50, 0xa8, 0xdc, 0xfc, 0xf2, 0x56, 0x72, 0xa6, 0x65, 0x2f, 0x9f, 0x9b, 0x3d, 0xba,
    0x7d, 0xc2, 0x45, 0x82, 0xa7, 0x57, 0xb6, 0xa3, 0x7a, 0x75, 0x4f, 0xae, 0x3f, 0x37, 0x6d, 0x47,
    0x61, 0xbe, 0xab, 0xd3, 0x5f, 0xb0, 0x58, 0xaf, 0xca, 0x5e, 0xfa, 0x85, 0xe4, 0x4d, 0x8a, 0x05,
    0xfb, 0x60, 0xb7, 0x7b, 0xb8, 0x26, 0x4a, 0x67, 0xc6, 0x1a, 0xf8, 0x69, 0x25, 0xb3, 0xdb, 0xbd,
    0x66, 0xdd, 0xf1, 0xd2, 0xdf, 0x03, 0x8d, 0x34, 0xd9, 0x92, 0x0d, 0x63, 0x55, 0xaa, 0x49, 0xec,
    0xbc, 0x95, 0x3c, 0x84, 0x0b, 0xf5, 0xe6, 0xe7, 0xe5, 0xac, 0x7e, 0x6e, 0xb9, 0xf9, 0xda, 0x8e,
    0x9a, 0xc9, 0x24, 0xe1, 0x0a, 0x15, 0x6b, 0x3a, 0xa0, 0x51, 0xf4, 0xea, 0xb2, 0x97, 0x9e, 0x5d,
    0x22, 0x88, 0x94, 0xce, 0x19, 0x01, 0x71, 0x4c, 0xa5, 0xe3, 0xc5, 0x31, 0xbb, 0xcc, 0x1f, 0x2d,
    0x3b, 0x52, 0x6f, 0xf6, 0x2e, 0x89, 0xf7, 0xc0, 0x68, 0x1b, 0x64, 0x04, 0x06, 0xbf, 0x83, 0x38,
];

const EXP_TABLE: [u8; 256] = [
    0x01, 0xe5, 0x4c, 0xb5, 0xfb, 0x9f, 0xfc, 0x12, 0x03, 0x34, 0xd4, 0xc4, 0x16, 0xba, 0x1f, 0x36,
    0x05, 0x5c, 0x67, 0x57, 0x3a, 0xd5, 0x21, 0x5a, 0x0f, 0xe4, 0xa9, 0xf9, 0x4e, 0x64, 0x63, 0xee,
    0x11, 0x37, 0xe0, 0x10, 0xd2, 0xac, 0xa5, 0x29, 0x33, 0x59, 0x3b, 0x30, 0x6d, 0xef, 0xf4, 0x7b,
    0x55, 0xeb, 0x4d, 0x50, 0xb7, 0x2a, 0x07, 0x8d, 0xff, 0x26, 0xd7, 0xf0, 0xc2, 0x7e, 0x09, 0x8c,
    0x1a, 0x6a, 0x62, 0x0b, 0x5d, 0x82, 0x1b, 0x8f, 0x2e, 0xbe, 0xa6, 0x1d, 0xe7, 0x9d, 0x2d, 0x8a,
    0x72, 0xd9, 0xf1, 0x27, 0x32, 0xbc, 0x77, 0x85, 0x96, 0x70, 0x08, 0x69, 0x56, 0xdf, 0x99, 0x94,
    0xa1, 0x90, 0x18, 0xbb, 0xfa, 0x7a, 0xb0, 0xa7, 0xf8, 0xab, 0x28, 0xd6, 0x15, 0x8e, 0xcb, 0xf2,
    0x13, 0xe6, 0x78, 0x61, 0x3f, 0x89, 0x46, 0x0d, 0x35, 0x31, 0x88, 0xa3, 0x41, 0x80, 0xca, 0x17,
    0x5f, 0x53, 0x83, 0xfe, 0xc3, 0x9b, 0x45, 0x39, 0xe1, 0xf5, 0x9e, 0x19, 0x5e, 0xb6, 0xcf, 0x4b,
    0x38, 0x04, 0xb9, 0x2b, 0xe2, 0xc1, 0x4a, 0xdd, 0x48, 0x0c, 0xd0, 0x7d, 0x3d, 0x58, 0xde, 0x7c,
    0xd8, 0x14, 0x6b, 0x87, 0x47, 0xe8, 0x79, 0x84, 0x73, 0x3c, 0xbd, 0x92, 0xc9, 0x23, 0x8b, 0x97,
    0x95, 0x44, 0xdc, 0xad, 0x40, 0x65, 0x86, 0xa2, 0xa4, 0xcc, 0x7f, 0xec, 0xc0, 0xaf, 0x91, 0xfd,
    0xf7, 0x4f, 0x81, 0x2f, 0x5b, 0xea, 0xa8, 0x1c, 0x02, 0xd1, 0x98, 0x71, 0xed, 0x25, 0xe3, 0x24,
    0x06, 0x68, 0xb3, 0x93, 0x2c, 0x6f, 0x3e, 0x6c, 0x0a, 0xb8, 0xce, 0xae, 0x74, 0xb1, 0x42, 0xb4,
    0x1e, 0xd3, 0x49, 0xe9, 0x9c, 0xc8, 0xc6, 0xc7, 0x22, 0x6e, 0xdb, 0x20, 0xbf, 0x43, 0x51, 0x52,
    0x66, 0xb2, 0x76, 0x60, 0xda, 0xc5, 0xf3, 0xf6, 0xaa, 0xcd, 0x9a, 0xa0, 0x75, 0x54, 0x0e, 0x01,
];

#[derive(Debug)]
enum Error {
    DivisionByZero,
    CannotEvaluateAtZero,
    IndexOutOfBounds,
    DifferentLenShares,
}

fn add(a: u8, b: u8) -> u8 {
    a ^ b
}

fn div(a: u8, b: u8) -> Result<u8, Error> {
    if b == 0 {
        return Err(Error::DivisionByZero);
    }

    if a == 0 {
        return Ok(0);
    }

    let log_a = LOG_TABLE[a as usize];
    let log_b = LOG_TABLE[b as usize];
    let diff = (log_a - log_b + 255) % 255;
    Ok(EXP_TABLE[diff as usize])
}

fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        return 0;
    }

    let log_a = LOG_TABLE[a as usize];
    let log_b = LOG_TABLE[b as usize];
    let diff = (log_a + log_b) % 255;
    EXP_TABLE[diff as usize]
}

fn interpolate_polynomial(x_samples: &[u8], y_samples: &[u8], x: u8) -> Result<u8, Error> {
    if x_samples.len() != y_samples.len() {
        return Err(Error::DifferentLenShares);
    }

    let samples_len = x_samples.len();
    let mut basis;
    let mut result = 0;

    for i in 0..samples_len {
        basis = 1;
        for j in 0..samples_len {
            if i != j {
                let num = add(x, x_samples[j]);
                let denom = add(x_samples[i], x_samples[j]);
                let term = div(num, denom)?;
                basis = mul(basis, term);
            }
        }
        result = add(result, mul(y_samples[i], basis));
    }

    Ok(result)
}

fn evaluate(coefficients: &[u8], x: u8, degree: u8) -> Result<u8, Error> {
    if x == 0 {
        return Err(Error::CannotEvaluateAtZero);
    }

    if degree >= coefficients.len() as u8 {
        return Err(Error::IndexOutOfBounds);
    }

    let mut result = coefficients[degree as usize];
    for i in (0..degree).rev() {
        let coefficient = coefficients[i as usize];
        result = add(mul(result, x), coefficient)
    }

    Ok(result)
}

fn get_random_bytes(n: usize) -> Vec<u8> {
    use rand::{thread_rng, RngCore};

    let mut bytes = vec![0; n];
    thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn new_coefficients(intercept: u8, degree: u8) -> Vec<u8> {
    let mut coefficients = get_random_bytes(degree as usize + 1);
    coefficients[0] = intercept;
    coefficients
}

fn new_coordinates() -> [u8; 255] {
    let mut coordinates = [0; 255];
    for i in 0..coordinates.len() {
        coordinates[i] = i as u8 + 1;
    }

    let random_indices = get_random_bytes(255);
    for i in 0..coordinates.len() {
        let random_index = random_indices[i] as usize % 255;
        coordinates.swap(i, random_index);
    }

    coordinates
}

#[derive(Debug)]
pub enum SSSError {
    SharesOutOfRange,
    ThresholdOutOfRange,
    SharesLenMismatch,
    ShareTooSmall,
    DuplicateShare,
    SharesLessThanThreshold(u8, u8),
    EmptySecret,
    PolinomialEvalFailed,
    PolinomialInterpolationFailed,
}

pub fn split(secret: &[u8], shares: u8, threshold: u8) -> Result<Vec<Vec<u8>>, SSSError> {
    if secret.len() == 0 {
        return Err(SSSError::EmptySecret);
    }
    if !(2..=255).contains(&shares) {
        return Err(SSSError::SharesOutOfRange);
    }
    if !(2..=255).contains(&threshold) {
        return Err(SSSError::ThresholdOutOfRange);
    }

    if shares < threshold {
        return Err(SSSError::SharesLessThanThreshold(shares, threshold));
    }

    let mut result: Vec<Vec<u8>> = Vec::with_capacity(shares as usize);
    let x_coordinates = new_coordinates();

    for i in 0..shares {
        let mut share = vec![0; secret.len() + 1];
        share[secret.len()] = x_coordinates[i as usize];
        result.push(share);
    }

    let degree = threshold - 1;

    for i in 0..secret.len() {
        let byte = secret[i];
        let coefficients = new_coefficients(byte, degree);

        for j in 0..shares {
            let x = x_coordinates[j as usize];
            let y = match evaluate(&coefficients, x, degree) {
                Ok(y) => y,
                Err(_) => return Err(SSSError::PolinomialEvalFailed),
            };
            result[j as usize][i] = y;
        }
    }

    Ok(result)
}

pub fn combine(shares: &[Vec<u8>]) -> Result<Vec<u8>, SSSError> {
    use std::collections::HashSet;

    if !(2..=255).contains(&shares.len()) {
        return Err(SSSError::SharesOutOfRange);
    }

    for share in shares {
        if share.len() != shares[0].len() {
            return Err(SSSError::SharesLenMismatch);
        }
        if share.len() < 2 {
            return Err(SSSError::ShareTooSmall);
        }
    }

    let secret_length = shares[0].len() - 1;
    let mut secret = vec![0; secret_length];

    let mut x_samples = vec![0; shares.len()];
    let mut y_samples = vec![0; shares.len()];

    let mut samples = HashSet::new();
    for i in 0..shares.len() {
        let share = &shares[i];
        let sample = share[share.len() - 1];
        if samples.contains(&sample) {
            return Err(SSSError::DuplicateShare);
        }
        samples.insert(sample);
        x_samples[i] = sample;
    }

    for i in 0..secret_length {
        for j in 0..shares.len() {
            y_samples[j] = shares[j][i];
        }

        secret[i] = match interpolate_polynomial(&x_samples, &y_samples, 0) {
            Ok(res) => res,
            Err(_) => return Err(SSSError::PolinomialInterpolationFailed),
        }
    }

    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_numbers() {
        assert_eq!(add(0b00000000, 0b00000000), 0b00000000);
        assert_eq!(add(0b11111111, 0b00000000), 0b11111111);
        assert_eq!(add(0b10101010, 0b01010101), 0b11111111);
    }

    #[test]
    fn div_numbers() {
        assert_eq!(div(20, 170).unwrap(), 115);
        assert_eq!(div(255, 255).unwrap(), 1);
        assert_eq!(div(0, 47).unwrap(), 0);
        assert_eq!(div(65, 32).unwrap(), 56);
        assert!(div(1, 0).is_err());
    }

    #[test]
    fn mul_numbers() {
        assert_eq!(mul(20, 170), 208);
        assert_eq!(mul(48, 2), 96);
        assert_eq!(mul(231, 169), 176);
        assert_eq!(mul(255, 255), 19);
        assert_eq!(mul(0, 47), 0);
        assert_eq!(mul(65, 32), 248);
    }

    #[test]
    fn random_bytes() {
        let bytes = get_random_bytes(255);
        assert_eq!(bytes.len(), 255);
    }

    const SECRET: [u8; 6] = [0x73, 0x65, 0x63, 0x72, 0x65, 0x74];

    #[test]
    fn split_invalid() {
        let res = split(&[], 3, 2);
        assert!(res.is_err());

        let res = split(&SECRET, 1, 2);
        assert!(res.is_err());

        let res = split(&SECRET, 3, 4);
        assert!(res.is_err());
    }

    #[test]
    fn combine_invalid() {
        let share_1 = vec![0xff, 0x23];
        let share_2 = vec![0xc1, 0xa7, 0x04];

        let shares = combine(&[share_1.clone()]);
        assert!(shares.is_err());

        let shares = combine(&[share_1, share_2]);
        assert!(shares.is_err());
    }

    #[test]
    fn split_secret() {
        let shares = split(&SECRET, 3, 2);
        assert!(shares.is_ok());
        let shares = shares.unwrap();
        assert_eq!(shares.len(), 3);

        assert_eq!(shares[0].len(), SECRET.len() + 1);
        assert_eq!(shares[1].len(), SECRET.len() + 1);
        assert_eq!(shares[2].len(), SECRET.len() + 1);

        let reconstructed = combine(&shares);
        assert!(reconstructed.is_ok());
        assert_eq!(reconstructed.unwrap(), SECRET);
    }

    #[test]
    fn split_short_secret() {
        let secret = [0x28];
        let shares = split(&secret, 3, 2);
        assert!(shares.is_ok());
        let shares = shares.unwrap();
        assert_eq!(shares.len(), 3);

        assert_eq!(shares[0].len(), 2);
        assert_eq!(shares[1].len(), 2);
        assert_eq!(shares[2].len(), 2);

        let reconstructed = combine(&shares);
        assert!(reconstructed.is_ok());
        assert_eq!(reconstructed.unwrap(), secret);
    }

    #[test]
    fn combine_all_shares() {
        let shares = split(&SECRET, 3, 3);
        let reconstructed = combine(&shares.unwrap());
        assert!(reconstructed.is_ok());
        assert_eq!(reconstructed.unwrap(), SECRET);
    }

    #[test]
    fn combine_all_combinations() {
        let shares = split(&SECRET, 3, 3);
        let reconstructed = combine(&shares.unwrap());
        assert!(reconstructed.is_ok());
        assert_eq!(reconstructed.unwrap(), SECRET);

        let shares = split(&SECRET, 5, 3).unwrap();
        assert_eq!(shares.len(), 5);

        // Test combining all permutations of 3 shares
        for i in 0..5 {
            assert_eq!(shares[i].len(), SECRET.len() + 1);

            for j in 0..5 {
                if j == i {
                    continue;
                }
                for k in 0..5 {
                    if k == i || k == j {
                        continue;
                    }
                    let reconstructed =
                        combine(&[shares[i].clone(), shares[j].clone(), shares[k].clone()]);
                    assert_eq!(reconstructed.unwrap(), SECRET);
                }
            }
        }
    }
}
