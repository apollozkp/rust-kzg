extern crate alloc;

use std::io::{Read, Write};

use alloc::sync::Arc;
use alloc::vec::Vec;

use kzg::eip_4844::hash_to_bls_field;
use kzg::{Fr, G1Mul, G2Mul, G1, G2};

use crate::consts::{G1_GENERATOR, G2_GENERATOR};
use crate::types::g1::FsG1;
use crate::types::g2::FsG2;

pub fn generate_trusted_setup(n: usize, secret: [u8; 32usize]) -> (Vec<FsG1>, Vec<FsG2>) {
    let s = hash_to_bls_field(&secret);
    let mut s_pow = Fr::one();

    let mut s1 = Vec::with_capacity(n);
    let mut s2 = Vec::with_capacity(n);

    for _ in 0..n {
        s1.push(G1_GENERATOR.mul(&s_pow));
        s2.push(G2_GENERATOR.mul(&s_pow));

        s_pow = s_pow.mul(&s);
    }

    (s1, s2)
}

pub fn load_g1(
    reader: &mut std::io::BufReader<std::fs::File>,
    compressed: bool,
) -> Result<Vec<FsG1>, String> {
    const COMPRESSED_BYTES: usize = 48;
    const UNCOMPRESSED_BYTES: usize = 96;
    let mut g1_size_bytes = [0u8; 8];
    reader
        .read_exact(&mut g1_size_bytes)
        .map_err(|e| e.to_string())?;
    let g1_size = u64::from_le_bytes(g1_size_bytes);

    if compressed {
        fn g1_handler(bytes: &[u8; COMPRESSED_BYTES]) -> FsG1 {
            FsG1::from_bytes(bytes).expect("Failed to parse G1 element")
        }

        kzg::io_utils::batch_reader::<COMPRESSED_BYTES, FsG1>(
            reader,
            g1_size as usize,
            Arc::new(g1_handler),
            None,
        )
    } else {
        fn g1_handler(bytes: &[u8; UNCOMPRESSED_BYTES]) -> FsG1 {
            FsG1::deserialize(bytes).expect("Failed to parse G1 element")
        }

        kzg::io_utils::batch_reader::<UNCOMPRESSED_BYTES, FsG1>(
            reader,
            g1_size as usize,
            Arc::new(g1_handler),
            None,
        )
    }
}

pub fn load_g2(
    reader: &mut std::io::BufReader<std::fs::File>,
    compressed: bool,
) -> Result<Vec<FsG2>, String> {
    const COMPRESSED_BYTES: usize = 96;
    const UNCOMPRESSED_BYTES: usize = 192;
    let mut g2_size_bytes = [0u8; 8];
    reader
        .read_exact(&mut g2_size_bytes)
        .map_err(|e| e.to_string())?;
    let g2_size = u64::from_le_bytes(g2_size_bytes);

    if compressed {
        fn g2_handler(bytes: &[u8; COMPRESSED_BYTES]) -> FsG2 {
            FsG2::from_bytes(bytes).expect("Failed to parse G2 element")
        }

        kzg::io_utils::batch_reader::<COMPRESSED_BYTES, FsG2>(
            reader,
            g2_size as usize,
            Arc::new(g2_handler),
            None,
        )
    } else {
        fn g2_handler(bytes: &[u8; UNCOMPRESSED_BYTES]) -> FsG2 {
            FsG2::deserialize(bytes).expect("Failed to parse G2 element")
        }

        kzg::io_utils::batch_reader::<UNCOMPRESSED_BYTES, FsG2>(
            reader,
            g2_size as usize,
            Arc::new(g2_handler),
            None,
        )
    }
}

pub fn load_secrets_from_file(
    path: &str,
    compressed: bool,
) -> Result<(Vec<FsG1>, Vec<FsG2>), String> {
    let file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut reader = std::io::BufReader::new(file);

    Ok((
        load_g1(&mut reader, compressed)?,
        load_g2(&mut reader, compressed)?,
    ))
}

pub fn save_secrets_to_file(
    file_path: &str,
    secret_g1: &[FsG1],
    secret_g2: &[FsG2],
    compressed: bool,
) -> Result<(), String> {
    let mut file = std::fs::File::create(file_path).unwrap();

    let encoded_s1_size = secret_g1.len() as u64;
    Write::write(&mut file, &encoded_s1_size.to_le_bytes()).unwrap();
    for el in secret_g1.iter() {
        if compressed {
            let bytes = el.to_bytes();
            Write::write(&mut file, &bytes).unwrap();
        } else {
            let bytes = el.serialize();
            Write::write(&mut file, &bytes).unwrap();
        }
    }

    let encoded_s2_size = secret_g2.len() as u64;
    Write::write(&mut file, &encoded_s2_size.to_le_bytes()).unwrap();
    for el in secret_g2.iter() {
        if compressed {
            let bytes = el.to_bytes();
            Write::write(&mut file, &bytes).unwrap();
        } else {
            let bytes = el.serialize();
            Write::write(&mut file, &bytes).unwrap();
        }
    }

    Ok(())
}
