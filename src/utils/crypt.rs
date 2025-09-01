use aes_gcm::{
    Aes256Gcm, Key, KeyInit,
    aead::{
        Aead,
        {consts::U12, generic_array::GenericArray},
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};

use anyhow::{Result, bail};

fn simple_nonce(seq: u8) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[11] = seq;
    nonce
}

fn init_cipher_and_nonce(
    key_ascii32: &str,
    seq: u8
) -> Result<(Aes256Gcm, GenericArray<u8, U12>)> {
    if key_ascii32.len() != 32 {
        bail!("Invalid key length (need 32 ASCII bytes)");
    }

    let key = Key::<Aes256Gcm>::from_slice(key_ascii32.as_bytes());
    let cipher = Aes256Gcm::new(key);

    let nonce_derived = simple_nonce(seq);
    // Nonce “owned” (GenericArray<u8, U12>)
    let nonce_owned: GenericArray<u8, U12> = GenericArray::clone_from_slice(&nonce_derived);

    Ok((cipher, nonce_owned))
}

// Decripts a base64 codified data using the provided key of 32 chars (256 bits)
// For this, extract first the base64 data, then, use a symmetric decryption algorithm
pub fn decrypt(
    data_base64: &str,
    key_ascii32: &str,
    seq: u8,
) -> Result<String> {
    // Data & nonce are base 64 encoded
    let data = decode_base_64(data_base64);
    if data.is_empty() || key_ascii32.len() != 32 {
        return Err(anyhow::anyhow!("Invalid input data"));
    }
    let (cipher, nonce) = init_cipher_and_nonce(key_ascii32, seq)?;
    let decrypted = cipher
        .decrypt(&nonce, data.as_ref())
        .map_err(|e| anyhow::anyhow!("Failed to decrypt data: {}", e))?;
    Ok(String::from_utf8_lossy(&decrypted).into_owned())
}

pub fn encrypt_field_b64(
    plaintext: &str,
    key_ascii32: &str,
    seq: u8,
) -> Result<String> {
    if key_ascii32.len() != 32 {
        bail!("Invalid key length (need 32 ASCII bytes)");
    }
    let (cipher, nonce) = init_cipher_and_nonce(key_ascii32, seq)?;

    let ct = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("Failed to encrypt data: {}", e))?;

    Ok(STANDARD.encode(ct))
    // Ok(URL_SAFE_NO_PAD.encode(ct))
}

// Decodes base64, ensures always has data. Not only used for decrypt, is an utility
pub fn decode_base_64(data_base64: &str) -> Vec<u8> {
    if let Ok(data) = STANDARD.decode(data_base64) {
        return data;
    }
    Vec::new()
}

pub fn encode_base_64(data: &[u8]) -> String {
    STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_encoding_decoding() {
        let original = b"Hello, world!";
        let encoded = encode_base_64(original);
        let decoded = decode_base_64(&encoded);
        assert_eq!(original.to_vec(), decoded);
    }
}