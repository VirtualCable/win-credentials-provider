// Copyright (c) 2026 Virtual Cable S.L.U.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without modification,
// are permitted provided that the following conditions are met:
//
//    * Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above copyright notice,
//      this list of conditions and the following disclaimer in the documentation
//      and/or other materials provided with the distribution.
//    * Neither the name of Virtual Cable S.L.U. nor the names of its contributors
//      may be used to endorse or promote products derived from this software
//      without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
/*!
Author: Adolfo Gómez, dkmaster at dkmon dot com
*/
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