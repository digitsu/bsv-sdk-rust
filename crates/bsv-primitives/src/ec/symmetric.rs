//! Symmetric key encryption using ECDH shared secrets and AES-GCM.
//!
//! Derives a shared symmetric key from two EC key pairs and provides
//! authenticated encryption/decryption. Uses AES-256-GCM with a 32-byte
//! initialization vector.

use rand::RngCore;

use crate::PrimitivesError;

/// IV (initialization vector) length used by the Go SDK (32 bytes).
const IV_LEN: usize = 32;

/// AES-GCM authentication tag length (16 bytes).
const TAG_LEN: usize = 16;

/// A symmetric encryption key derived from ECDH.
///
/// Provides AES-256-GCM authenticated encryption and decryption using a
/// 32-byte key. The encryption format is: IV (32 bytes) || ciphertext || tag (16 bytes).
pub struct SymmetricKey {
    /// The 32-byte AES key.
    key: [u8; 32],
}

impl SymmetricKey {
    /// Create a SymmetricKey from a byte slice.
    ///
    /// If the input is shorter than 32 bytes, it is left-padded with zeros.
    /// If the input is 32 bytes or longer, the first 32 bytes are used.
    ///
    /// # Arguments
    /// * `key` - The key bytes (ideally 32 bytes).
    ///
    /// # Returns
    /// A new `SymmetricKey`.
    pub fn new(key: &[u8]) -> Self {
        let mut padded = [0u8; 32];
        if key.len() < 32 {
            // Left-pad with zeros (matches Go SDK behavior)
            padded[32 - key.len()..].copy_from_slice(key);
        } else {
            padded.copy_from_slice(&key[..32]);
        }
        SymmetricKey { key: padded }
    }

    /// Generate a random 32-byte symmetric key.
    ///
    /// # Returns
    /// A new `SymmetricKey` with cryptographically random bytes.
    pub fn new_random() -> Self {
        let mut key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut key);
        SymmetricKey { key }
    }

    /// Create a SymmetricKey from a Base64-encoded string.
    ///
    /// # Arguments
    /// * `b64` - A Base64 (standard encoding) string of the key bytes.
    ///
    /// # Returns
    /// `Ok(SymmetricKey)` on success, or an error if the Base64 is invalid.
    pub fn from_base64(b64: &str) -> Result<Self, PrimitivesError> {
        use base64::Engine;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| PrimitivesError::EncryptionError(e.to_string()))?;
        Ok(Self::new(&bytes))
    }

    /// Encrypt a plaintext message using AES-256-GCM.
    ///
    /// The output format is: IV (32 bytes) || ciphertext || tag (16 bytes),
    /// matching the Go SDK's symmetric encryption format.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing the encrypted data, or an error if encryption fails.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, PrimitivesError> {
        // Generate 32-byte IV (Go SDK uses 32-byte IV)
        let mut iv = [0u8; IV_LEN];
        rand::rngs::OsRng.fill_bytes(&mut iv);

        self.encrypt_with_iv(plaintext, &iv)
    }

    /// Encrypt a plaintext message using AES-256-GCM with a specified IV.
    ///
    /// The Go SDK uses a 32-byte IV but AES-GCM standard uses 12-byte nonce.
    /// The Go SDK's custom AES-GCM implementation uses the full 32 bytes.
    /// We truncate to the standard 12-byte nonce but store the full 32-byte IV
    /// in the output for compatibility.
    ///
    /// # Arguments
    /// * `plaintext` - The data to encrypt.
    /// * `iv` - A 32-byte initialization vector.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing IV || ciphertext || tag, or an error.
    fn encrypt_with_iv(
        &self,
        plaintext: &[u8],
        iv: &[u8; IV_LEN],
    ) -> Result<Vec<u8>, PrimitivesError> {
        // Use the Go SDK's custom AES-GCM approach with 32-byte IV
        // The Go SDK uses a custom aesgcm package. Standard AES-GCM uses 12-byte nonce.
        // For compatibility, we use a custom GCM approach matching the Go SDK.
        let cipher = aes::Aes256::new_from_slice(&self.key)
            .map_err(|e| PrimitivesError::EncryptionError(e.to_string()))?;

        let ciphertext_and_tag =
            aes_gcm_encrypt_custom(&cipher, iv, plaintext, &[])
                .map_err(|e| PrimitivesError::EncryptionError(e))?;

        // Output: IV || ciphertext || tag
        let ciphertext = &ciphertext_and_tag[..ciphertext_and_tag.len() - TAG_LEN];
        let tag = &ciphertext_and_tag[ciphertext_and_tag.len() - TAG_LEN..];

        let mut result = Vec::with_capacity(IV_LEN + ciphertext.len() + TAG_LEN);
        result.extend_from_slice(iv);
        result.extend_from_slice(ciphertext);
        result.extend_from_slice(tag);
        Ok(result)
    }

    /// Decrypt a ciphertext message using AES-256-GCM.
    ///
    /// Expected input format: IV (32 bytes) || ciphertext || tag (16 bytes).
    ///
    /// # Arguments
    /// * `message` - The encrypted data (IV + ciphertext + tag).
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing the decrypted plaintext, or an error if decryption fails.
    pub fn decrypt(&self, message: &[u8]) -> Result<Vec<u8>, PrimitivesError> {
        if message.len() < IV_LEN + TAG_LEN {
            return Err(PrimitivesError::DecryptionError(
                "message is too short to be a valid encrypted message".to_string(),
            ));
        }

        let iv = &message[..IV_LEN];
        let ciphertext = &message[IV_LEN..message.len() - TAG_LEN];
        let tag = &message[message.len() - TAG_LEN..];

        let cipher = aes::Aes256::new_from_slice(&self.key)
            .map_err(|e| PrimitivesError::DecryptionError(e.to_string()))?;

        // Combine ciphertext and tag for the custom GCM decrypt
        let mut ct_with_tag = Vec::with_capacity(ciphertext.len() + TAG_LEN);
        ct_with_tag.extend_from_slice(ciphertext);
        ct_with_tag.extend_from_slice(tag);

        aes_gcm_decrypt_custom(&cipher, iv, &ct_with_tag, &[])
            .map_err(|e| PrimitivesError::DecryptionError(e))
    }

    /// Encrypt a string message.
    ///
    /// Convenience wrapper around `encrypt` for string data.
    ///
    /// # Arguments
    /// * `message` - The string to encrypt.
    ///
    /// # Returns
    /// `Ok(Vec<u8>)` containing the encrypted bytes.
    pub fn encrypt_string(&self, message: &str) -> Result<Vec<u8>, PrimitivesError> {
        self.encrypt(message.as_bytes())
    }

    /// Decrypt a message and return it as a string.
    ///
    /// Convenience wrapper around `decrypt` for string data.
    ///
    /// # Arguments
    /// * `message` - The encrypted data.
    ///
    /// # Returns
    /// `Ok(String)` containing the decrypted string.
    pub fn decrypt_string(&self, message: &[u8]) -> Result<String, PrimitivesError> {
        let plaintext = self.decrypt(message)?;
        String::from_utf8(plaintext)
            .map_err(|e| PrimitivesError::DecryptionError(e.to_string()))
    }

    /// Get the raw key bytes.
    ///
    /// # Returns
    /// A reference to the 32-byte key.
    pub fn to_bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

/// Custom AES-GCM encryption matching the Go SDK's aesgcm package.
///
/// The Go SDK uses a custom GHASH/GCM implementation that supports arbitrary IV lengths.
/// Standard AES-GCM uses a 12-byte nonce. This implementation uses the GHASH-based
/// approach for IV lengths != 12 to be compatible with Go.
///
/// # Arguments
/// * `cipher` - The AES-256 block cipher.
/// * `iv` - The initialization vector (32 bytes in Go SDK).
/// * `plaintext` - The data to encrypt.
/// * `aad` - Additional authenticated data (typically empty).
///
/// # Returns
/// `Ok(Vec<u8>)` containing ciphertext || 16-byte tag, or an error string.
fn aes_gcm_encrypt_custom(
    cipher: &aes::Aes256,
    iv: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    use aes::cipher::{BlockEncrypt, generic_array::GenericArray};

    // Compute H = AES_K(0^128)
    let mut h_block = GenericArray::default();
    cipher.encrypt_block(&mut h_block);
    let h = h_block.into();

    // Compute J0 from IV using GHASH if IV length != 12
    let j0 = if iv.len() == 12 {
        let mut j = [0u8; 16];
        j[..12].copy_from_slice(iv);
        j[15] = 1;
        j
    } else {
        ghash_iv(&h, iv)
    };

    // Encrypt plaintext using CTR mode starting from J0 + 1
    let mut counter = j0;
    inc32(&mut counter);

    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let blocks = (plaintext.len() + 15) / 16;
    for i in 0..blocks {
        let start = i * 16;
        let end = std::cmp::min(start + 16, plaintext.len());
        let mut block = GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut block);
        for j in 0..(end - start) {
            ciphertext.push(plaintext[start + j] ^ block[j]);
        }
        inc32(&mut counter);
    }

    // Compute tag = GHASH(H, AAD, C) XOR E(K, J0)
    let tag_hash = ghash_compute(&h, aad, &ciphertext);
    let mut j0_block = GenericArray::clone_from_slice(&j0);
    cipher.encrypt_block(&mut j0_block);
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = tag_hash[i] ^ j0_block[i];
    }

    let mut result = ciphertext;
    result.extend_from_slice(&tag);
    Ok(result)
}

/// Custom AES-GCM decryption matching the Go SDK's aesgcm package.
///
/// # Arguments
/// * `cipher` - The AES-256 block cipher.
/// * `iv` - The initialization vector.
/// * `ciphertext_with_tag` - The ciphertext followed by the 16-byte authentication tag.
/// * `aad` - Additional authenticated data.
///
/// # Returns
/// `Ok(Vec<u8>)` containing the plaintext, or an error if authentication fails.
fn aes_gcm_decrypt_custom(
    cipher: &aes::Aes256,
    iv: &[u8],
    ciphertext_with_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    use aes::cipher::{BlockEncrypt, generic_array::GenericArray};

    if ciphertext_with_tag.len() < TAG_LEN {
        return Err("ciphertext too short".to_string());
    }

    let ct_len = ciphertext_with_tag.len() - TAG_LEN;
    let ciphertext = &ciphertext_with_tag[..ct_len];
    let tag = &ciphertext_with_tag[ct_len..];

    // Compute H = AES_K(0^128)
    let mut h_block = GenericArray::default();
    cipher.encrypt_block(&mut h_block);
    let h = h_block.into();

    // Compute J0
    let j0 = if iv.len() == 12 {
        let mut j = [0u8; 16];
        j[..12].copy_from_slice(iv);
        j[15] = 1;
        j
    } else {
        ghash_iv(&h, iv)
    };

    // Verify tag
    let tag_hash = ghash_compute(&h, aad, ciphertext);
    let mut j0_block = GenericArray::clone_from_slice(&j0);
    cipher.encrypt_block(&mut j0_block);
    let mut expected_tag = [0u8; 16];
    for i in 0..16 {
        expected_tag[i] = tag_hash[i] ^ j0_block[i];
    }

    if !constant_time_eq(tag, &expected_tag) {
        return Err("authentication failed".to_string());
    }

    // Decrypt using CTR mode
    let mut counter = j0;
    inc32(&mut counter);

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let blocks = (ciphertext.len() + 15) / 16;
    for i in 0..blocks {
        let start = i * 16;
        let end = std::cmp::min(start + 16, ciphertext.len());
        let mut block = GenericArray::clone_from_slice(&counter);
        cipher.encrypt_block(&mut block);
        for j in 0..(end - start) {
            plaintext.push(ciphertext[start + j] ^ block[j]);
        }
        inc32(&mut counter);
    }

    Ok(plaintext)
}

/// Increment the rightmost 32 bits of a 16-byte counter (big-endian).
fn inc32(counter: &mut [u8; 16]) {
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// Compute GHASH for a non-standard IV length.
///
/// GHASH(H, {}, IV) || len64(IV)
fn ghash_iv(h: &[u8; 16], iv: &[u8]) -> [u8; 16] {
    let mut state = [0u8; 16];

    // Process IV in 16-byte blocks
    let blocks = (iv.len() + 15) / 16;
    for i in 0..blocks {
        let start = i * 16;
        let end = std::cmp::min(start + 16, iv.len());
        let mut block = [0u8; 16];
        block[..end - start].copy_from_slice(&iv[start..end]);
        xor_block(&mut state, &block);
        gf_mul(&mut state, h);
    }

    // Append bit length of IV (64-bit big-endian)
    let mut len_block = [0u8; 16];
    let bit_len = (iv.len() as u64) * 8;
    len_block[8..16].copy_from_slice(&bit_len.to_be_bytes());
    xor_block(&mut state, &len_block);
    gf_mul(&mut state, h);

    state
}

/// Compute GHASH(H, AAD, ciphertext) for authentication.
fn ghash_compute(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut state = [0u8; 16];

    // Process AAD
    let aad_blocks = (aad.len() + 15) / 16;
    for i in 0..aad_blocks {
        let start = i * 16;
        let end = std::cmp::min(start + 16, aad.len());
        let mut block = [0u8; 16];
        block[..end - start].copy_from_slice(&aad[start..end]);
        xor_block(&mut state, &block);
        gf_mul(&mut state, h);
    }

    // Process ciphertext
    let ct_blocks = (ciphertext.len() + 15) / 16;
    for i in 0..ct_blocks {
        let start = i * 16;
        let end = std::cmp::min(start + 16, ciphertext.len());
        let mut block = [0u8; 16];
        block[..end - start].copy_from_slice(&ciphertext[start..end]);
        xor_block(&mut state, &block);
        gf_mul(&mut state, h);
    }

    // Append lengths (AAD bit length || ciphertext bit length)
    let mut len_block = [0u8; 16];
    let aad_bit_len = (aad.len() as u64) * 8;
    let ct_bit_len = (ciphertext.len() as u64) * 8;
    len_block[..8].copy_from_slice(&aad_bit_len.to_be_bytes());
    len_block[8..16].copy_from_slice(&ct_bit_len.to_be_bytes());
    xor_block(&mut state, &len_block);
    gf_mul(&mut state, h);

    state
}

/// XOR a 16-byte block into the state.
fn xor_block(state: &mut [u8; 16], block: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= block[i];
    }
}

/// GF(2^128) multiplication used in GHASH.
///
/// Multiplies x by y in GF(2^128) using the GCM reduction polynomial.
fn gf_mul(x: &mut [u8; 16], y: &[u8; 16]) {
    let mut z = [0u8; 16];
    let mut v = [0u8; 16];
    v.copy_from_slice(y);

    for i in 0..128 {
        if x[i / 8] & (1 << (7 - (i % 8))) != 0 {
            xor_block(&mut z, &v);
        }
        let lsb = v[15] & 1;
        // Right shift v by 1
        for j in (1..16).rev() {
            v[j] = (v[j] >> 1) | (v[j - 1] << 7);
        }
        v[0] >>= 1;
        if lsb == 1 {
            v[0] ^= 0xe1; // GCM reduction polynomial
        }
    }

    x.copy_from_slice(&z);
}

/// Constant-time comparison of two byte slices.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

use aes::cipher::KeyInit as _;

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic encryption and decryption round-trip.
    #[test]
    fn test_symmetric_key_encryption_and_decryption() {
        let key = SymmetricKey::new_random();
        let plaintext = b"a thing to encrypt";

        let ciphertext = key.encrypt(plaintext).unwrap();
        let decrypted = key.decrypt(&ciphertext).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    /// Test decryption of Go SDK test vectors.
    #[test]
    fn test_symmetric_key_decryption_vectors() {
        let vectors_json = include_str!("testdata/SymmetricKey.vectors.json");
        let vectors: Vec<serde_json::Value> = serde_json::from_str(vectors_json).unwrap();

        for (i, v) in vectors.iter().enumerate() {
            let key_b64 = v["key"].as_str().unwrap();
            let ciphertext_b64 = v["ciphertext"].as_str().unwrap();
            let expected_plaintext = v["plaintext"].as_str().unwrap();

            use base64::Engine;
            let ciphertext = base64::engine::general_purpose::STANDARD
                .decode(ciphertext_b64)
                .unwrap();

            let sym_key = SymmetricKey::from_base64(key_b64).unwrap();
            let decrypted = sym_key.decrypt(&ciphertext).unwrap_or_else(|e| {
                panic!("vector #{}: decryption failed: {}", i + 1, e);
            });

            assert_eq!(
                String::from_utf8_lossy(&decrypted),
                expected_plaintext,
                "vector #{}: plaintext mismatch",
                i + 1
            );
        }
    }

    /// Test encryption with a 31-byte key (left-padded to 32).
    #[test]
    fn test_symmetric_key_with_short_key() {
        let short_key = vec![0xABu8; 31];
        let sym_key = SymmetricKey::new(&short_key);
        let plaintext = b"test message";

        let ciphertext = sym_key.encrypt(plaintext).unwrap();
        let decrypted = sym_key.decrypt(&ciphertext).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Test that decrypting a too-short message returns an error.
    #[test]
    fn test_symmetric_key_decrypt_too_short() {
        let key = SymmetricKey::new_random();
        let short_msg = vec![0u8; 10];
        assert!(key.decrypt(&short_msg).is_err());
    }
}
