//! Token identifier type.

use std::fmt;

use serde::{Deserialize, Serialize};

use bsv_script::Address;

/// A unique token identifier derived from a BSV address.
///
/// Wraps an address string and the corresponding 20-byte public key hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TokenId {
    /// The Base58Check address string.
    address_string: String,
    /// The 20-byte public key hash.
    #[serde(with = "hex_pkh")]
    pkh: [u8; 20],
}

mod hex_pkh {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 20], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        serializer.serialize_str(&hex_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(serde::de::Error::custom))
            .collect::<Result<Vec<u8>, _>>()?;
        let mut arr = [0u8; 20];
        if bytes.len() != 20 {
            return Err(serde::de::Error::custom("expected 20 bytes"));
        }
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

impl TokenId {
    /// Create a `TokenId` from a BSV [`Address`].
    pub fn from_address(address: &Address) -> Self {
        Self {
            address_string: address.address_string.clone(),
            pkh: address.public_key_hash,
        }
    }

    /// Create a `TokenId` from an address string.
    ///
    /// Note: the public key hash will be zeroed since we cannot decode
    /// the address without base58 utilities. Use [`from_address`](Self::from_address) when possible.
    pub fn from_string(address: &str) -> Self {
        Self {
            address_string: address.to_string(),
            pkh: [0u8; 20],
        }
    }

    /// Returns the address string.
    pub fn as_str(&self) -> &str {
        &self.address_string
    }

    /// Create a `TokenId` directly from a 20-byte public key hash.
    ///
    /// The address string will be set to the hex encoding of the PKH.
    pub fn from_pkh(pkh: [u8; 20]) -> Self {
        let hex_str: String = pkh.iter().map(|b| format!("{:02x}", b)).collect();
        Self {
            address_string: hex_str,
            pkh,
        }
    }

    /// Returns the 20-byte public key hash.
    pub fn public_key_hash(&self) -> &[u8; 20] {
        &self.pkh
    }
}

impl fmt::Display for TokenId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address_string)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_string_and_accessors() {
        let tid = TokenId::from_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(tid.as_str(), "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        assert_eq!(tid.public_key_hash(), &[0u8; 20]);
    }

    #[test]
    fn serde_roundtrip() {
        let tid = TokenId::from_string("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
        let json = serde_json::to_string(&tid).unwrap();
        let restored: TokenId = serde_json::from_str(&json).unwrap();
        assert_eq!(tid, restored);
    }

    #[test]
    fn display() {
        let tid = TokenId::from_string("1TestAddr");
        assert_eq!(format!("{}", tid), "1TestAddr");
    }
}
