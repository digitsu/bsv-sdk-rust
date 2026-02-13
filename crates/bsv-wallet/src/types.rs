//! Core wallet types — Protocol, Counterparty, SecurityLevel, EncryptionArgs, etc.

use bsv_primitives::ec::public_key::PublicKey;
use bsv_primitives::ec::signature::Signature;
use serde::{Deserialize, Serialize};

/// Security level for wallet operations.
pub type SecurityLevel = i32;

pub const SECURITY_LEVEL_SILENT: SecurityLevel = 0;
pub const SECURITY_LEVEL_EVERY_APP: SecurityLevel = 1;
pub const SECURITY_LEVEL_EVERY_APP_AND_COUNTERPARTY: SecurityLevel = 2;

/// Protocol identifier with security level and name.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Protocol {
    pub security_level: SecurityLevel,
    pub protocol: String,
}

/// The type of counterparty in a cryptographic operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CounterpartyType {
    Uninitialized,
    Anyone,
    Self_,
    Other,
}

impl Default for CounterpartyType {
    fn default() -> Self {
        CounterpartyType::Uninitialized
    }
}

/// Counterparty in a cryptographic operation.
#[derive(Debug, Clone)]
pub struct Counterparty {
    pub r#type: CounterpartyType,
    pub counterparty: Option<PublicKey>,
}

impl Default for Counterparty {
    fn default() -> Self {
        Self {
            r#type: CounterpartyType::Uninitialized,
            counterparty: None,
        }
    }
}

/// Common parameters for cryptographic operations.
#[derive(Debug, Clone)]
pub struct EncryptionArgs {
    pub protocol_id: Protocol,
    pub key_id: String,
    pub counterparty: Counterparty,
    pub privileged: bool,
    pub privileged_reason: String,
    pub seek_permission: bool,
}

/// Arguments for encrypting data.
#[derive(Debug, Clone)]
pub struct EncryptArgs {
    pub encryption_args: EncryptionArgs,
    pub plaintext: Vec<u8>,
}

/// Arguments for decrypting data.
#[derive(Debug, Clone)]
pub struct DecryptArgs {
    pub encryption_args: EncryptionArgs,
    pub ciphertext: Vec<u8>,
}

/// Result of an encryption operation.
#[derive(Debug, Clone)]
pub struct EncryptResult {
    pub ciphertext: Vec<u8>,
}

/// Result of a decryption operation.
#[derive(Debug, Clone)]
pub struct DecryptResult {
    pub plaintext: Vec<u8>,
}

/// Arguments for retrieving a public key.
#[derive(Debug, Clone)]
pub struct GetPublicKeyArgs {
    pub encryption_args: EncryptionArgs,
    pub identity_key: bool,
    pub for_self: Option<bool>,
}

/// Result of a public key retrieval.
#[derive(Debug, Clone)]
pub struct GetPublicKeyResult {
    pub public_key: PublicKey,
}

/// Arguments for creating a digital signature.
#[derive(Debug, Clone)]
pub struct CreateSignatureArgs {
    pub encryption_args: EncryptionArgs,
    pub data: Vec<u8>,
    pub hash_to_directly_sign: Vec<u8>,
}

/// Result of a signature creation.
#[derive(Debug, Clone)]
pub struct CreateSignatureResult {
    pub signature: Signature,
}

/// Arguments for verifying a digital signature.
#[derive(Debug, Clone)]
pub struct VerifySignatureArgs {
    pub encryption_args: EncryptionArgs,
    pub data: Vec<u8>,
    pub hash_to_directly_verify: Vec<u8>,
    pub signature: Option<Signature>,
    pub for_self: Option<bool>,
}

/// Result of a signature verification.
#[derive(Debug, Clone)]
pub struct VerifySignatureResult {
    pub valid: bool,
}

/// Arguments for creating an HMAC.
#[derive(Debug, Clone)]
pub struct CreateHmacArgs {
    pub encryption_args: EncryptionArgs,
    pub data: Vec<u8>,
}

/// Result of an HMAC creation.
#[derive(Debug, Clone)]
pub struct CreateHmacResult {
    pub hmac: [u8; 32],
}

/// Arguments for verifying an HMAC.
#[derive(Debug, Clone)]
pub struct VerifyHmacArgs {
    pub encryption_args: EncryptionArgs,
    pub data: Vec<u8>,
    pub hmac: [u8; 32],
}

/// Result of an HMAC verification.
#[derive(Debug, Clone)]
pub struct VerifyHmacResult {
    pub valid: bool,
}

// === Action / Transaction Types ===

/// Arguments for creating a transaction action.
#[derive(Debug, Clone)]
pub struct CreateActionArgs {
    pub description: String,
    pub input_beef: Vec<u8>,
    pub inputs: Vec<CreateActionInput>,
    pub outputs: Vec<CreateActionOutput>,
    pub lock_time: Option<u32>,
    pub version: Option<u32>,
    pub labels: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CreateActionInput {
    pub outpoint: String,
    pub input_description: String,
    pub unlocking_script: Vec<u8>,
    pub unlocking_script_length: u32,
    pub sequence_number: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct CreateActionOutput {
    pub locking_script: Vec<u8>,
    pub satoshis: u64,
    pub output_description: String,
    pub basket: String,
    pub custom_instructions: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct CreateActionResult {
    pub txid: [u8; 32],
    pub tx: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignActionArgs {
    pub reference: Vec<u8>,
    pub spends: std::collections::HashMap<u32, SignActionSpend>,
}

#[derive(Debug, Clone)]
pub struct SignActionSpend {
    pub unlocking_script: Vec<u8>,
    pub sequence_number: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SignActionResult {
    pub txid: [u8; 32],
    pub tx: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AbortActionArgs {
    pub reference: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AbortActionResult {
    pub aborted: bool,
}

#[derive(Debug, Clone)]
pub struct ListActionsArgs {
    pub labels: Vec<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ListActionsResult {
    pub total_actions: u32,
    pub actions: Vec<ActionRecord>,
}

#[derive(Debug, Clone)]
pub struct ActionRecord {
    pub txid: [u8; 32],
    pub satoshis: i64,
    pub status: String,
    pub is_outgoing: bool,
    pub description: String,
}

#[derive(Debug, Clone)]
pub struct InternalizeActionArgs {
    pub tx: Vec<u8>,
    pub description: String,
    pub labels: Vec<String>,
    pub outputs: Vec<InternalizeOutput>,
}

#[derive(Debug, Clone)]
pub struct InternalizeOutput {
    pub output_index: u32,
    pub protocol: String,
}

#[derive(Debug, Clone)]
pub struct InternalizeActionResult {
    pub accepted: bool,
}

#[derive(Debug, Clone)]
pub struct ListOutputsArgs {
    pub basket: String,
    pub tags: Vec<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ListOutputsResult {
    pub total_outputs: u32,
    pub outputs: Vec<OutputRecord>,
}

#[derive(Debug, Clone)]
pub struct OutputRecord {
    pub satoshis: u64,
    pub locking_script: Vec<u8>,
    pub spendable: bool,
    pub outpoint: String,
}

#[derive(Debug, Clone)]
pub struct RelinquishOutputArgs {
    pub basket: String,
    pub output: String,
}

#[derive(Debug, Clone)]
pub struct RelinquishOutputResult {
    pub relinquished: bool,
}

// === Key Linkage Types ===

#[derive(Debug, Clone)]
pub struct RevealCounterpartyKeyLinkageArgs {
    pub counterparty: PublicKey,
    pub verifier: PublicKey,
}

#[derive(Debug, Clone)]
pub struct RevealCounterpartyKeyLinkageResult {
    pub prover: PublicKey,
    pub counterparty: PublicKey,
    pub verifier: PublicKey,
    pub encrypted_linkage: Vec<u8>,
    pub encrypted_linkage_proof: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct RevealSpecificKeyLinkageArgs {
    pub counterparty: Counterparty,
    pub verifier: PublicKey,
    pub protocol_id: Protocol,
    pub key_id: String,
}

#[derive(Debug, Clone)]
pub struct RevealSpecificKeyLinkageResult {
    pub encrypted_linkage: Vec<u8>,
    pub encrypted_linkage_proof: Vec<u8>,
    pub prover: PublicKey,
    pub verifier: PublicKey,
    pub counterparty: PublicKey,
    pub protocol_id: Protocol,
    pub key_id: String,
}

// === Certificate Types ===

pub type CertificateType = [u8; 32];
pub type SerialNumber = [u8; 32];

#[derive(Debug, Clone)]
pub struct Certificate {
    pub cert_type: CertificateType,
    pub serial_number: SerialNumber,
    pub subject: PublicKey,
    pub certifier: PublicKey,
    pub fields: std::collections::HashMap<String, String>,
    pub signature: Option<Signature>,
}

#[derive(Debug, Clone)]
pub struct CertificateResult {
    pub certificate: Certificate,
    pub keyring: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct AcquireCertificateArgs {
    pub cert_type: CertificateType,
    pub certifier: PublicKey,
    pub acquisition_protocol: String,
    pub fields: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct ListCertificatesArgs {
    pub certifiers: Vec<PublicKey>,
    pub types: Vec<CertificateType>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct ListCertificatesResult {
    pub total_certificates: u32,
    pub certificates: Vec<CertificateResult>,
}

#[derive(Debug, Clone)]
pub struct ProveCertificateArgs {
    pub certificate: Certificate,
    pub fields_to_reveal: Vec<String>,
    pub verifier: PublicKey,
}

#[derive(Debug, Clone)]
pub struct ProveCertificateResult {
    pub keyring_for_verifier: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct RelinquishCertificateArgs {
    pub cert_type: CertificateType,
    pub serial_number: SerialNumber,
    pub certifier: PublicKey,
}

#[derive(Debug, Clone)]
pub struct RelinquishCertificateResult {
    pub relinquished: bool,
}

// === Discovery Types ===

#[derive(Debug, Clone)]
pub struct DiscoverByIdentityKeyArgs {
    pub identity_key: PublicKey,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DiscoverByAttributesArgs {
    pub attributes: std::collections::HashMap<String, String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct DiscoverCertificatesResult {
    pub total_certificates: u32,
    pub certificates: Vec<CertificateResult>,
}

// === Auth / Info Types ===

#[derive(Debug, Clone)]
pub struct AuthenticatedResult {
    pub authenticated: bool,
}

#[derive(Debug, Clone)]
pub struct GetHeightResult {
    pub height: u32,
}

#[derive(Debug, Clone)]
pub struct GetHeaderArgs {
    pub height: u32,
}

#[derive(Debug, Clone)]
pub struct GetHeaderResult {
    pub header: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct GetNetworkResult {
    pub network: String,
}

#[derive(Debug, Clone)]
pub struct GetVersionResult {
    pub version: String,
}

/// Returns the special "anyone" private/public key pair (scalar = 1).
pub fn anyone_key() -> (bsv_primitives::ec::private_key::PrivateKey, PublicKey) {
    let priv_key = bsv_primitives::ec::private_key::PrivateKey::from_bytes(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
        .expect("anyone key should always be valid");
    let pub_key = priv_key.pub_key();
    (priv_key, pub_key)
}
