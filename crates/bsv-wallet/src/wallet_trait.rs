//! The 29-method Wallet interface trait.
//!
//! This mirrors the Go `wallet.Interface` — the full set of operations
//! a BSV wallet must support.

use crate::error::WalletError;
use crate::types::*;

/// The full wallet interface (29 methods).
///
/// Methods that are not implemented by ProtoWallet (transaction management,
/// certificates, blockchain queries) return `WalletError::General("not implemented")`.
pub trait WalletInterface {
    // === Key Operations ===

    fn get_public_key(&self, args: GetPublicKeyArgs) -> Result<GetPublicKeyResult, WalletError>;

    fn encrypt(&self, args: EncryptArgs) -> Result<EncryptResult, WalletError>;
    fn decrypt(&self, args: DecryptArgs) -> Result<DecryptResult, WalletError>;

    fn create_hmac(&self, args: CreateHmacArgs) -> Result<CreateHmacResult, WalletError>;
    fn verify_hmac(&self, args: VerifyHmacArgs) -> Result<VerifyHmacResult, WalletError>;

    fn create_signature(
        &self,
        args: CreateSignatureArgs,
    ) -> Result<CreateSignatureResult, WalletError>;
    fn verify_signature(
        &self,
        args: VerifySignatureArgs,
    ) -> Result<VerifySignatureResult, WalletError>;

    // === Action / Transaction Operations ===

    fn create_action(&self, _args: CreateActionArgs) -> Result<CreateActionResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn sign_action(&self, _args: SignActionArgs) -> Result<SignActionResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn abort_action(&self, _args: AbortActionArgs) -> Result<AbortActionResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn list_actions(&self, _args: ListActionsArgs) -> Result<ListActionsResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn internalize_action(
        &self,
        _args: InternalizeActionArgs,
    ) -> Result<InternalizeActionResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn list_outputs(&self, _args: ListOutputsArgs) -> Result<ListOutputsResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn relinquish_output(
        &self,
        _args: RelinquishOutputArgs,
    ) -> Result<RelinquishOutputResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }

    // === Key Linkage ===

    fn reveal_counterparty_key_linkage(
        &self,
        _args: RevealCounterpartyKeyLinkageArgs,
    ) -> Result<RevealCounterpartyKeyLinkageResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn reveal_specific_key_linkage(
        &self,
        _args: RevealSpecificKeyLinkageArgs,
    ) -> Result<RevealSpecificKeyLinkageResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }

    // === Certificate Operations ===

    fn acquire_certificate(
        &self,
        _args: AcquireCertificateArgs,
    ) -> Result<CertificateResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn list_certificates(
        &self,
        _args: ListCertificatesArgs,
    ) -> Result<ListCertificatesResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn prove_certificate(
        &self,
        _args: ProveCertificateArgs,
    ) -> Result<ProveCertificateResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn relinquish_certificate(
        &self,
        _args: RelinquishCertificateArgs,
    ) -> Result<RelinquishCertificateResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }

    // === Discovery ===

    fn discover_by_identity_key(
        &self,
        _args: DiscoverByIdentityKeyArgs,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn discover_by_attributes(
        &self,
        _args: DiscoverByAttributesArgs,
    ) -> Result<DiscoverCertificatesResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }

    // === Authentication / Info ===

    fn is_authenticated(&self) -> Result<AuthenticatedResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn wait_for_authentication(&self) -> Result<AuthenticatedResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn get_height(&self) -> Result<GetHeightResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn get_header_for_height(
        &self,
        _args: GetHeaderArgs,
    ) -> Result<GetHeaderResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn get_network(&self) -> Result<GetNetworkResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
    fn get_version(&self) -> Result<GetVersionResult, WalletError> {
        Err(WalletError::General("not implemented".into()))
    }
}
