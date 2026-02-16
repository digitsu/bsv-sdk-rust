//! JungleBus HTTP client for querying transactions, addresses, and block headers.

use reqwest::header::{HeaderMap, HeaderValue};
use serde::de::DeserializeOwned;

use crate::error::JungleBusError;
use crate::types::{AddressInfo, BlockHeader, JungleBusConfig, Transaction};

/// HTTP client for the JungleBus API.
#[derive(Debug, Clone)]
pub struct JungleBusClient {
    /// Client configuration.
    config: JungleBusConfig,
    /// Underlying HTTP client.
    client: reqwest::Client,
}

impl JungleBusClient {
    /// Create a new JungleBus client with the given configuration.
    pub fn new(config: JungleBusConfig) -> Self {
        let client = reqwest::Client::new();
        Self { config, client }
    }

    /// Get a transaction by its ID.
    pub async fn get_transaction(&self, txid: &str) -> Result<Transaction, JungleBusError> {
        let path = format!("transaction/get/{}", txid);
        self.do_request(&path).await
    }

    /// Get address transaction metadata.
    pub async fn get_address_transactions(
        &self,
        address: &str,
    ) -> Result<Vec<AddressInfo>, JungleBusError> {
        let path = format!("address/get/{}", address);
        self.do_request(&path).await
    }

    /// Get full transaction details for an address.
    pub async fn get_address_transaction_details(
        &self,
        address: &str,
    ) -> Result<Vec<Transaction>, JungleBusError> {
        let path = format!("address/transactions/{}", address);
        self.do_request(&path).await
    }

    /// Get a block header by hash or height.
    pub async fn get_block_header(&self, block: &str) -> Result<BlockHeader, JungleBusError> {
        let path = format!("block_header/get/{}", block);
        self.do_request(&path).await
    }

    /// List block headers starting from a given block.
    pub async fn get_block_headers(
        &self,
        from_block: &str,
        limit: u32,
    ) -> Result<Vec<BlockHeader>, JungleBusError> {
        let path = format!("block_header/list/{}?limit={}", from_block, limit);
        self.do_request(&path).await
    }

    /// Perform a GET request to the JungleBus API and deserialize the response.
    async fn do_request<T: DeserializeOwned>(&self, path: &str) -> Result<T, JungleBusError> {
        let url = format!(
            "{}/{}/{}",
            self.config.server_url, self.config.api_version, path
        );

        let headers = self.build_headers();

        let resp = self.client.get(&url).headers(headers).send().await?;

        let status = resp.status();

        if status.as_u16() == 404 {
            return Err(JungleBusError::NotFound);
        }

        if !status.is_success() {
            let message = resp.text().await.unwrap_or_default();
            return Err(JungleBusError::ServerError {
                status_code: status.as_u16(),
                message,
            });
        }

        let text = resp.text().await?;
        let parsed = serde_json::from_str(&text)?;
        Ok(parsed)
    }

    /// Build common headers from config.
    fn build_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();

        if let Some(ref token) = self.config.token {
            if let Ok(val) = HeaderValue::from_str(token) {
                headers.insert("token", val);
            }
        }

        headers
    }
}
