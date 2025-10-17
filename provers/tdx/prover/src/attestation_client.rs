use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

#[derive(Debug, Serialize)]
struct Request<T> {
    method: String,
    data: T,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IssueRequestData {
    user_data: String,
    nonce: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MetadataRequestData {}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct ValidateRequestData {
    document: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct Response<T> {
    data: Option<T>,
    error: Option<String>,
}

type IssueResponse = Response<IssueResponseData>;
type MetadataResponse = Response<MetadataResponseData>;
type ValidateResponse = Response<ValidateResponseData>;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IssueResponseData {
    document: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MetadataResponseData {
    issuer_type: String,
    user_data: String,
    nonce: String,
    metadata: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ValidateResponseData {
    user_data: String,
    valid: bool,
}

impl<T> Response<T> {
    fn into_result(self) -> Result<T> {
        match (self.data, self.error) {
            (Some(data), None) => Ok(data),
            (None, Some(error)) => Err(anyhow!("Attestation service error: {}", error)),
            (None, None) => Err(anyhow!("Invalid response: neither data nor error present")),
            (Some(_), Some(error)) => {
                Err(anyhow!("Invalid response: both data and error present. Error: {}", error))
            }
        }
    }
}

pub fn issue_attestation(socket_path: &str, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    let issue_data = IssueRequestData {
        user_data: hex::encode(user_data),
        nonce: hex::encode(nonce),
    };

    let request = Request {
        method: "issue".to_string(),
        data: serde_json::to_value(issue_data)?,
    };

    let request_json =
        serde_json::to_string(&request).context("Failed to serialize issue request")?;

    let mut stream = UnixStream::connect(socket_path).with_context(|| {
        format!(
            "Failed to connect to attestation service at {}",
            socket_path
        )
    })?;

    stream
        .write_all(request_json.as_bytes())
        .context("Failed to write request to socket")?;

    stream
        .shutdown(std::net::Shutdown::Write)
        .context("Failed to shutdown write side of socket")?;

    let mut response_buf = Vec::new();
    stream
        .read_to_end(&mut response_buf)
        .context("Failed to read response from socket")?;

    let response: IssueResponse = serde_json::from_slice(&response_buf)
        .context("Failed to parse attestation service response")?;

    let data = response.into_result()?;
    
    hex::decode(&data.document).context("Failed to decode attestation document from hex")
}

pub fn metadata(socket_path: &str) -> Result<MetadataResponseData> {
    let metadata_data = MetadataRequestData {};

    let request = Request {
        method: "metadata".to_string(),
        data: serde_json::to_value(metadata_data)?,
    };

    let request_json =
        serde_json::to_string(&request).context("Failed to serialize metadata request")?;

    let mut stream = UnixStream::connect(socket_path).with_context(|| {
        format!(
            "Failed to connect to attestation service at {}",
            socket_path
        )
    })?;

    stream
        .write_all(request_json.as_bytes())
        .context("Failed to write request to socket")?;

    stream
        .shutdown(std::net::Shutdown::Write)
        .context("Failed to shutdown write side of socket")?;

    let mut response_buf = Vec::new();
    stream
        .read_to_end(&mut response_buf)
        .context("Failed to read response from socket")?;

    let response: MetadataResponse = serde_json::from_slice(&response_buf)
        .context("Failed to parse attestation service response")?;

    let data = response.into_result()?;
    
    Ok(data)
}

pub fn validate_document(
    socket_path: &str,
    document: &[u8],
    nonce: &[u8],
) -> Result<(Vec<u8>, bool)> {
    let validate_data = ValidateRequestData {
        document: hex::encode(document),
        nonce: hex::encode(nonce),
    };

    let request = Request {
        method: "validate".to_string(),
        data: serde_json::to_value(validate_data)?,
    };

    let request_json =
        serde_json::to_string(&request).context("Failed to serialize validate request")?;

    let mut stream = UnixStream::connect(socket_path).with_context(|| {
        format!(
            "Failed to connect to attestation service at {}",
            socket_path
        )
    })?;

    stream
        .write_all(request_json.as_bytes())
        .context("Failed to write request to socket")?;

    stream
        .shutdown(std::net::Shutdown::Write)
        .context("Failed to shutdown write side of socket")?;

    let mut response_buf = Vec::new();
    stream
        .read_to_end(&mut response_buf)
        .context("Failed to read response from socket")?;

    let response: ValidateResponse = serde_json::from_slice(&response_buf)
        .context("Failed to parse attestation service response")?;

    let data = response.into_result()?;
    
    let user_data = hex::decode(&data.user_data)
        .context("Failed to decode user data from hex")?;

    Ok((user_data, data.valid))
}
