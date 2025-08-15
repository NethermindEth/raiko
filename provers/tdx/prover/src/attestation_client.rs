use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum Request {
    Issue { data: IssueData },
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct IssueData {
    user_data: String,
    nonce: String,
}

#[derive(Debug, Deserialize)]
struct IssueResponse {
    document: String,
    error: String,
}

pub fn issue_attestation(socket_path: &str, user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    let request = Request::Issue {
        data: IssueData {
            user_data: hex::encode(user_data),
            nonce: hex::encode(nonce),
        },
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

    if !response.error.is_empty() {
        return Err(anyhow!("Attestation service error: {}", response.error));
    }

    hex::decode(&response.document).context("Failed to decode attestation document from hex")
}
