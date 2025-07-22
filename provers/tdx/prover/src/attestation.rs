use anyhow::{anyhow, Result};
use az_tdx_vtpm::{hcl, imds, tdx, vtpm};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

/// InstanceInfo wraps the TDX report with additional Azure specific runtime data
/// following the Constellation standard
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InstanceInfo {
    pub attestation_report: Vec<u8>,
    pub runtime_data: Vec<u8>,
}

/// Issue an attestation document
/// 
/// # Arguments
/// * `user_data` - User-provided data to include in the attestation
/// * `nonce` - Nonce for freshness
/// 
/// # Returns
/// Serialized InstanceInfo containing the attestation report and runtime data
pub fn issue(user_data: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    // Combine user_data and nonce to create extra_data
    let extra_data = make_extra_data(user_data, nonce);

    // Get instance info with the extra data included
    let instance_info = get_instance_info(&extra_data)?;

    // Serialize the instance info
    let serialized = serde_json::to_vec(&instance_info)?;
    
    Ok(serialized)
}

/// Get instance information including TDX quote and runtime data
fn get_instance_info(extra_data: &[u8]) -> Result<InstanceInfo> {
    // Get the HCL report from vTPM with our extra data included
    // This will include the extra_data in the TD report's reportdata field
    let hcl_report_bytes = vtpm::get_report_with_report_data(extra_data)
        .map_err(|e| anyhow!("Failed to get HCL report from vTPM: {}", e))?;
    
    // Parse the HCL report
    let hcl_report = hcl::HclReport::new(hcl_report_bytes)
        .map_err(|e| anyhow!("Failed to parse HCL report: {}", e))?;
    
    // Extract runtime data (Variable Data from HCL report)
    // This contains the attestation key public part and other metadata
    let runtime_data = hcl_report.var_data().to_vec();
    
    // Convert HCL report to TD report - need to specify the type
    let td_report: tdx::TdReport = hcl_report.try_into()
        .map_err(|e: hcl::HclError| anyhow!("Failed to extract TD report: {}", e))?;
    
    // Verify that our extra_data is included in the TD report
    // The extra_data should be in the reportdata field (first 32 bytes after var_data hash)
    let report_data = &td_report.report_mac.reportdata;
    let var_data_hash = &report_data[..32];
    let _embedded_extra_data = &report_data[32..];
    
    // The var_data_hash should match the SHA256 of runtime_data
    let calculated_var_data_hash = {
        let mut hasher = Sha256::new();
        hasher.update(&runtime_data);
        hasher.finalize()
    };
    
    if var_data_hash != calculated_var_data_hash.as_slice() {
        return Err(anyhow!("Variable data hash mismatch"));
    }
    
    // Get TDX quote from IMDS
    let quote = imds::get_td_quote(&td_report)
        .map_err(|e| anyhow!("Failed to get TDX quote from IMDS: {}", e))?;
    
    Ok(InstanceInfo {
        attestation_report: quote,
        runtime_data,
    })
}

/// Create extra data by combining user data and nonce
/// This follows the Constellation standard for extra data creation
fn make_extra_data(user_data: &[u8], nonce: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(user_data);
    hasher.update(nonce);
    hasher.finalize().to_vec()
}

/// Check if the current VM is a TDX CVM
pub fn is_tdx_cvm() -> Result<bool> {
    az_tdx_vtpm::is_tdx_cvm()
        .map_err(|e| anyhow!("Failed to check if VM is TDX CVM: {}", e))
}