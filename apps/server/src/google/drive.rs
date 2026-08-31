use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use crate::google::error::{ProviderErrorKind, map_google_http_error};

const DRIVE_FILES_URL: &str = "https://www.googleapis.com/drive/v3/files";
const UPLOAD_URL: &str = "https://www.googleapis.com/upload/drive/v3/files";

/// Vault file naming per spec: appDataFolder/voult-vault-<vault_id>.json
pub fn vault_file_name(vault_id: &str) -> String {
    format!("voult-vault-{}.json", vault_id)
}

/// Provider-neutral vault descriptor for listing
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultDescriptor {
    pub vault_id: String,
    pub file_id: String,
    pub name: String,
    pub modified_time: Option<String>,
    pub size: Option<String>,
    pub head_revision_id: Option<String>,
    pub version: Option<String>,
}

#[derive(Deserialize)]
struct DriveFileList {
    files: Vec<DriveFile>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}

#[derive(Deserialize, Clone)]
struct DriveFile {
    id: String,
    name: String,
    #[serde(rename = "modifiedTime")]
    modified_time: Option<String>,
    size: Option<String>,
    #[serde(rename = "headRevisionId")]
    head_revision_id: Option<String>,
    version: Option<String>,
    #[serde(rename = "mimeType")]
    mime_type: Option<String>,
    properties: Option<std::collections::HashMap<String, String>>,
}

#[derive(Serialize)]
struct CreateFileBody {
    name: String,
    parents: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    properties: Option<std::collections::HashMap<String, String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    appProperties: Option<std::collections::HashMap<String, String>>,
}

fn vault_id_from_name(name: &str) -> Option<String> {
    // voult-vault-<uuid>.json
    if !name.starts_with("voult-vault-") || !name.ends_with(".json") {
        return None;
    }
    let inner = &name["voult-vault-".len()..name.len() - ".json".len()];
    // Validate UUID
    if uuid::Uuid::parse_str(inner).is_ok() {
        Some(inner.to_string())
    } else {
        None
    }
}

pub async fn list_vaults(access_token: &str) -> Result<Vec<VaultDescriptor>, (ProviderErrorKind, String)> {
    let client = reqwest::Client::new();
    let url = format!(
        "{DRIVE_FILES_URL}?spaces=appDataFolder&fields=nextPageToken,files(id,name,mimeType,modifiedTime,size,headRevisionId,version,properties,appProperties)&pageSize=100"
    );

    let resp = client
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| (ProviderErrorKind::RemoteUnavailable, format!("network error: {:?}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        return Err((kind, body));
    }

    let list: DriveFileList = resp
        .json()
        .await
        .map_err(|e| (ProviderErrorKind::Unknown, format!("parse error: {:?}", e)))?;

    let mut out = Vec::new();
    for f in list.files {
        if let Some(vid) = vault_id_from_name(&f.name) {
            out.push(VaultDescriptor {
                vault_id: vid,
                file_id: f.id,
                name: f.name,
                modified_time: f.modified_time,
                size: f.size,
                head_revision_id: f.head_revision_id,
                version: f.version,
            });
        }
    }
    Ok(out)
}

pub async fn read_vault(
    access_token: &str,
    file_id: &str,
) -> Result<(Vec<u8>, String), (ProviderErrorKind, String)> {
    // First get metadata to get revision
    let client = reqwest::Client::new();
    let meta_url = format!("{DRIVE_FILES_URL}/{}?fields=id,headRevisionId,version,modifiedTime", file_id);
    let meta_resp = client
        .get(&meta_url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| (ProviderErrorKind::RemoteUnavailable, format!("network error: {:?}", e)))?;

    if !meta_resp.status().is_success() {
        let status = meta_resp.status();
        let body = meta_resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        return Err((kind, body));
    }

    #[derive(Deserialize)]
    struct Meta {
        #[serde(rename = "headRevisionId")]
        head_revision_id: Option<String>,
        version: Option<String>,
    }
    let meta: Meta = meta_resp
        .json()
        .await
        .map_err(|e| (ProviderErrorKind::Unknown, format!("meta parse error: {:?}", e)))?;

    let revision = meta.head_revision_id.or(meta.version).unwrap_or_else(|| "unknown".to_string());

    // Now download content
    let dl_url = format!("{DRIVE_FILES_URL}/{}?alt=media", file_id);
    let dl_resp = client
        .get(&dl_url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| (ProviderErrorKind::RemoteUnavailable, format!("network error: {:?}", e)))?;

    if !dl_resp.status().is_success() {
        let status = dl_resp.status();
        let body = dl_resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        return Err((kind, body));
    }

    let bytes = dl_resp
        .bytes()
        .await
        .map_err(|e| (ProviderErrorKind::Unknown, format!("bytes error: {:?}", e)))?
        .to_vec();

    Ok((bytes, revision))
}

pub async fn create_vault(
    access_token: &str,
    vault_id: &str,
    package_bytes: &[u8],
) -> Result<(String, String), (ProviderErrorKind, String)> {
    let client = reqwest::Client::new();
    // Check if file already exists (idempotent)
    let existing = list_vaults(access_token).await?;
    if let Some(found) = existing.iter().find(|v| v.vault_id == vault_id) {
        // File already exists – verify content matches? For idempotent retry, return existing
        // We read and verify package's vault_id matches – caller will verify read-back
        return Ok((found.file_id.clone(), found.head_revision_id.clone().or(found.version.clone()).unwrap_or_else(|| "unknown".to_string())));
    }

    let file_name = vault_file_name(vault_id);
    // Multipart upload: metadata + media
    // For simplicity, use simple media upload with metadata via query? Use multipart.
    // We'll use the upload endpoint with multipart.
    let mut props = std::collections::HashMap::new();
    props.insert("vaultId".to_string(), vault_id.to_string());
    props.insert("voultSchema".to_string(), "1".to_string());

    let metadata = serde_json::json!({
        "name": file_name,
        "parents": ["appDataFolder"],
        "properties": props,
        "appProperties": props,
        "mimeType": "application/json"
    });

    // Use multipart upload: https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart
    let form = reqwest::multipart::Form::new()
        .part(
            "metadata",
            reqwest::multipart::Part::text(metadata.to_string()).mime_str("application/json").unwrap(),
        )
        .part(
            "media",
            reqwest::multipart::Part::bytes(package_bytes.to_vec())
                .mime_str("application/json").unwrap()
                .file_name(file_name.clone()),
        );

    let resp = client
        .post(format!("{UPLOAD_URL}?uploadType=multipart&fields=id,headRevisionId,version"))
        .bearer_auth(access_token)
        .multipart(form)
        .send()
        .await
        .map_err(|e| (ProviderErrorKind::RemoteUnavailable, format!("network error: {:?}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        return Err((kind, body));
    }

    #[derive(Deserialize)]
    struct CreateResp {
        id: String,
        #[serde(rename = "headRevisionId")]
        head_revision_id: Option<String>,
        version: Option<String>,
    }
    let cr: CreateResp = resp
        .json()
        .await
        .map_err(|e| (ProviderErrorKind::Unknown, format!("create parse error: {:?}", e)))?;
    let rev = cr.head_revision_id.or(cr.version).unwrap_or_else(|| "unknown".to_string());
    Ok((cr.id, rev))
}

pub async fn replace_vault(
    access_token: &str,
    file_id: &str,
    package_bytes: &[u8],
    if_match_revision: Option<&str>,
) -> Result<String, (ProviderErrorKind, String)> {
    let client = reqwest::Client::new();

    // For conditional write, fetch current revision and compare
    if let Some(expected) = if_match_revision {
        let meta_url = format!("{DRIVE_FILES_URL}/{}?fields=headRevisionId,version", file_id);
        let meta_resp = client
            .get(&meta_url)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| (ProviderErrorKind::RemoteUnavailable, format!("network error: {:?}", e)))?;

        if !meta_resp.status().is_success() {
            let status = meta_resp.status();
            let body = meta_resp.text().await.unwrap_or_default();
            let kind = map_google_http_error(status, &body);
            return Err((kind, body));
        }
        #[derive(Deserialize)]
        struct Meta {
            #[serde(rename = "headRevisionId")]
            head_revision_id: Option<String>,
            version: Option<String>,
        }
        let meta: Meta = meta_resp.json().await.map_err(|e| (ProviderErrorKind::Unknown, format!("meta parse error: {:?}", e)))?;
        let current = meta.head_revision_id.or(meta.version).unwrap_or_default();
        if current != expected {
            return Err((ProviderErrorKind::RemoteConflict, format!("revision mismatch: expected {}, got {}", expected, current)));
        }
    }

    // Media upload to update file content: PATCH /upload/drive/v3/files/{fileId}?uploadType=media
    let resp = client
        .patch(format!("{UPLOAD_URL}/{}?uploadType=media&fields=id,headRevisionId,version", file_id))
        .bearer_auth(access_token)
        .header("Content-Type", "application/json")
        .body(package_bytes.to_vec())
        .send()
        .await
        .map_err(|e| (ProviderErrorKind::RemoteUnavailable, format!("network error: {:?}", e)))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        return Err((kind, body));
    }

    #[derive(Deserialize)]
    struct UpdateResp {
        id: String,
        #[serde(rename = "headRevisionId")]
        head_revision_id: Option<String>,
        version: Option<String>,
    }
    let ur: UpdateResp = resp
        .json()
        .await
        .map_err(|e| (ProviderErrorKind::Unknown, format!("update parse error: {:?}", e)))?;
    let rev = ur.head_revision_id.or(ur.version).unwrap_or_else(|| "unknown".to_string());
    Ok(rev)
}

pub async fn delete_vault(
    access_token: &str,
    file_id: &str,
) -> Result<(), (ProviderErrorKind, String)> {
    let client = reqwest::Client::new();
    // Drive appDataFolder files cannot be trashed, but can be deleted via files.delete (permanent).
    // However spec says cannot trash; delete may also be not supported? We'll try delete.
    // If delete fails with notSupportedForAppDataFolderFiles, map to permission denied.
    let resp = client
        .delete(format!("{DRIVE_FILES_URL}/{}", file_id))
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| (ProviderErrorKind::RemoteUnavailable, format!("network error: {:?}", e)))?;

    if !resp.status().is_success() {
        // 204 is success for delete
        if resp.status() == StatusCode::NO_CONTENT {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        if body.contains("notSupportedForAppDataFolderFiles") {
            return Err((ProviderErrorKind::PermissionDenied, body));
        }
        return Err((kind, body));
    }
    Ok(())
}
