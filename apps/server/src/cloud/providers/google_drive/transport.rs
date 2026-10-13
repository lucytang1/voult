use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

use super::status_mapper::map_google_http_error;
use crate::cloud::error::{ProviderError, ProviderErrorKind};

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

#[derive(Deserialize, Clone)]
struct FileRevision {
    #[serde(rename = "headRevisionId")]
    head_revision_id: Option<String>,
    version: Option<String>,
}

impl FileRevision {
    /// Drive reports `headRevisionId` for binary files and a monotonic
    /// `version` string for everything else; either is a usable CAS token.
    fn token(&self) -> String {
        self.head_revision_id
            .clone()
            .or(self.version.clone())
            .unwrap_or_else(|| UNKNOWN_REVISION.to_string())
    }
}

/// Sentinel used when Drive reports no revision at all. Treated as "no usable
/// CAS token" by callers — never as a revision that could match.
///
/// Owned by the provider root (`super::UNKNOWN_REVISION`); transport only
/// produces it, so callers outside this directory need not know Drive's
/// terminology.
pub(crate) const UNKNOWN_REVISION: &str = "unknown";

/// Fetches just the current revision token for a file (metadata only, no
/// content download). Used to establish a CAS baseline before a conditional
/// write.
pub async fn file_revision(access_token: &str, file_id: &str) -> Result<String, ProviderError> {
    let client = crate::cloud::http_client::client();
    let meta_url = format!(
        "{DRIVE_FILES_URL}/{}?fields=headRevisionId,version",
        file_id
    );
    let resp = client
        .get(&meta_url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::RemoteUnavailable,
                format!("network error: {:?}", e),
            )
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        return Err(ProviderError::new(kind, body));
    }

    let meta: FileRevision = resp.json().await.map_err(|e| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            format!("meta parse error: {:?}", e),
        )
    })?;
    Ok(meta.token())
}

pub async fn list_vaults(access_token: &str) -> Result<Vec<VaultDescriptor>, ProviderError> {
    let client = crate::cloud::http_client::client();
    let url = format!(
        "{DRIVE_FILES_URL}?spaces=appDataFolder&fields=nextPageToken,files(id,name,mimeType,modifiedTime,size,headRevisionId,version,properties,appProperties)&pageSize=100"
    );

    let resp = client
        .get(&url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::RemoteUnavailable,
                format!("network error: {:?}", e),
            )
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        return Err(ProviderError::new(kind, body));
    }

    let list: DriveFileList = resp.json().await.map_err(|e| {
        ProviderError::new(ProviderErrorKind::Unknown, format!("parse error: {:?}", e))
    })?;

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
) -> Result<(Vec<u8>, String), ProviderError> {
    // First get metadata to get revision
    let client = crate::cloud::http_client::client();
    let meta_url = format!(
        "{DRIVE_FILES_URL}/{}?fields=id,headRevisionId,version,modifiedTime",
        file_id
    );
    let meta_resp = client
        .get(&meta_url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::RemoteUnavailable,
                format!("network error: {:?}", e),
            )
        })?;

    if !meta_resp.status().is_success() {
        let status = meta_resp.status();
        let body = meta_resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        return Err(ProviderError::new(kind, body));
    }

    #[derive(Deserialize)]
    struct Meta {
        #[serde(rename = "headRevisionId")]
        head_revision_id: Option<String>,
        version: Option<String>,
    }
    let meta: Meta = meta_resp.json().await.map_err(|e| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            format!("meta parse error: {:?}", e),
        )
    })?;

    let revision = meta
        .head_revision_id
        .or(meta.version)
        .unwrap_or_else(|| "unknown".to_string());

    // Now download content
    let dl_url = format!("{DRIVE_FILES_URL}/{}?alt=media", file_id);
    let dl_resp = client
        .get(&dl_url)
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::RemoteUnavailable,
                format!("network error: {:?}", e),
            )
        })?;

    if !dl_resp.status().is_success() {
        let status = dl_resp.status();
        let body = dl_resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        return Err(ProviderError::new(kind, body));
    }

    let bytes = dl_resp
        .bytes()
        .await
        .map_err(|e| {
            ProviderError::new(ProviderErrorKind::Unknown, format!("bytes error: {:?}", e))
        })?
        .to_vec();

    Ok((bytes, revision))
}

pub async fn create_vault(
    access_token: &str,
    vault_id: &str,
    package_bytes: &[u8],
) -> Result<(String, String), ProviderError> {
    let client = crate::cloud::http_client::client();
    // Check if file already exists (idempotent)
    let existing = list_vaults(access_token).await?;
    if let Some(found) = existing.iter().find(|v| v.vault_id == vault_id) {
        // File already exists – verify content matches? For idempotent retry, return existing
        // We read and verify package's vault_id matches – caller will verify read-back
        return Ok((
            found.file_id.clone(),
            found
                .head_revision_id
                .clone()
                .or(found.version.clone())
                .unwrap_or_else(|| "unknown".to_string()),
        ));
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
            reqwest::multipart::Part::text(metadata.to_string())
                .mime_str("application/json")
                .unwrap(),
        )
        .part(
            "media",
            reqwest::multipart::Part::bytes(package_bytes.to_vec())
                .mime_str("application/json")
                .unwrap()
                .file_name(file_name.clone()),
        );

    let resp = client
        .post(format!(
            "{UPLOAD_URL}?uploadType=multipart&fields=id,headRevisionId,version"
        ))
        .bearer_auth(access_token)
        .multipart(form)
        .send()
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::RemoteUnavailable,
                format!("network error: {:?}", e),
            )
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        return Err(ProviderError::new(kind, body));
    }

    #[derive(Deserialize)]
    struct CreateResp {
        id: String,
        #[serde(rename = "headRevisionId")]
        head_revision_id: Option<String>,
        version: Option<String>,
    }
    let cr: CreateResp = resp.json().await.map_err(|e| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            format!("create parse error: {:?}", e),
        )
    })?;
    let rev = cr
        .head_revision_id
        .or(cr.version)
        .unwrap_or_else(|| "unknown".to_string());
    Ok((cr.id, rev))
}

pub async fn replace_vault(
    access_token: &str,
    file_id: &str,
    package_bytes: &[u8],
    if_match_revision: Option<&str>,
) -> Result<String, ProviderError> {
    let client = crate::cloud::http_client::client();

    // Conditional write: refuse unless the file is still at the revision we
    // last observed. This is the gate that stops a stale mirror (or a stale
    // client) from clobbering a newer Drive copy.
    //
    // Note the ordering: this read-then-write is *not* atomic at the provider
    // level, so a change landing between the two calls could still be
    // overwritten. That is accepted because Drive offers no true conditional
    // write, and the alternative — unconditional overwrite — would let a stale
    // mirror destroy a newer backup, which is strictly worse. The failure mode
    // is bounded to one revision of drift.
    if let Some(expected) = if_match_revision {
        let current = file_revision(access_token, file_id).await?;
        if current != expected {
            return Err(ProviderError::new(
                ProviderErrorKind::RemoteConflict,
                format!(
                    "revision mismatch: expected {}, got {}",
                    expected,
                    if current == UNKNOWN_REVISION {
                        "(none)"
                    } else {
                        &current
                    }
                ),
            ));
        }
    }

    // Media upload to update file content: PATCH /upload/drive/v3/files/{fileId}?uploadType=media
    let resp = client
        .patch(format!(
            "{UPLOAD_URL}/{}?uploadType=media&fields=id,headRevisionId,version",
            file_id
        ))
        .bearer_auth(access_token)
        .header("Content-Type", "application/json")
        .body(package_bytes.to_vec())
        .send()
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::RemoteUnavailable,
                format!("network error: {:?}", e),
            )
        })?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        return Err(ProviderError::new(kind, body));
    }

    // `id` is returned by Drive but unused here: the caller already knows which
    // file it wrote. Only the revision matters, and that becomes the next CAS
    // baseline.
    #[derive(Deserialize)]
    struct UpdateResp {
        #[serde(rename = "headRevisionId")]
        head_revision_id: Option<String>,
        version: Option<String>,
    }
    let ur: UpdateResp = resp.json().await.map_err(|e| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            format!("update parse error: {:?}", e),
        )
    })?;
    let rev = ur
        .head_revision_id
        .or(ur.version)
        .unwrap_or_else(|| "unknown".to_string());
    Ok(rev)
}

pub async fn delete_vault(access_token: &str, file_id: &str) -> Result<(), ProviderError> {
    let client = crate::cloud::http_client::client();
    // Drive appDataFolder files cannot be trashed, but can be deleted via files.delete (permanent).
    // However spec says cannot trash; delete may also be not supported? We'll try delete.
    // If delete fails with notSupportedForAppDataFolderFiles, map to permission denied.
    let resp = client
        .delete(format!("{DRIVE_FILES_URL}/{}", file_id))
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::RemoteUnavailable,
                format!("network error: {:?}", e),
            )
        })?;

    if !resp.status().is_success() {
        // 204 is success for delete
        if resp.status() == StatusCode::NO_CONTENT {
            return Ok(());
        }
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        let kind = map_google_http_error(status, &body);
        if body.contains("notSupportedForAppDataFolderFiles") {
            return Err(ProviderError::new(
                ProviderErrorKind::PermissionDenied,
                body,
            ));
        }
        return Err(ProviderError::new(kind, body));
    }
    Ok(())
}
