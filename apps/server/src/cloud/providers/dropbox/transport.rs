use crate::cloud::{
    error::{ProviderError, ProviderErrorKind},
    provider::RemoteVaultFile,
};
const API: &str = "https://api.dropboxapi.com/2";
const CONTENT: &str = "https://content.dropboxapi.com/2";
#[derive(serde::Deserialize, Clone)]
pub struct Meta {
    id: String,
    name: String,
    path_display: Option<String>,
    pub rev: Option<String>,
    size: Option<u64>,
    server_modified: Option<String>,
}
fn failure(status: reqwest::StatusCode, body: String) -> ProviderError {
    let kind = if status.as_u16() == 409 {
        ProviderErrorKind::RemoteConflict
    } else if status.as_u16() == 401 {
        ProviderErrorKind::AuthRequired
    } else if status.as_u16() == 429 {
        ProviderErrorKind::RateLimited
    } else {
        ProviderErrorKind::RemoteUnavailable
    };
    ProviderError::new(kind, format!("Dropbox API status {status}: {body}"))
}
async fn metadata_path(token: &str, path: &str) -> Result<Meta, ProviderError> {
    let r = crate::cloud::http_client::client()
        .post(format!("{API}/files/get_metadata"))
        .bearer_auth(token)
        .json(&serde_json::json!({"path":path,"include_deleted":false}))
        .send()
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::RemoteUnavailable,
                format!("Dropbox metadata transport: {e:?}"),
            )
        })?;
    if !r.status().is_success() {
        return Err(failure(r.status(), r.text().await.unwrap_or_default()));
    }
    r.json().await.map_err(|e| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            format!("Dropbox metadata parse: {e:?}"),
        )
    })
}
pub async fn metadata(token: &str, id: &str) -> Result<Meta, ProviderError> {
    metadata_path(token, id).await
}
fn descriptor(m: Meta) -> Option<RemoteVaultFile> {
    // Root listing can include non-file entries without a revision.
    let path = m.path_display.as_deref()?;
    let name = m.name;
    let id = path.strip_prefix("/voult-vault-")?.strip_suffix(".json")?;
    let vault_id = uuid::Uuid::parse_str(id).ok()?.to_string();
    let revision = m.rev?;
    Some(RemoteVaultFile {
        vault_id,
        file_id: m.id,
        revision,
        name,
        modified_time: m.server_modified,
        size: m.size.map(|s| s.to_string()),
    })
}
pub async fn list(token: &str) -> Result<Vec<RemoteVaultFile>, ProviderError> {
    #[derive(serde::Deserialize)]
    struct L {
        entries: Vec<Meta>,
        has_more: bool,
        cursor: String,
    }
    let client = crate::cloud::http_client::client();
    let mut request = serde_json::json!({"path":"","recursive":false,"include_deleted":false});
    let mut output = Vec::new();
    loop {
        let endpoint = if request.get("cursor").is_some() {
            "list_folder/continue"
        } else {
            "list_folder"
        };
        let r = client
            .post(format!("{API}/files/{endpoint}"))
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
            .map_err(|e| {
                ProviderError::new(
                    ProviderErrorKind::RemoteUnavailable,
                    format!("Dropbox list transport: {e:?}"),
                )
            })?;
        if !r.status().is_success() {
            return Err(failure(r.status(), r.text().await.unwrap_or_default()));
        }
        let page: L = r.json().await.map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::Unknown,
                format!("Dropbox list parse: {e:?}"),
            )
        })?;
        output.extend(page.entries.into_iter().filter_map(descriptor));
        if !page.has_more {
            break;
        }
        request = serde_json::json!({"cursor":page.cursor});
    }
    Ok(output)
}
fn path(v: &str) -> String {
    format!("/voult-vault-{v}.json")
}
pub async fn create(
    token: &str,
    vault: &str,
    bytes: &[u8],
) -> Result<RemoteVaultFile, ProviderError> {
    if let Some(f) = list(token).await?.into_iter().find(|f| f.vault_id == vault) {
        return Ok(f);
    }
    let r = crate::cloud::http_client::client()
        .post(format!("{CONTENT}/files/upload"))
        .bearer_auth(token)
        .header(
            "Dropbox-API-Arg",
            serde_json::json!({
                "path": path(vault),
                "mode": "add",
                "autorename": false,
                "mute": true,
                "strict_conflict": true
            })
            .to_string(),
        )
        .header("content-type", "application/octet-stream")
        .body(bytes.to_vec())
        .send()
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::RemoteUnavailable,
                format!("Dropbox upload transport: {e:?}"),
            )
        })?;
    if !r.status().is_success() {
        return Err(failure(r.status(), r.text().await.unwrap_or_default()));
    }
    let m: Meta = r.json().await.map_err(|e| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            format!("Dropbox upload parse: {e:?}"),
        )
    })?;
    descriptor(m).ok_or_else(|| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            "Dropbox returned unexpected vault path",
        )
    })
}
pub async fn read(token: &str, id: &str) -> Result<(Vec<u8>, String), ProviderError> {
    let m = metadata(token, id).await?;
    let r = crate::cloud::http_client::client()
        .post(format!("{CONTENT}/files/download"))
        .bearer_auth(token)
        .header(
            "Dropbox-API-Arg",
            serde_json::json!({"path":id}).to_string(),
        )
        .send()
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::RemoteUnavailable,
                format!("Dropbox download transport: {e:?}"),
            )
        })?;
    if !r.status().is_success() {
        return Err(failure(r.status(), r.text().await.unwrap_or_default()));
    }
    let b = r.bytes().await.map_err(|e| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            format!("Dropbox download body: {e:?}"),
        )
    })?;
    let revision = m.rev.ok_or_else(|| {
        ProviderError::new(
            ProviderErrorKind::RemoteRevisionUnavailable,
            "Dropbox file has no revision",
        )
    })?;
    Ok((b.to_vec(), revision))
}
pub async fn write(
    token: &str,
    id: &str,
    bytes: &[u8],
    rev: &str,
) -> Result<String, ProviderError> {
    let r = crate::cloud::http_client::client()
        .post(format!("{CONTENT}/files/upload"))
        .bearer_auth(token)
        .header(
            "Dropbox-API-Arg",
            serde_json::json!({
                "path": id,
                "mode": {".tag": "update", "update": rev},
                "autorename": false,
                "mute": true
            })
            .to_string(),
        )
        .header("content-type", "application/octet-stream")
        .body(bytes.to_vec())
        .send()
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::RemoteUnavailable,
                format!("Dropbox conditional upload transport: {e:?}"),
            )
        })?;
    if !r.status().is_success() {
        return Err(failure(r.status(), r.text().await.unwrap_or_default()));
    }
    let m: Meta = r.json().await.map_err(|e| {
        ProviderError::new(
            ProviderErrorKind::Unknown,
            format!("Dropbox upload parse: {e:?}"),
        )
    })?;
    m.rev.ok_or_else(|| {
        ProviderError::new(
            ProviderErrorKind::RemoteRevisionUnavailable,
            "Dropbox upload response omitted revision",
        )
    })
}
pub async fn delete(token: &str, id: &str) -> Result<(), ProviderError> {
    let r = crate::cloud::http_client::client()
        .post(format!("{API}/files/delete_v2"))
        .bearer_auth(token)
        .json(&serde_json::json!({"path":id}))
        .send()
        .await
        .map_err(|e| {
            ProviderError::new(
                ProviderErrorKind::RemoteUnavailable,
                format!("Dropbox delete transport: {e:?}"),
            )
        })?;
    if !r.status().is_success() {
        return Err(failure(r.status(), r.text().await.unwrap_or_default()));
    }
    Ok(())
}
