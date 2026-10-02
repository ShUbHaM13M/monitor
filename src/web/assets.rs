use axum::extract::Path;
use axum::http::header;
use axum::response::IntoResponse;
use rust_embed::Embed;

use super::error::AppError;

/// Files under `static/`, embedded into the binary in release builds
/// (read from disk in debug builds, so edits show up without recompiling).
#[derive(Embed)]
#[folder = "static/"]
struct Assets;

pub async fn serve(Path(path): Path<String>) -> Result<impl IntoResponse, AppError> {
    let file = Assets::get(&path).ok_or(AppError::NotFound)?;
    Ok((
        [
            (header::CONTENT_TYPE, file.metadata.mimetype().to_owned()),
            (header::CACHE_CONTROL, "public, max-age=3600".to_owned()),
        ],
        file.data,
    ))
}
