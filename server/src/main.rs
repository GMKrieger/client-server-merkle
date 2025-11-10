// server/src/main.rs
use actix_multipart::Multipart;
use actix_web::{App, HttpResponse, HttpServer, Responder, Result, web};
use base64::{Engine as _, engine::general_purpose};
use futures_util::stream::StreamExt as _;
use serde::Serialize;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

use merkle::{MerkleTree, ProofNode};

#[derive(Clone)]
struct AppState {
    storage_dir: PathBuf,
    // We'll keep a cached root and tree; rebuild on each upload for simplicity
    // Use an RwLock for concurrency
    cache: Arc<RwLock<Option<MerkleTree>>>,
}

#[derive(Serialize)]
struct FileResponse {
    file_name: String,
    file_bytes: String, // base64
    proof: Vec<ProofNode>,
    root: String, // hex
}

#[derive(Serialize)]
struct UploadResponse {
    root: String,
    files_count: usize,
}

async fn get_file(state: web::Data<AppState>, path: web::Path<String>) -> Result<impl Responder> {
    let file_name = path.into_inner();
    let p = state.storage_dir.join(&file_name);

    if !p.exists() {
        return Ok(HttpResponse::NotFound().body("file not found"));
    }

    // read list of files (sorted)
    let mut entries: Vec<_> = fs::read_dir(&state.storage_dir)?
        .filter_map(|res| res.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().into_string().ok())
        .filter_map(|s| s)
        .collect();
    entries.sort();

    // read all files in that order
    let mut files_bytes: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
    for name in &entries {
        let pb = state.storage_dir.join(name);
        let data = fs::read(pb)?;
        files_bytes.push(data);
    }

    let tree = MerkleTree::from_bytes_vec(&files_bytes)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let root = tree.root_hash();

    // find index
    let index = entries.iter().position(|n| n == &file_name);
    let index = match index {
        Some(i) => i,
        None => return Ok(HttpResponse::NotFound().body("file not indexed")),
    };

    // generate proof
    let proof = tree
        .generate_proof(index)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let file_bytes = files_bytes[index].clone();
    let file_b64 = general_purpose::STANDARD.encode(&file_bytes);
    let root_hex = hex::encode(&root);

    let resp = FileResponse {
        file_name,
        file_bytes: file_b64,
        proof,
        root: root_hex,
    };

    Ok(HttpResponse::Ok().json(resp))
}

async fn root(state: web::Data<AppState>) -> Result<impl Responder> {
    let cache = state.cache.read().await;
    if let Some(tree) = cache.as_ref() {
        Ok(HttpResponse::Ok().body(hex::encode(tree.root_hash())))
    } else {
        Ok(HttpResponse::Ok().body("no root yet"))
    }
}

/// POST /upload
/// Receives all files via multipart/form-data, clears storage, builds new tree.
async fn upload(state: web::Data<AppState>, mut payload: Multipart) -> Result<impl Responder> {
    // 1. Clear storage directory (delete all existing files)
    if state.storage_dir.exists() {
        for entry in fs::read_dir(&state.storage_dir)? {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                fs::remove_file(entry.path())?;
            }
        }
    } else {
        fs::create_dir_all(&state.storage_dir)?;
    }

    // 2. Process multipart data and save files
    let mut file_count = 0;
    while let Some(item) = payload.next().await {
        let mut field = item.map_err(actix_web::error::ErrorBadRequest)?;

        // Get filename from content disposition
        let content_disp = field.content_disposition();
        let filename = content_disp
            .and_then(|cd| cd.get_filename())
            .ok_or_else(|| actix_web::error::ErrorBadRequest("missing filename"))?;

        let filepath = state.storage_dir.join(filename);

        // Create file and write chunks
        let mut f = web::block(move || std::fs::File::create(filepath))
            .await?
            .map_err(actix_web::error::ErrorInternalServerError)?;

        // Write field data to file
        while let Some(chunk) = field.next().await {
            let data = chunk.map_err(actix_web::error::ErrorBadRequest)?;
            f = web::block(move || f.write_all(&data).map(|_| f))
                .await?
                .map_err(actix_web::error::ErrorInternalServerError)?;
        }

        file_count += 1;
    }

    // 3. Read all filenames (sorted)
    let mut entries: Vec<_> = fs::read_dir(&state.storage_dir)?
        .filter_map(|r| r.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().into_string().ok())
        .filter_map(|s| s)
        .collect();
    entries.sort();

    // 4. Read bytes and compute tree
    let mut files_bytes: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
    for name in &entries {
        let pb = state.storage_dir.join(name);
        let data = fs::read(pb)?;
        files_bytes.push(data);
    }

    let tree = MerkleTree::from_bytes_vec(&files_bytes)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let root = tree.root_hash();
    let root_hex = hex::encode(&root);

    // 5. Persist manifest + root
    let manifest_path = state.storage_dir.join("manifest.json");
    let root_path = state.storage_dir.join("root.hex");

    let manifest_json = serde_json::to_string(&entries)?;
    let mut mfile = File::create(manifest_path)?;
    mfile.write_all(manifest_json.as_bytes())?;

    let mut rfile = File::create(root_path)?;
    rfile.write_all(root_hex.as_bytes())?;

    // 6. Cache tree
    {
        let mut cache = state.cache.write().await;
        *cache = Some(tree);
    }

    Ok(HttpResponse::Ok().json(UploadResponse {
        root: root_hex,
        files_count: file_count,
    }))
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let storage_dir = std::env::var("STORAGE_DIR").unwrap_or_else(|_| "./server_files".to_string());
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3000);

    let state = AppState {
        storage_dir: PathBuf::from(storage_dir),
        cache: Arc::new(RwLock::new(None)),
    };

    println!(
        "Starting server on 0.0.0.0:{} storing files in {:?}",
        port, state.storage_dir
    );

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .route("/upload", web::post().to(upload))
            .route("/file/{name}", web::get().to(get_file))
            .route("/root", web::get().to(root))
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
