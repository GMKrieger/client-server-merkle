// server/src/main.rs
use actix_web::{App, HttpResponse, HttpServer, Responder, Result, web};
use base64::{Engine as _, engine::general_purpose};
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
struct CommitResponse {
    root: String,
}

async fn upload(
    state: web::Data<AppState>,
    query: web::Query<std::collections::HashMap<String, String>>,
    body: web::Bytes,
) -> Result<impl Responder> {
    let filename = match query.get("name") {
        Some(n) => n.clone(),
        None => return Ok(HttpResponse::BadRequest().body("missing ?name=")),
    };

    let path = state.storage_dir.join(&filename);
    // ensure directory exists
    fs::create_dir_all(&state.storage_dir)?;

    // write file bytes
    let mut f = fs::File::create(&path)?;
    f.write_all(&body)?;

    // Rebuild Merkle tree (simple approach: read all files sorted)
    let mut entries: Vec<_> = fs::read_dir(&state.storage_dir)?
        .filter_map(|res| res.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().into_string().ok())
        .filter_map(|s| s)
        .collect();

    entries.sort(); // deterministic ordering

    let mut files_bytes: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
    for name in &entries {
        let p = state.storage_dir.join(name);
        let data = fs::read(p)?;
        files_bytes.push(data);
    }

    let tree = MerkleTree::from_bytes_vec(&files_bytes)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    {
        let mut cache = state.cache.write().await;
        *cache = Some(tree);
    }

    Ok(HttpResponse::Ok().body("uploaded"))
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
    let proof = tree.generate_proof(index)
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

/// POST /commit
/// Rebuilds the tree from files on disk, persists manifest & root, and returns root hex.
async fn commit(state: web::Data<AppState>) -> Result<impl actix_web::Responder> {
    // read all filenames (sorted)
    let mut entries: Vec<_> = std::fs::read_dir(&state.storage_dir)?
        .filter_map(|r| r.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().into_string().ok())
        .filter_map(|s| s)
        .collect();
    entries.sort();

    // read bytes and compute tree
    let mut files_bytes: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
    for name in &entries {
        let pb = state.storage_dir.join(name);
        let data = std::fs::read(pb)?;
        files_bytes.push(data);
    }

    let tree = MerkleTree::from_bytes_vec(&files_bytes)
        .map_err(|e| actix_web::error::ErrorInternalServerError(e.to_string()))?;
    let root = tree.root_hash();
    let root_hex = hex::encode(&root);

    // persist manifest + root
    let manifest_path = state.storage_dir.join("manifest.json");
    let root_path = state.storage_dir.join("root.hex");

    // manifest: list of filenames in order
    let manifest_json = serde_json::to_string(&entries)?;
    let mut mfile = File::create(manifest_path)?;
    mfile.write_all(manifest_json.as_bytes())?;

    // root hex
    let mut rfile = File::create(root_path)?;
    rfile.write_all(root_hex.as_bytes())?;

    // cache tree
    {
        let mut cache = state.cache.write().await;
        *cache = Some(tree);
    }

    Ok(HttpResponse::Ok().json(CommitResponse { root: root_hex }))
}

async fn root(state: web::Data<AppState>) -> Result<impl Responder> {
    let cache = state.cache.read().await;
    if let Some(tree) = cache.as_ref() {
        Ok(HttpResponse::Ok().body(hex::encode(tree.root_hash())))
    } else {
        Ok(HttpResponse::Ok().body("no root yet"))
    }
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
            .route("/commit", web::post().to(commit))
    })
    .bind(("0.0.0.0", port))?
    .run()
    .await
}
