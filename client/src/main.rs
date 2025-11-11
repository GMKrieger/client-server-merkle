// client/src/main.rs
use base64::{Engine as _, engine::general_purpose};
use clap::{Parser, Subcommand};
use merkle::{MerkleTree, ProofNode, sha256};
use reqwest::Client;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "merkle-client")]
struct Cli {
    #[command(subcommand)]
    cmd: Commands,

    #[arg(long, default_value = "http://localhost:3000")]
    server: String,
}

#[derive(Subcommand)]
enum Commands {
    Upload {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long, default_value = "./merkle_root.hex")]
        root_file: PathBuf,
    },
    Request {
        #[arg(long)]
        name: String,
        #[arg(long, default_value = "./merkle_root.hex")]
        root_file: PathBuf,
        #[arg(long)]
        out: Option<PathBuf>,
    },
}

#[derive(serde::Deserialize)]
struct UploadResp {
    root: String,
    files_count: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Commands::Upload { dir, root_file } => {
            upload_dir(&cli.server, dir, root_file).await?;
        }
        Commands::Request {
            name,
            root_file,
            out,
        } => {
            request_file(&cli.server, &name, root_file, out).await?;
        }
    }
    Ok(())
}

fn validate_filename(name: &str) -> anyhow::Result<()> {
    if name.is_empty() {
        anyhow::bail!("filename cannot be empty");
    }
    if name.contains("..") || name.contains('/') || name.contains('\\') {
        anyhow::bail!("invalid filename '{}': path traversal not allowed", name);
    }
    if name == "manifest.json" || name == "root.hex" {
        anyhow::bail!("invalid filename '{}': reserved name", name);
    }
    if name.chars().any(|c| c.is_control() || c == '\0') {
        anyhow::bail!("invalid filename '{}': contains control characters", name);
    }
    if name.len() > 255 {
        anyhow::bail!("filename '{}' too long (max 255 characters)", name);
    }
    Ok(())
}

async fn upload_dir(server: &str, dir: PathBuf, root_file: PathBuf) -> anyhow::Result<()> {
    // 1. Read and sort local files
    let mut entries: Vec<_> = fs::read_dir(&dir)?
        .filter_map(|r| r.ok())
        .filter(|e| e.file_type().map(|t| t.is_file()).unwrap_or(false))
        .map(|e| e.file_name().into_string().ok())
        .filter_map(|s| s)
        .collect();
    entries.sort();

    if entries.is_empty() {
        anyhow::bail!("No files found in directory");
    }

    // Validate all filenames before uploading
    for name in &entries {
        validate_filename(name)?;
    }

    let mut files_bytes: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
    for name in &entries {
        let p = dir.join(name);
        let data = fs::read(&p)?;
        files_bytes.push(data);
    }

    // 2. Build local Merkle tree and compute root
    let tree = MerkleTree::from_bytes_vec(&files_bytes)?;
    let local_root_hex = hex::encode(tree.root_hash()?);
    println!("Local root: {}", local_root_hex);

    // 3. Build multipart form with all files
    let client = Client::new();
    let url = format!("{}/upload", server.trim_end_matches('/'));

    let mut form = reqwest::multipart::Form::new();
    for (i, name) in entries.iter().enumerate() {
        let bytes = files_bytes[i].clone();
        let part = reqwest::multipart::Part::bytes(bytes).file_name(name.clone());
        form = form.part(name.clone(), part);
        println!("Adding {} to upload", name);
    }

    // 4. Send upload request
    println!("Uploading {} files...", entries.len());
    let resp = client.post(&url).multipart(form).send().await?;

    if !resp.status().is_success() {
        anyhow::bail!("upload failed: {}", resp.text().await?);
    }

    let upload_obj: UploadResp = resp.json().await?;
    println!(
        "Server received {} files, root: {}",
        upload_obj.files_count, upload_obj.root
    );

    // 5. Compare local root vs server root
    if upload_obj.root != local_root_hex {
        anyhow::bail!(
            "root mismatch: local {} vs server {}",
            local_root_hex,
            upload_obj.root
        );
    }

    println!("Root hashes match!");

    // 6. On match, persist local root and delete local files
    fs::write(&root_file, local_root_hex.as_bytes())?;
    for name in &entries {
        let p = dir.join(name);
        fs::remove_file(p)?;
        println!("deleted local {}", name);
    }

    println!("Upload complete; local root saved at {:?}", root_file);
    Ok(())
}

async fn request_file(
    server: &str,
    name: &str,
    root_file: PathBuf,
    out: Option<PathBuf>,
) -> anyhow::Result<()> {
    // validate filename
    validate_filename(name)?;

    // read local saved root
    let saved_root = fs::read_to_string(&root_file)?;
    let saved_root_bytes = hex::decode(saved_root.trim())?;

    // fetch from server
    let url = format!(
        "{}/file/{}",
        server.trim_end_matches('/'),
        urlencoding::encode(name)
    );
    let resp = reqwest::get(&url).await?;
    if !resp.status().is_success() {
        anyhow::bail!("server returned error: {}", resp.status());
    }
    let json: serde_json::Value = resp.json().await?;
    let file_b64 = json["file_bytes"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("missing file_bytes"))?;
    let proof_val = &json["proof"];
    let server_root_hex = json["root"].as_str().unwrap_or_default();

    let file_bytes = general_purpose::STANDARD.decode(file_b64)?;
    let proof: Vec<ProofNode> = serde_json::from_value(proof_val.clone())?;
    let leaf_hash = sha256(&file_bytes);

    // verify using local saved root
    let ok_local = MerkleTree::verify_proof(&leaf_hash, &proof, &saved_root_bytes);
    if !ok_local {
        anyhow::bail!(
            "Verification FAILED: proof does not match local saved root. Server root: {}. File rejected.",
            server_root_hex
        );
    }

    println!("File verified against local saved root.");

    // write file only if verification succeeded
    let out_path = out.unwrap_or_else(|| PathBuf::from(name));
    let mut f = fs::File::create(&out_path)?;
    f.write_all(&file_bytes)?;
    println!("Wrote file to {:?}", out_path);

    Ok(())
}
