# Client-Server Merkle Tree File Storage

A Rust-based client-server system implementing Merkle tree verification for secure file storage and retrieval. The system allows clients to upload files to a server, verify data integrity using Merkle proofs, and retrieve files with cryptographic verification.

## Overview

This project demonstrates how Merkle trees can be used to ensure data integrity in distributed file storage:

1. **Client builds local Merkle tree** → Computes root hash from all files
2. **Client performs upload** → All files sent in single atomic request
3. **Server builds Merkle tree** → Replaces any existing tree with new one
4. **Client verifies root hash** → Client and server roots must match
5. **Client can retrieve files** → Server provides file + Merkle proof
6. **Client verifies proof** → Ensures file hasn't been tampered with

### Why Merkle Trees?

Merkle trees allow efficient verification of large datasets:
- **Integrity**: Any change to a file changes the root hash
- **Efficiency**: Only need to verify O(log n) hashes to prove a file is authentic
- **Tamper Detection**: Cannot modify files without detection

## Architecture

### Project Structure

```
client-server-merkle/
├── merkle/          # Core Merkle tree library
│   └── src/
│       └── lib.rs   # Tree building, proof generation, verification
├── server/          # HTTP server (Actix-web)
│   └── src/
│       └── main.rs  # File storage + Merkle proof endpoints
├── client/          # CLI client (Clap)
│   └── src/
│       └── main.rs  # Upload/download commands
├── Dockerfile.server
├── Dockerfile.client
└── docker-compose.yml
```

### Components

**Merkle Library** (`merkle/`)
- SHA-256 based Merkle tree implementation
- Proof generation and verification
- Handles odd number of nodes by duplicating the last leaf

**Server** (`server/`)
- Actix-web HTTP server on port 3000
- Stores files in a directory
- Atomic upload: clears storage and builds new Merkle tree
- Provides files with cryptographic proofs

**Client** (`client/`)
- CLI tool for uploading and requesting files
- Verifies server integrity before deleting local files
- Checks Merkle proofs on file retrieval

## Local Development

### Prerequisites

- Rust 1.70+ (uses edition 2024)
- Cargo

### Build

Build the entire workspace:
```bash
cargo build --release
```

Build individual components:
```bash
cargo build --release -p merkle
cargo build --release -p server
cargo build --release -p client
```

### Run Tests

```bash
cargo test
```

Run tests for a specific package:
```bash
cargo test -p merkle
```

### Run Locally

**Start the server:**
```bash
# Default: stores files in ./server_files, runs on port 3000
cargo run --release --bin server

# Custom configuration:
STORAGE_DIR=/path/to/storage PORT=8080 cargo run --release --bin server
```

**Run the client:**

Upload files:
```bash
cargo run --release --bin client -- upload \
  --dir ./my_files \
  --root-file ./merkle_root.hex
```

Request a file:
```bash
cargo run --release --bin client -- request \
  --name example.txt \
  --root-file ./merkle_root.hex \
  --out ./downloaded.txt
```

Use a custom server:
```bash
cargo run --release --bin client -- \
  --server http://localhost:3000 \
  upload --dir ./my_files
```

## Docker Deployment

### Quick Start

```bash
# Create local directories for file storage (if not already created)
mkdir -p client_files server_files

# Start the server
docker-compose up -d server

# Check status
docker-compose ps

# View server logs
docker-compose logs -f server
```

### Container Architecture

- **merkle-server**: Runs the HTTP server continuously
  - Exposed on `http://localhost:3000`
  - Persistent storage via bind mount to `./server_files/`

- **merkle-client**: Interactive container for running client commands
  - Connects to server via internal Docker network
  - Persistent storage via bind mount to `./client_files/`

**Important**: The containers use bind mounts, meaning files in `./client_files/` and `./server_files/` on your host are directly accessible inside the containers. No copying required!

### Using the Client Container

**Prepare files on your host:**
```bash
# Place files you want to upload in the local directory
echo "Hello Merkle!" > ./client_files/test.txt
cp /path/to/myfile.txt ./client_files/
```

**Run client commands directly (recommended):**
```bash
# Upload files to server
docker-compose run --rm client client \
  --server http://server:3000 \
  upload \
  --dir /data/client_files \
  --root-file /data/client_files/root.hex

# Request file back (with verification)
docker-compose run --rm client client \
  --server http://server:3000 \
  request \
  --name test.txt \
  --root-file /data/client_files/root.hex \
  --out /data/client_files/retrieved.txt

# Check the retrieved file on your host
cat ./client_files/retrieved.txt
```

**Alternative: Interactive shell:**
```bash
# Enter the client container
docker-compose exec client /bin/bash

# Inside the container, run commands
client --server http://server:3000 upload \
  --dir /data/client_files \
  --root-file /data/client_files/root.hex
```

### Managing Files in Docker

**Add files for upload:**
```bash
# Files in ./client_files/ are immediately accessible in the container
cp ./myfile.txt ./client_files/
echo "test data" > ./client_files/newfile.txt
```

**Access uploaded files:**
```bash
# Files uploaded to the server appear in ./server_files/
ls -la ./server_files/
cat ./server_files/test.txt
```

**View files in containers (if needed):**
```bash
# List client files
docker-compose exec client ls -la /data/client_files/

# List server files
docker-compose exec server ls -la /data/server_files/
```

### Rebuild Containers

After code changes:
```bash
docker-compose down
docker-compose up -d --build
```

### Clean Up

```bash
# Stop containers
docker-compose down

# Clean up local files (if desired)
rm -rf ./client_files/* ./server_files/*

# Note: The local directories ./client_files/ and ./server_files/ persist on your host
# and are NOT automatically deleted when containers are stopped
```

### Complete Testing Example

Here's a full end-to-end workflow for testing with Docker:

```bash
# 1. Create local directories
mkdir -p client_files server_files

# 2. Create some test files
echo "Hello from file 1" > ./client_files/file1.txt
echo "Hello from file 2" > ./client_files/file2.txt
echo "Hello from file 3" > ./client_files/file3.txt

# 3. Start the server
docker-compose up -d server

# 4. Upload files and get root hash
docker-compose run --rm client client \
  --server http://server:3000 \
  upload \
  --dir /data/client_files \
  --root-file /data/client_files/root.hex

# 5. Check that root.hex was created on your host
cat ./client_files/root.hex

# 6. Verify files were uploaded to server
ls -la ./server_files/

# 7. Request a file back with verification
docker-compose run --rm client client \
  --server http://server:3000 \
  request \
  --name file2.txt \
  --root-file /data/client_files/root.hex

# 8. Clean up
docker-compose down && rm -rf ./client_files/* ./server_files/*
```

## API Endpoints

The server exposes the following HTTP endpoints:

### POST `/upload`
Atomically upload all files and replace the entire Merkle tree.
- **Content-Type**: `multipart/form-data`
- **Body**: All files as multipart form fields
- **Behavior**:
  - Clears all existing files from storage
  - Saves all uploaded files
  - Builds new Merkle tree from uploaded files
  - Persists manifest and root hash
- **Response**:
```json
{
  "root": "hex-encoded-root-hash",
  "files_count": 3
}
```

### GET `/file/{name}`
Retrieve a file with Merkle proof.
- **Response**:
```json
{
  "file_name": "example.txt",
  "file_bytes": "base64-encoded-content",
  "proof": [
    {"hash": [bytes], "is_left": true},
    ...
  ],
  "root": "hex-encoded-root-hash"
}
```

### GET `/root`
Get the current cached Merkle root.
- **Response**: Hex-encoded root hash or `"no root yet"`

## Workflow Example

### Upload Workflow

1. Client reads all local files and sorts them alphabetically
2. Client builds local Merkle tree and computes root hash
3. Client sends all files in a single atomic upload via `POST /upload`
4. Server clears existing storage and saves all uploaded files
5. Server builds new Merkle tree and returns its root hash
6. Client compares local root vs server root
7. If they match: client saves root and deletes local files
8. If mismatch: client aborts with error (files not deleted)

**Key advantage**: The upload is atomic - either all files are uploaded successfully with matching root hash, or nothing changes.

### Retrieval Workflow

1. Client loads previously saved root hash from file
2. Client requests file via `GET /file/{name}`
3. Server responds with file bytes + Merkle proof
4. Client verifies proof against saved root
5. If valid: file is authentic and unmodified
6. Client writes verified file to disk

**Note**: Even if the server tree changes after upload, verification will fail if the file was modified, providing tamper detection.

## File Ordering

**Critical**: Both client and server must sort filenames alphabetically before building the Merkle tree. This ensures consistent tree structure and matching root hashes.

This ordering happens in:
- `client/src/main.rs:64` (upload preparation)
- `server/src/main.rs:53` (get_file endpoint)
- `server/src/main.rs:154` (upload endpoint)

## License

See [LICENSE](LICENSE) for details.