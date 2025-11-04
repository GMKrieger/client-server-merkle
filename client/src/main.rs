use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "merkle-client")]
#[command(about = "Client to upload and verify files", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Upload {
        #[arg(short, long)]
        path: String,
    },
    Request {
        #[arg(short, long)]
        file: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Upload { path } => {
            println!("Uploading files from {}", path);
            // TODO: Read files, build Merkle tree, send to server
        }
        Commands::Request { file } => {
            println!("Requesting file: {}", file);
            // TODO: Send request to server, verify Merkle proof
        }
    }
}
