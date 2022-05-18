use clap::Parser;
use cli::common::split_stream;
use log::{error, info};
use rand::RngCore;
use sindri::common::channel::Receiver;
use sindri::crypto::rng;
use sindri::host::core::Core;
use std::fs;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Unix domain socket path
    #[clap(short, long, default_value = "sindri.sock")]
    socket: PathBuf,
}

struct EntropySource {}

impl rng::EntropySource for EntropySource {
    fn random_seed(&mut self) -> [u8; 32] {
        let mut data = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut data);
        data
    }
}

fn main() {
    simple_logger::SimpleLogger::new()
        .init()
        .expect("Failed to initialize logger");
    let args = Args::parse();

    // instantiate core
    let rng = rng::Rng::new(EntropySource {}, None);
    let mut core = Core::new(rng);

    // Listen to socket
    remove_old_socket(args.socket.as_path());
    let listener = UnixListener::bind(args.socket).expect("Failed to create socket");
    for stream in listener.incoming().filter_map(Result::ok) {
        let (mut sender, mut receiver) = split_stream(0, stream);
        let request = receiver.recv();
        info!(
            "Received request ({} bytes): {}",
            request.len(),
            hex::encode(&request)
        );
        if let Err(e) = core.process(&mut sender, &request) {
            error!("Failed to send data to core: {:?}", e);
        }
    }
}

/// Remove old socket if it exists
fn remove_old_socket(socket: &Path) {
    if let Ok(metadata) = fs::metadata(&socket) {
        if metadata.len() == 0 && !metadata.is_dir() {
            info!("Deleting old socket '{}'", socket.to_string_lossy());
            if let Err(e) = fs::remove_file(&socket) {
                error!("Failed to delete old socket: {e}");
            };
        }
    }
}
