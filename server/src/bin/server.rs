use clap::Parser;
use log::{error, info};
use rand::RngCore;
use sindri::crypto::rng;
use sindri::host;
use sindri::host::core::Core;
use std::io::{BufRead, ErrorKind, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::{fs, io};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Unix domain socket path
    #[clap(short, long, default_value = "sindri.sock")]
    socket: PathBuf,
}

struct ListenerSocket {
    path: PathBuf,
}

impl ListenerSocket {
    fn new(path: PathBuf) -> Result<ListenerSocket, io::Error> {
        // Remove old socket if it exists
        if let Ok(metadata) = fs::metadata(&path) {
            if metadata.len() == 0 && !metadata.is_dir() {
                info!("Deleting old socket '{}'", path.to_string_lossy());
                if let Err(e) = fs::remove_file(&path) {
                    error!("Failed to close old socket");
                    return Err(e);
                };
            } else {
                error!(
                    "Socket file or directory {} already exists",
                    path.to_string_lossy()
                );
                return Err(ErrorKind::AlreadyExists.into());
            }
        }
        Ok(ListenerSocket { path })
    }

    fn bind(&mut self) -> Result<UnixListener, io::Error> {
        UnixListener::bind(&self.path)
    }
}

impl Drop for ListenerSocket {
    fn drop(&mut self) {
        let path = self.path.to_string_lossy();
        match fs::remove_file(&self.path) {
            Ok(()) => {
                info!("Closed socket '{path}'")
            }
            Err(_) => {
                error!("Failed to close socket '{path}'");
            }
        }
    }
}

struct Client {
    stream: UnixStream,
}

impl host::core::Client for Client {
    fn write(&mut self, data: &[u8]) {
        let response = base64::encode(data);
        info!(
            "Sending encoded request ({} bytes) to client: {}",
            response.len(),
            hex::encode(&response)
        );
        if let Err(e) = writeln!(self.stream, "{response}") {
            error!("Failed to write to socket: {}", e);
        };
    }
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
    let mut listener = ListenerSocket::new(args.socket).expect("Failed to create socket");
    let listener = listener.bind().expect("Failed to bind to socket");
    for stream in listener.incoming().filter_map(Result::ok) {
        let reader = io::BufReader::new(stream.try_clone().expect("Failed to clone stream"));
        let mut client = Client { stream };
        for request in reader
            .lines()
            .filter_map(Result::ok)
            .filter_map(|s| base64::decode(s).ok())
        {
            info!(
                "Received request ({} bytes): {}",
                request.len(),
                hex::encode(&request)
            );
            if let Err(e) = core.process(&mut client, &request) {
                error!("Failed to send data to core: {:?}", e);
            }
        }
    }
}
