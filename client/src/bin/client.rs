use clap::Parser;
use log::{error, info};
use sindri::host::jobs::{Request, Response};
use std::io;
use std::io::{BufRead, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Unix domain socket path
    #[clap(short, long, default_value = "sindri.sock")]
    socket: PathBuf,
}

fn main() {
    simple_logger::SimpleLogger::new()
        .init()
        .expect("Failed to initialize logger");
    let args = Args::parse();

    // Connect tom socket
    let mut stream = UnixStream::connect(&args.socket).expect("Failed to connect to socket");
    info!("Connected to '{}'", args.socket.to_string_lossy());

    // Send request
    let request = Request::GetRandom { size: 16 };
    let request: Vec<u8> = request.try_into().expect("Failed to serialize request");
    info!(
        "Sending request ({} bytes): {}",
        request.len(),
        hex::encode(&request)
    );
    if let Err(e) = writeln!(stream, "{}", base64::encode(request)) {
        error!("Failed to write to socket: '{e}");
    };

    // Wait for response
    let reader = io::BufReader::new(stream.try_clone().expect("Failed to clone stream"));
    let response = reader
        .lines()
        .filter_map(Result::ok)
        .next()
        .expect("Failed to receive response");
    info!(
        "Received encoded response ({} bytes): {}",
        response.len(),
        hex::encode(&response)
    );
    let response = base64::decode(response).expect("Failed to decode response");
    info!(
        "Decoded response ({} bytes): {}",
        response.len(),
        hex::encode(&response)
    );
    match Response::try_from(response.as_slice()).expect("Failed to parse response") {
        Response::Error(e) => {
            error!("Response: Error: {:?}", e)
        }
        Response::GetRandom { data } => {
            info!(
                "Response: random data: ({} bytes): {}",
                data.len(),
                hex::encode(data)
            )
        }
    }
}
