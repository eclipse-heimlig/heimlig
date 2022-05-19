use sindri::common::channel::{Receiver, Sender};
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::os::unix::net::UnixStream;

#[derive(Clone, Eq, PartialEq, Debug)]
pub enum Error {
    Encode,
    Decode,
    Busy,
}

pub struct UnixStreamReceiver {
    id: u32,
    stream: UnixStream,
}

pub struct UnixStreamSender {
    id: u32,
    stream: UnixStream,
}

impl Receiver for UnixStreamReceiver {
    fn id(&self) -> u32 {
        self.id
    }

    fn recv(&mut self) -> Vec<u8> {
        let reader = BufReader::new(&self.stream);
        if let Some(response) = reader.lines().filter_map(Result::ok).next() {
            if let Ok(response) = base64::decode(response) {
                return response;
            }
        }
        return vec![];
    }
}

impl Sender for UnixStreamSender {
    type Error = Error;

    fn id(&self) -> u32 {
        self.id
    }

    fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        writeln!(self.stream, "{}", base64::encode(data)).expect("Failed to write to stream");
        Ok(())
    }
}

pub fn split_stream(id: u32, stream: UnixStream) -> (UnixStreamSender, UnixStreamReceiver) {
    let sender = UnixStreamSender {
        id,
        stream: stream.try_clone().expect("Failed to clone stream"),
    };
    let receiver = UnixStreamReceiver { id, stream };
    (sender, receiver)
}
