use structopt::StructOpt;

/// This command line tool simulates a crypto server. It retrieves data from crypto clients, carries
/// out the requested crypto operation and returns the result to the client. The communication
/// between server and client is based on queues in POSIX shared memory.
#[derive(StructOpt, Debug)]
struct Opt {
    /// Name of the POSIX shared memory object to be used for communicating with the clients. The
    /// name should be in the form of "/somename". If the leading slash is omitted, it'll be added
    /// implicitly.
    #[structopt(long, short)]
    shm: String,
    /// The number of queues which shall be made available in shared memory. This value defines the
    /// number of clients which can communicate with the server simultaneously.
    #[structopt(long, short = "q", default_value = "10")]
    num_queues: usize,
    /// The size each queue shall have in bytes.
    #[structopt(long, short = "n", default_value = "1024")]
    queue_size: usize,
}

fn main() {
    let opt = Opt::from_args();
    println!("{:?}", opt);
}
