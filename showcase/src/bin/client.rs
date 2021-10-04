use structopt::clap::arg_enum;
use structopt::StructOpt;

/// This command line tool simulates a crypto client. It reads data from the standard input,
/// forwards it to the crypto server for processing and writes the result to the standard output.
/// The communication between server and client is based on queues in POSIX shared memory.
#[derive(StructOpt, Debug)]
struct Opt {
    /// Name of the POSIX shared memory object to be used for communicating with the server
    /// instance. The name should be in the form of "/somename". If the leading slash is omitted,
    /// it'll be added implicitly.
    #[structopt(long, short)]
    shm: String,
    /// Index of the queue allocated within the shared memory to be used for communicating with the
    /// server. Please make sure that this index does not exceed the number of queues the server
    /// provides. The index is zero-based, which means that if there are N queues, the highest index
    /// is N-1.
    #[structopt(long, short)]
    queue: usize,
    /// The queues size in bytes.
    #[structopt(long, short = "n", default_value = "1024")]
    queue_size: usize,
    /// Cryptographic operation to be carried out.
    #[structopt(subcommand)]
    op: Op,
}

arg_enum! {
#[derive(Debug)]
enum HashAlgo {
    Sha256,
    Sha384,
    Sha512,
}
}

#[derive(StructOpt, Debug)]
enum Op {
    /// Executes a cryptographic hash function
    Hash {
        #[structopt(long, short, possible_values = &HashAlgo::variants(), case_insensitive = true)]
        algo: HashAlgo,
    },
}

fn main() {
    let opt = Opt::from_args();
    println!("{:?}", opt);
}
