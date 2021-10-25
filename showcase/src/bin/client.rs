use anyhow::Result;
use std::io::{self, BufRead, Write};
use structopt::{clap::arg_enum, StructOpt};

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
    subcommand: Subcommand,
}

#[derive(StructOpt, Debug)]
enum Subcommand {
    /// Executes a cryptographic hash function
    Hash(HashSubcommand),
}

#[derive(StructOpt, Debug)]
struct HashSubcommand {
    /// The algorithm that shall be used
    #[structopt(long, short, possible_values = &HashAlgo::variants(), default_value="Sha256", case_insensitive = true)]
    algo: HashAlgo,
}

arg_enum! {
#[derive(Debug)]
enum HashAlgo {
    Sha256,
    Sha384,
    Sha512,
}
}

fn hash_subcommand(_opt: &HashSubcommand) -> Result<()> {
    let input = io::BufReader::new(io::stdin());
    let mut output = io::BufWriter::new(io::stdout());

    for line in input.lines() {
        output.write_all(line?.as_bytes())?;
        output.flush()?;
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let opt = Opt::from_args();
    match opt.subcommand {
        Subcommand::Hash(s) => hash_subcommand(&s),
    }
}
