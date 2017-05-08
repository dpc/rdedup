extern crate log;
extern crate rustc_serialize as serialize;
#[macro_use]
extern crate clap;
extern crate rdedup_lib as lib;
extern crate rpassword;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate slog_async;


use lib::Repo;
use lib::settings;
use serialize::hex::ToHex;
use slog::Drain;
use std::{io, process, env};

use std::path::PathBuf;

macro_rules! printerrln {
    ($($arg:tt)*) => ({
        use std::io::prelude::*;
        if let Err(e) = writeln!(&mut ::std::io::stderr(), "{}",
            format_args!($($arg)*)) {
            panic!(concat!(
                    "Failed to write to stderr.\n",
                    "Original error output: {}\n",
                    "Secondary error writing to stderr: {}"),
                    format_args!($($arg)*), e);
        }
    })
}

macro_rules! printerr {
    ($($arg:tt)*) => ({
        use std::io::prelude::*;
        if let Err(e) = write!(&mut ::std::io::stderr(), "{}",
            format_args!($($arg)*)) {
            panic!(concat!(
                    "Failed to write to stderr.\n",
                    "Original error output: {}\n",
                    "Secondary error writing to stderr: {}"),
                    format_args!($($arg)*), e);
        }
    })
}



// #[derive(Copy, Clone)]
// enum Command {
// Help,
// Store,
// Load,
// Init,
// DU,
// GC,
// Remove,
// ChangePassphrase,
// List,
// Verify,
// }
//
// impl FromStr for Command {
// type Err = ();
// fn from_str(src: &str) -> Result<Command, ()> {
// match src {
// "help" => Ok(Command::Help),
// "store" => Ok(Command::Store),
// "load" => Ok(Command::Load),
// "init" => Ok(Command::Init),
// "rm" | "delete" | "del" => Ok(Command::Remove),
// "ls" | "list" => Ok(Command::List),
// "du" => Ok(Command::DU),
// "gc" => Ok(Command::GC),
// "chpasswd" |
// "chpassphrase" |
// "changepassphrase" => Ok(Command::ChangePassphrase),
// "verify" => Ok(Command::Verify),
// _ => Err(()),
// }
// }
// }
//
#[derive(Clone)]
struct Options {
    dir: PathBuf,
    debug_level: u32,
    settings: settings::Repo,
}

impl Options {
    fn new(path: PathBuf) -> Options {
        Options {
            dir: path,
            debug_level: 0,
            settings: settings::Repo::new(),
        }
    }


    fn set_encryption(&mut self, s: &str) {
        let encryption = match s {
            "curve25519" => lib::settings::Encryption::Curve25519,
            "none" => lib::settings::Encryption::None,
            _ => {
                printerrln!("unsupported encryption: {}", s);
                process::exit(-1);
            }
        };

        self.settings
            .set_encryption(encryption)
            .expect("wrong encryption");
    }

    fn set_compression(&mut self, s: &str) {
        let compression = match s {
            "deflate" => lib::settings::Compression::Deflate,
            "none" => lib::settings::Compression::None,
            _ => {
                printerrln!("unsupported compression: {}", s);
                process::exit(-1);
            }
        };

        self.settings
            .set_compression(compression)
            .expect("wrong compression");
    }

    fn set_chunking(&mut self, s: &str, chunk_size: Option<u32>) {
        match s {
            "bup" => {
                self.settings
                    .use_bup_chunking(chunk_size)
                    .expect("wrong chunking settings")
            }
            _ => {
                printerrln!("unsupported encryption: {}", s);
                process::exit(-1);
            }
        };
    }
}


mod util;
use util::{read_passphrase, read_new_passphrase};

fn validate_chunk_size(s: String) -> Result<(), String> {
    if let Some(_) = util::parse_size(&s) {
        Ok(())
    } else {
        Err("Can't parse a human readable byte-size value".into())
    }

}

fn create_logger(verbosity: u32) -> slog::Logger {
    match verbosity {
        0 => slog::Logger::root(slog::Discard, o!()),
        dl => {
            let level = match dl {
                0 => unreachable!(),
                1 => slog::Level::Info,
                2 => slog::Level::Debug,
                _ => slog::Level::Trace,
            };
            let drain = slog_term::term_full();
            if dl > 4 {
                // at level 4, use synchronous logger so not to loose any
                // logging messages
                let drain = std::sync::Mutex::new(drain);
                let drain = slog::LevelFilter::new(drain, level);
                slog::Logger::root(drain.fuse(), o!())
            } else {
                let drain = slog_async::Async::default(drain.fuse());
                let drain = slog::LevelFilter::new(drain, level);
                slog::Logger::root(drain.fuse(), o!())
            }
        }
    }
}

fn run() -> io::Result<()> {
    let matches = clap_app!(
        rdedup =>
        (version: env!("CARGO_PKG_VERSION"))
        (author: "Dawid Ciężarkiewicz <dpc@dpc.pw>")
        (about: "Data deduplication toolkit")
        (@arg REPO_DIR: -d --dir +takes_value "Path to rdedup repository. Override `RDEDUP_DIR` environment variable.")
        (@arg verbose: -v ... "Increase debugging level")
        (@subcommand init =>
         (about: "Create a new repository")
         (@arg CHUNKING: --chunking possible_values(&["bup"]) +takes_value "Set chunking scheme. Default: bup")
         (@arg CHUNK_SIZE: --("chunk-size") {validate_chunk_size} +takes_value "Set average chunk size"
          )
         (@arg ENCRYPTION: --encryption  possible_values(&["curve25519", "none"]) +takes_value "Set encryption scheme. Default: curve25519")
         (@arg COMPRESSION : --compression possible_values(&["deflate", "none"]) +takes_value "Set compression scheme. Default: deflate")
        )
        (@subcommand store =>
         (about: "Store data from repository")
         (@arg NAME: +required "Name to store")
        )
        (@subcommand load =>
         (about: "Load data from repository")
         (@arg NAME:  +required "Name to load")
        )
        (@subcommand list =>
         (visible_alias: "ls")
         (about: "List names stored in the repository")
        )
        (@subcommand change_passphrase =>
         (visible_alias: "chpasswd")
         (about: "Change the passphrase protecting the encryption key (if any)")
        )
        (@subcommand remove =>
         (visible_alias: "rm")
         (about: "Remove name(s) stored in the repository")
         (@arg NAME: +required ... "Names to remove")
        )
        (@subcommand gc =>
         (about: "Garbage collect unreferenced chunks")
        )
        (@subcommand verify =>
         (about: "Verify integrity of data stored in the repository")
         (@arg NAME: +required ... "Names to verify")
        )
        (@subcommand du =>
         (about: "Calculate disk usage of a give data stored in the repository")
         (@arg NAME: +required ... "Names to check")
        )

        )
        .setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .get_matches();


    let dir = if let Some(dir) = matches.value_of_os("REPO_DIR") {
        PathBuf::from(dir)
    } else {
        if let Some(dir) = env::var_os("RDEDUP_DIR") {
            PathBuf::from(dir)
        } else {
            printerrln!("Repository dir path not specified");
            process::exit(-1);
        }
    };

    let mut options = Options::new(dir);

    let log = create_logger(matches.occurrences_of("verbose") as u32);

    match matches.subcommand() {
        ("init", Some(matches)) => {
            if let Some(chunking) = matches.value_of("CHUNKING") {
                options.set_chunking(chunking,
                                     matches
                                         .value_of("CHUNK_SIZE")
                                         .map(|s| {
                                                       util::parse_size(s).expect("Invalid chunk size option")
                                                   })
                                         .map(|u| u.trailing_zeros()));
            }
            if let Some(encryption) = matches.value_of("ENCRYPTION") {
                options.set_encryption(encryption);
            }
            if let Some(compression) = matches.value_of("COMPRESSION") {
                options.set_compression(compression);
            }
            let _ = Repo::init(&options.dir,
                               &|| util::read_new_passphrase(),
                               options.settings,
                               log)?;
        }
        ("store", Some(matches)) => {
            let name = matches.value_of("NAME").expect("name agument missing");
            let repo = Repo::open(&options.dir, log)?;
            let enc = repo.unlock_encrypt(&|| util::read_passphrase())?;
            let stats = repo.write(&name, &mut io::stdin(), &enc)?;
            println!("{} new chunks", stats.new_chunks);
            println!("{} new bytes", stats.new_bytes);
        }
        ("load", Some(matches)) => {
            let name = matches.value_of("NAME").expect("name agument missing");
            let repo = Repo::open(&options.dir, log)?;
            let dec = repo.unlock_decrypt(&|| util::read_passphrase())?;
            repo.read(&name, &mut io::stdout(), &dec)?;
        }
        ("change_passphrase", Some(_matches)) => {
            let mut repo = Repo::open(&options.dir, log)?;
            repo.change_passphrase(&|| read_passphrase(),
                                   &|| read_new_passphrase())?;
        }
        ("remove", Some(matches)) => {
            let repo = Repo::open(&options.dir, log)?;
            for name in matches.values_of("NAME").expect("names missing") {
                repo.rm(name)?;
            }
        }
        ("du", Some(matches)) => {
            let repo = Repo::open(&options.dir, log)?;
            let dec = repo.unlock_decrypt(&|| read_passphrase())?;

            for name in matches.values_of("NAME").expect("names missing") {
                let result = repo.du(&name, &dec)?;
                println!("{} chunks", result.chunks);
                println!("{} bytes", result.bytes);
            }
        }
        ("gc", Some(_matches)) => {
            let repo = Repo::open(&options.dir, log)?;

            let result = repo.gc()?;
            println!("Removed {} chunks", result.chunks);
            println!("Freed {} bytes", result.bytes);
        }
        ("list", Some(_matches)) => {
            let repo = Repo::open(&options.dir, log)?;

            for name in try!(repo.list_names()) {
                println!("{}", name);
            }
        }
        ("verify", Some(matches)) => {
            let repo = Repo::open(&options.dir, log)?;
            let dec = repo.unlock_decrypt(&|| read_passphrase())?;
            for name in matches.values_of("NAME").expect("values") {
                let results = repo.verify(&name, &dec)?;
                println!("scanned {} chunk(s)", results.scanned);
                println!("found {} corrupted chunk(s)", results.errors.len());
                for err in results.errors {
                    println!("chunk {} - {}", &err.0.to_hex(), err.1);
                }
            }
        }
        _ => panic!("Unrecognized subcommand"),
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        printerrln!("Error: {}", e);
        process::exit(-1);
    }
}
