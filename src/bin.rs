//! `rdedup` is the data deduplication engine and backup software
//!
//! `rdedup` is written in Rust and provides both command line tool
//! and library API (`rdedup-lib`).
//!
//! `rdedup` is generally similar to existing software like
//!  duplicacy, restic, attic, duplicity, zbackup, etc.
//!
//!  ## Features
//!
//!  * support for public-key encryption (the only tool like that I'm aware of,
//!    and primary reason `rdedup` was created)
//!  * flat-file synchronization friendly (Dropbox, syncthing) backend
//!    * cloud backends are WIP
//!  * garbage collection
//!  * variety of supported algorithms:
//!    * chunking: bup, gear
//!    * hashing: blake2b, sha256
//!    * compression: deflate, xz2, bzip2, zstd, none
//!    * encryption: curve25519, none
//!    * very easy to add new ones
//!    * check `rdedup init --help` output for up-to-date list
//!  * extreme performance and parallelism - see [Rust fearless
//!    concurrency in `rdedup`](https://dpc.pw/blog/2017/04/rusts-fearless-concurrency-in-rdedup/)
//!  * attention to reliability (eg. `rdedup` is using `fsync` + `rename`
//!    to avoid data corruption even in case of hardware crash)
//!
//! ## Strong parts
//!
//! It's written in Rust. It's a modern language, that is actually really nice to use.
//! Rust makes it easy to have a very robust and fast software.
//!
//! The author is a nice person, welcomes contributions, and helps users. Or at
//! least he's trying... :)
//!
//! ## Shortcomings and missing features:
//!
//! `rdedup` currently does not implement own backup/restore functionality (own
//! directory traversal), and because of that it's typically paired with `tar`
//! or `rdup` tools. Built-in directory traversal could improve deduplication
//! ratio for workloads with many small files.
//!
//! Garbage collection could be optimized and made more scalable.
//!
//! Cloud storage integrations are missing. The architecture to support it is
//! mostly implemented, but the actual backends are not.
//!
//! ## Installation
//!
//! If you have `cargo` installed:
//!
//! ```
//! cargo install rdedup
//! ```
//!
//! If not, I highly recommend installing [rustup][rustup] (think `pip`, `npm` but for Rust)
//!
//! [rustup]: https://www.rustup.rs/
//!
//! In case of troubles, check
//! [rdedup building issues](https://github.com/dpc/rdedup/issues?q=is%3Aissue+is%3Aclosed+label%3Abuilding)
//! or report a new one (sorry)!
//!
//! ## Usage
//!
//! See `rdedup -h` for help.
//!
//! Supported commands:
//!
//! * `rdedup init` - create a *repo* directory with keypair used for encryption.
//! * `rdedup ls` - list all stored names.
//! * `rdedup store <name>` - store data read from standard input under given *name*.
//! * `rdedup load <name>` - load data stored under given *name* and write it on standard output
//! * `rdedup rm <name>` - remove the given *name*. This by itself does not remove the data.
//! * `rdedup gc` - remove any no longer reachable data
//!
//! Check `rdedup init --help` for repository configuration options.
//!
//! In combination with [rdup][rdup] this can be used to store and restore your backup like this:
//!
//! ```
//! rdup -x /dev/null "$HOME" | rdedup store home
//! rdedup load home | rdup-up "$HOME.restored"
//! ```
//!
//! `rdedup` is data agnostic, so formats like `tar`, `cpio` and other will work,
//! but to get benefits of deduplication, archive format should not be compressed
//! or encrypted already.
//!
//! # `RDEDUP_PASSPHRASE` environment variable
//!
//! While it's not advised, if `RDEDUP_PASSPHRASE` is defined, it will be used
//! instead of interactively asking user for password.
//!
//! [bup]: https://github.com/bup/bup/
//! [rdup]: https://github.com/miekg/rdup
//! [syncthing]: https://syncthing.net
//! [zbackup]: http://zbackup.org/
//! [zbackup-issue]: https://github.com/zbackup/zbackup/issues/109
//! [ddar]: https://github.com/basak/ddar/
//! [ddar-issue]: https://github.com/basak/ddar/issues/10

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
use std::str::FromStr;

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
            "xz2" => lib::settings::Compression::Xz2,
            "zstd" => lib::settings::Compression::Zstd,
            "bzip2" => lib::settings::Compression::Bzip2,
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
            "gear" => {
                self.settings
                    .use_gear_chunking(chunk_size)
                    .expect("wrong chunking settings")
            }
            _ => {
                printerrln!("unsupported encryption: {}", s);
                process::exit(-1);
            }
        };
    }

    fn set_hashing(&mut self, s: &str) {
        match s {
            "sha256" => {
                self.settings
                    .set_hashing(lib::settings::Hashing::Sha256)
                    .expect("wrong hashing settings")
            }
            "blake2b" => {
                self.settings
                    .set_hashing(lib::settings::Hashing::Blake2b)
                    .expect("wrong hashing settings")
            }
            _ => {
                printerrln!("unsupported hashing: {}", s);
                process::exit(-1);
            }
        };
    }

    fn set_nesting(&mut self, level: u8) {
        self.settings.set_nesting(level).expect("invalid nesting");
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

fn validate_nesting(s: String) -> Result<(), String> {
    let msg = "nesting must be an integer between 0 and 31";
    let levels = match u8::from_str(s.as_str()) {
        Ok(l) => l,
        Err(_) => return Err(msg.into()),
    };
    if levels > 31 {
        return Err(msg.into());
    }
    Ok(())
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
         (@arg CHUNKING: --chunking possible_values(&["bup", "gear"]) +takes_value "Set chunking scheme. Default: gear")
         (@arg CHUNK_SIZE: --("chunk-size") {validate_chunk_size} +takes_value "Set average chunk size")
         (@arg ENCRYPTION: --encryption  possible_values(&["curve25519", "none"]) +takes_value "Set encryption scheme. Default: curve25519")
         (@arg COMPRESSION : --compression possible_values(&["deflate", "xz2", "bzip2", "zstd", "none"]) +takes_value "Set compression scheme. Default: deflate")
         (@arg COMPRESSION_LEVEL : --("compression-level") +takes_value "Set compression level where negative numbers mean \"faster\" and positive ones \"smaller\". Default: 0")
         (@arg NESTING: --nesting {validate_nesting} +takes_value "Set level of folder nesting. Default: 2")
         (@arg HASHING: --hashing possible_values(&["sha256", "blake2b"]) +takes_value "Set hashing scheme. Default: blake2b")
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
            options.set_chunking(
                matches.value_of("CHUNKING").unwrap_or("gear"),
                matches
                    .value_of("CHUNK_SIZE")
                    .map(|s| {
                        util::parse_size(s).expect("Invalid chunk size option")
                    })
                    .map(|u| u.trailing_zeros()),
            );
            if let Some(encryption) = matches.value_of("ENCRYPTION") {
                options.set_encryption(encryption);
            }
            if let Some(compression) = matches.value_of("COMPRESSION") {
                options.set_compression(compression);
            }
            if let Some(compression_level) =
                matches.value_of("COMPRESSION_LEVEL") {
                options.settings.set_compression_level(i32::from_str(compression_level).unwrap());
            }
            if let Some(nesting) = matches.value_of("NESTING") {
                options.set_nesting(u8::from_str(nesting).unwrap());
            }
            if let Some(hashing) = matches.value_of("HASHING") {
                options.set_hashing(hashing);
            }
            let _ = Repo::init(
                &options.dir,
                &|| util::read_new_passphrase(),
                options.settings,
                log,
            )?;
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
            repo.change_passphrase(
                &|| read_passphrase(),
                &|| read_new_passphrase(),
            )?;
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
