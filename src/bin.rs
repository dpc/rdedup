//! `rdedup` is a data deduplication engine and a backup software.
//!
//! `rdedup` is generally similar to existing software like
//!  duplicacy, restic, attic, duplicity, zbackup, etc.
//!
//! `rdedup` is written in Rust and provides both command line tool
//! and library API (`rdedup-lib`).
//!
//!  ## Features
//!
//!  * simple but solid cryptography:
//!    * libsodium based
//!    * public-key encryption mode (the only tool like that I'm aware of,
//!      and primary reason `rdedup` was created)
//!  * flat-file synchronization friendly (Dropbox/syncthing, rsync, rclone)
//!    * cloud backends are WIP
//!  * incremental, scalable garbage collection
//!  * variety of supported algorithms:
//!    * chunking: fastcdc, gear, bup
//!    * hashing: blake2b, sha256
//!    * compression: zstd, deflate, xz2, bzip2, none
//!    * encryption: curve25519, none
//!    * very easy to add new ones
//!    * check `rdedup init --help` output for up-to-date list
//!  * extreme performance and parallelism - see
//!    [Rust fearless concurrency in `rdedup`](https://dpc.pw/blog/2017/04/rusts-fearless-concurrency-in-rdedup/)
//!  * reliability focus (eg. `rdedup` is using `fsync` + `rename`
//!    to avoid data corruption even in case of a hardware crash)
//!  * built-in time/performance profiler
//!
//! ## Strong parts
//!
//! It's written in Rust. It's a modern language, that is actually really nice
//! to use.
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
//! ratio for workloads with many small, frequently changing files.
//!
//! Cloud storage integrations are missing. The architecture to support it is
//! mostly implemented, but the actual backends are not.
//!
//! ## Installation
//!
//! If you have `cargo` installed:
//!
//! ```norust
//! cargo install rdedup --vers '^2' # for 2.x stable version
//! cargo install rdedup --vers '^3' # for 3.x experimental, and unstable
//! version
//! ```
//!
//! If not, I highly recommend installing [rustup][rustup] (think `pip`, `npm`
//! but for Rust)
//!
//! If you're interested in running `rdedup` with maximum possible performance,
//! try:
//!
//! ```norust
//! RUSTFLAGS="-C target-cpu=native" cargo install rdedup --vers ...
//! ```
//!
//! [rustup]: https://www.rustup.rs/
//!
//! In case of troubles, check [rdedup building issues][building-issues] or
//! report a new one (sorry)!
//!
//! [building-issues]: http://bit.ly/2ypLPtJ
//!
//! ## Usage
//!
//! See `rdedup -h` for help.
//!
//! Rdedup always operates on a *repo*, that you provide as an argument
//! (eg. `--dir <DIR>`), or via environment variable (eg. `RDEDUP_DIR`).
//!
//! Supported commands:
//!
//! * `rdedup init` - create a new *repo*.
//!   * `rdedup init --help` for repository configuration options.
//! * `rdedup store <name>` - store data from standard input under a given
//!   *name*.
//! * `rdedup load <name>` - load data stored under given *name* and write it
//!   to standard output.
//! * `rdedup rm <name>` - remove the given *name*.
//! * `rdedup ls` - list all stored names.
//! * `rdedup gc` - remove any no longer reachable data.
//!
//!
//! In combination with [rdup][rdup] this can be used to store and restore your
//! backup like this:
//!
//! ```norust
//! rdup -x /dev/null "$HOME" | rdedup store home
//! rdedup load home | rdup-up "$HOME.restored"
//! ```
//!
//! `rdedup` is data agnostic, so formats like `tar`, `cpio` and other will
//! work,
//! but to get benefits of deduplication, archive format should not be
//! compressed
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

#[macro_use]
extern crate clap;
extern crate hex;
extern crate rdedup_lib as lib;
extern crate rpassword;
#[macro_use]
extern crate slog;
extern crate slog_async;
extern crate slog_term;
extern crate url;

use url::Url;
use std::error::Error;
use lib::Repo;
use lib::settings;
use hex::ToHex;
use slog::Drain;
use std::{env, io, process};

use std::str::FromStr;

// Url parse with `io::Result` shortcut
fn parse_url(s: &str) -> io::Result<Url> {
    Url::parse(s).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("URI parsing error : {}", e.description()),
        )
    })
}

#[derive(Clone)]
struct Options {
    url: Url,
    debug_level: u32,
    settings: settings::Repo,
}

impl Options {
    fn new(url: Url) -> Options {
        Options {
            url: url,
            debug_level: 0,
            settings: settings::Repo::new(),
        }
    }


    fn set_encryption(&mut self, s: &str) {
        let encryption = match s {
            "curve25519" => lib::settings::Encryption::Curve25519,
            "none" => lib::settings::Encryption::None,
            _ => {
                eprintln!("unsupported encryption: {}", s);
                process::exit(-1)
            }
        };

        self.settings
            .set_encryption(encryption)
            .expect("wrong encryption");
    }

    fn set_compression(&mut self, s: &str) {
        let compression = match s {
            #[cfg(feature = "with-deflate")]
            "deflate" => lib::settings::Compression::Deflate,
            #[cfg(feature = "with-xz2")]
            "xz2" => lib::settings::Compression::Xz2,
            #[cfg(feature = "with-zstd")]
            "zstd" => lib::settings::Compression::Zstd,
            #[cfg(feature = "with-bzip2")]
            "bzip2" => lib::settings::Compression::Bzip2,
            "none" => lib::settings::Compression::None,
            _ => {
                eprintln!("unsupported compression: {}", s);
                process::exit(-1)
            }
        };

        self.settings
            .set_compression(compression)
            .expect("wrong compression");
    }

    fn set_chunking(&mut self, s: &str, chunk_size: Option<u32>) {
        match s {
            "bup" => self.settings
                .use_bup_chunking(chunk_size)
                .expect("wrong chunking settings"),
            "gear" => self.settings
                .use_gear_chunking(chunk_size)
                .expect("wrong chunking settings"),
            "fastcdc" => self.settings
                .use_fastcdc_chunking(chunk_size)
                .expect("wrong chunking settings"),
            _ => {
                eprintln!("unsupported encryption: {}", s);
                process::exit(-1);
            }
        };
    }

    fn set_hashing(&mut self, s: &str) {
        match s {
            "sha256" => self.settings
                .set_hashing(lib::settings::Hashing::Sha256)
                .expect("wrong hashing settings"),
            "blake2b" => self.settings
                .set_hashing(lib::settings::Hashing::Blake2b)
                .expect("wrong hashing settings"),
            _ => {
                eprintln!("unsupported hashing: {}", s);
                process::exit(-1);
            }
        };
    }

    fn set_nesting(&mut self, level: u8) {
        self.settings.set_nesting(level).expect("invalid nesting");
    }
}


mod util;
use util::{read_new_passphrase, read_passphrase};

#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
fn validate_chunk_size(s: String) -> Result<(), String> {
    util::parse_size(&s)
        .map(|_| ())
        .ok_or_else(|| "Can't parse a human readable byte-size value".into())
}

#[cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
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

fn create_logger(verbosity: u32, timing_verbosity: u32) -> slog::Logger {
    match (verbosity, timing_verbosity) {
        (0, 0) => slog::Logger::root(slog::Discard, o!()),
        (v, tv) => {
            let v = match v {
                0 => slog::Level::Warning,
                1 => slog::Level::Info,
                2 => slog::Level::Debug,
                _ => slog::Level::Trace,
            };
            let tv = match tv {
                0 => slog::Level::Warning,
                1 => slog::Level::Info,
                2 => slog::Level::Debug,
                _ => slog::Level::Trace,
            };
            let drain = slog_term::term_full();
            if verbosity > 4 {
                // at level 4, use synchronous logger so not to loose any
                // logging messages
                let drain = std::sync::Mutex::new(drain);
                let drain =
                    slog::Filter::new(drain, move |record: &slog::Record| {
                        if record.tag() == "slog_perf" {
                            record.level() >= tv
                        } else {
                            record.level() >= v
                        }
                    });
                let log = slog::Logger::root(drain.fuse(), o!());
                info!(
                    log,
                    "Using synchronized logging, that we'll be slightly slower."
                );
                log
            } else {
                let drain = slog_async::Async::default(drain.fuse());
                let drain =
                    slog::Filter::new(drain, move |record: &slog::Record| {
                        if record.tag() == "slog_perf" {
                            record.level().is_at_least(tv)
                        } else {
                            record.level().is_at_least(v)
                        }
                    });
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
        (@arg REPO_DIR: -d --dir +takes_value "Path to rdedup repository. \
         Override `RDEDUP_DIR` environment variable.")
        (@arg REPO_URI : -u --repo +takes_value "Rdedup repository URI. \
         Override `RDEDUP_URI` environment variable.")
        (@arg VERBOSE: -v ... "Increase debugging level for general messages")
        (@arg VERBOSE_TIMINGS: -t ... "Increase debugging level for timings")
        (@subcommand init =>
         (about: "Create a new repository")
         (@arg PWHASH: --pwhash possible_values(&["strong", "interactive", "weak"])
          +takes_value "Set pwhash strength. Default: strong")
         (@arg CHUNKING: --chunking possible_values(&["bup", "gear", "fastcdc"])
          +takes_value "Set chunking scheme. Default: gear")
         (@arg CHUNK_SIZE: --("chunk-size") {validate_chunk_size}
          +takes_value "Set average chunk size")
         (@arg ENCRYPTION: --encryption possible_values(&["curve25519", "none"])
          +takes_value "Set encryption scheme. Default: curve25519")
         (@arg COMPRESSION : --compression possible_values(
                 &["deflate", "xz2", "zstd", "bzip2", "none"]
                 )
          +takes_value "Set compression scheme. Default: deflate")
         (@arg COMPRESSION_LEVEL : --("compression-level")
          +takes_value "Set compression level where negative numbers mean \
          \"faster\" and positive ones \"smaller\". Default: 0")
         (@arg NESTING: --nesting {validate_nesting}
          +takes_value "Set level of folder nesting. Default: 2")
         (@arg HASHING: --hashing possible_values(&["sha256", "blake2b"])
          +takes_value "Set hashing scheme. Default: blake2b")
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
         (@arg GRACE_TIME: --grace
          +takes_value "Set grace time. Default: 1 day")
        )
        (@subcommand verify =>
         (about: "Verify integrity of data stored in the repository")
         (@arg NAME: +required ... "Names to verify")
        )
        (@subcommand du =>
         (about: "Calculate disk usage of a give data stored in the repository")
         (@arg NAME: +required ... "Names to check")
        )

        ).setting(clap::AppSettings::SubcommandRequiredElseHelp)
        .get_matches();


    let url: Url = if let Some(loc) = matches.value_of_os("REPO_URI") {
        if matches.value_of_os("REPO_DIR").is_some() {
            eprintln!("Can't use both --dir or --repo at the same time");
            process::exit(-1);
        }

        let s = loc.to_os_string().into_string().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("URI not valid UTF-8 string"),
            )
        })?;
        parse_url(&s)?
    } else if let Some(dir) = matches.value_of_os("REPO_DIR") {
        Url::from_file_path(dir).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("URI parsing error: {}", dir.to_string_lossy()),
            )
        })?
    } else if let Some(loc) = env::var_os("RDEDUP_URI") {
        if env::var_os("RDEDUP_DIR").is_some() {
            eprintln!(
                "Can't use both RDEDUP_REPOSITORY and RDEDUP_DIR  at the same time"
            );
            process::exit(-1);
        }

        let s = loc.to_os_string().into_string().map_err(|_e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("URI not valid UTF-8 string"),
            )
        })?;
        parse_url(&s)?
    } else if let Some(dir) = env::var_os("RDEDUP_DIR") {
        Url::from_file_path(&dir).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("URI parsing error: {}", dir.to_string_lossy()),
            )
        })?
    } else {
        eprintln!("Repository location not specified");
        process::exit(-1);
    };

    let mut options = Options::new(url);

    let log = create_logger(
        matches.occurrences_of("VERBOSE") as u32,
        matches.occurrences_of("VERBOSE_TIMINGS") as u32,
    );

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
            if let Some(pwhash) = matches.value_of("PWHASH") {
                options.settings.set_pwhash(settings::PWHash::from(pwhash));
            }
            if let Some(compression) = matches.value_of("COMPRESSION") {
                options.set_compression(compression);
            }
            if let Some(compression_level) =
                matches.value_of("COMPRESSION_LEVEL")
            {
                options.settings.set_compression_level(
                    i32::from_str(compression_level).unwrap(),
                );
            }
            if let Some(nesting) = matches.value_of("NESTING") {
                options.set_nesting(u8::from_str(nesting).unwrap());
            }
            if let Some(hashing) = matches.value_of("HASHING") {
                options.set_hashing(hashing);
            }
            let _ = Repo::init(
                &options.url,
                &|| util::read_new_passphrase(),
                options.settings,
                log,
            )?;
        }
        ("store", Some(matches)) => {
            let name = matches.value_of("NAME").expect("name agument missing");
            let repo = Repo::open(&options.url, log)?;
            let enc = repo.unlock_encrypt(&|| util::read_passphrase())?;
            let stats = repo.write(name, &mut io::stdin(), &enc)?;
            println!("{} new chunks", stats.new_chunks);
            println!("{} new bytes", stats.new_bytes);
        }
        ("load", Some(matches)) => {
            let name = matches.value_of("NAME").expect("name agument missing");
            let repo = Repo::open(&options.url, log)?;
            let dec = repo.unlock_decrypt(&|| util::read_passphrase())?;
            repo.read(name, &mut io::stdout(), &dec)?;
        }
        ("change_passphrase", Some(_matches)) => {
            let mut repo = Repo::open(&options.url, log)?;
            repo.change_passphrase(
                &|| read_passphrase(),
                &|| read_new_passphrase(),
            )?;
        }
        ("remove", Some(matches)) => {
            let repo = Repo::open(&options.url, log)?;
            for name in matches.values_of("NAME").expect("names missing") {
                repo.rm(name)?;
            }
        }
        ("du", Some(matches)) => {
            let repo = Repo::open(&options.url, log)?;
            let dec = repo.unlock_decrypt(&|| read_passphrase())?;

            for name in matches.values_of("NAME").expect("names missing") {
                let result = repo.du(name, &dec)?;
                println!("{} chunks", result.chunks);
                println!("{} bytes", result.bytes);
            }
        }
        ("gc", Some(matches)) => {
            let grace_secs = if let Some(grace) = matches.value_of("GRACE_TIME")
            {
                u64::from_str(grace).unwrap()
            } else {
                60 * 60 * 24
            };
            let repo = Repo::open(&options.url, log)?;

            repo.gc(grace_secs)?;
        }
        ("list", Some(_matches)) => {
            let repo = Repo::open(&options.url, log)?;

            for name in try!(repo.list_names()) {
                println!("{}", name);
            }
        }
        ("verify", Some(matches)) => {
            let repo = Repo::open(&options.url, log)?;
            let dec = repo.unlock_decrypt(&|| read_passphrase())?;
            for name in matches.values_of("NAME").expect("values") {
                let results = repo.verify(name, &dec)?;
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
        eprintln!("Error: {}", e);
        process::exit(-1);
    }
}
