//! `rdedup` is a data deduplication engine and a backup software.
//!
//! `rdedup` is generally similar to existing software like
//!  `duplicacy`, `restic`, `attic`, `duplicity`, `zbackup`, etc.
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
//!  * immutable data-conflict-free data store
//!  * cloud backends are WIP
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
//! to use. Rust makes it easy to have a very robust and fast software.
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
//! cargo install rdedup
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

use std::str::FromStr;
use std::{env, io, path::PathBuf, process};

use clap::Clap;
use slog::{info, o, Drain};
use url::Url;

use rdedup_lib as lib;

use crate::lib::settings;
use crate::lib::Repo;

// Url parse with `io::Result` shortcut
fn parse_url(s: &str) -> io::Result<Url> {
    Url::parse(s).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("URI parsing error : {}", e.to_string()),
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
            url,
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
            "bup" => self
                .settings
                .use_bup_chunking(chunk_size)
                .expect("wrong chunking settings"),
            "gear" => self
                .settings
                .use_gear_chunking(chunk_size)
                .expect("wrong chunking settings"),
            "fastcdc" => self
                .settings
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
            "sha256" => self
                .settings
                .set_hashing(lib::settings::Hashing::Sha256)
                .expect("wrong hashing settings"),
            "blake2b" => self
                .settings
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
use crate::util::{read_new_passphrase, read_passphrase};

fn validate_chunk_size(s: &str) -> Result<(), String> {
    util::parse_size(&s)
        .map(|_| ())
        .ok_or_else(|| "Can't parse a human readable byte-size value".into())
}

fn validate_nesting(s: &str) -> Result<(), String> {
    let msg = "nesting must be an integer between 0 and 31";
    let levels = match u8::from_str(s) {
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
                let drain = slog::Filter::new(
                    drain,
                    move |record: &slog::Record<'_>| {
                        if record.tag() == "slog_perf" {
                            record.level() >= tv
                        } else {
                            record.level() >= v
                        }
                    },
                );
                let log = slog::Logger::root(drain.fuse(), o!());
                info!(
                    log,
                    "Using synchronized logging, that we'll be slightly slower."
                );
                log
            } else {
                let drain = slog_async::Async::default(drain.fuse());
                let drain = slog::Filter::new(
                    drain,
                    move |record: &slog::Record<'_>| {
                        if record.tag() == "slog_perf" {
                            record.level().is_at_least(tv)
                        } else {
                            record.level().is_at_least(v)
                        }
                    },
                );
                slog::Logger::root(drain.fuse(), o!())
            }
        }
    }
}

#[derive(Debug, Clap)]
#[clap(author, about = "Data deduplication toolkit")]
struct CliOpts {
    #[clap(name = "dir", short = "d", long, value_name = "PATH")]
    /// Path to rdedup repository. Override `RDEDUP_DIR` environment variable
    repo_dir: Option<std::ffi::OsString>,

    #[clap(
        short = "u",
        long = "repo",
        conflicts_with = "dir",
        value_name = "URI"
    )]
    /// Rdedup repository URI. Override the `RDEDUP_URI` environment variable
    repo_uri: Option<std::ffi::OsString>,

    #[clap(short = "v", parse(from_occurrences))]
    /// Increase debugging level for general messages
    verbose: u8,

    #[clap(short = "t", parse(from_occurrences))]
    /// Increase debugging level for timings
    verbose_timings: u8,

    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Clap)]
#[clap(setting = clap::AppSettings::DeriveDisplayOrder)]
enum Command {
    #[clap(setting = clap::AppSettings::DeriveDisplayOrder)]
    /// Create a new repository
    Init {
        #[clap(
            long,
            possible_values = &["bup", "gear", "fastcdc"],
            default_value = "fastcdc",
            value_name = "SCHEME",
        )]
        /// Set chunking scheme
        chunking: String,

        #[clap(
            long,
            validator = validate_chunk_size,
            default_value = "128K",
            value_name = "N",
        )]
        /// Set average chunk size
        chunk_size: String,

        #[clap(
            long,
            possible_values = &["deflate", "xz2", "zstd", "bzip2", "none"],
            default_value = "zstd",
            value_name = "SCHEME",
        )]
        /// Set compression scheme
        compression: String,

        #[clap(long, default_value = "0", value_name = "N")]
        /// Set compression level where negative numbers mean "faster" and positive ones "smaller"
        compression_level: i32,

        #[clap(
            long,
            possible_values = &["curve25519", "none"],
            default_value = "curve25519",
            value_name = "SCHEME",
        )]
        /// Set encryptiopn scheme
        encryption: String,

        #[clap(
            long,
            possible_values = &["sha256", "blake2b"],
            default_value = "blake2b",
            value_name = "SCHEME",
        )]
        /// Set hashing scheme
        hashing: String,

        #[clap(long, validator = validate_nesting, default_value = "2", value_name = "N")]
        /// Set level of folder nesting
        nesting: u8,

        #[clap(
            long,
            possible_values = &["strong", "interactive", "weak"],
            default_value = "strong",
            value_name = "STRENGTH",
        )]
        /// Set pwhash strength
        pwhash: String,
    },

    /// Store data to repository
    Store {
        #[clap(name = "NAME")]
        /// Name to store to
        name: String,
    },

    /// Load data from repository
    Load {
        #[clap(name = "NAME")]
        /// Name to load from
        name: String,
    },

    #[clap(visible_alias = "ls")]
    /// List names stored in the repository
    List,

    #[clap(visible_alias = "rm")]
    /// Remove names stored in the repository
    Remove {
        #[clap(name = "NAME", required = true)]
        /// Names to remove
        names: Vec<String>,
    },

    #[clap(name = "change_passphrase", visible_alias = "chpasswd")]
    /// Change the passphrase protecting the encryption key (if any)
    ChangePassphrase,

    /// Calculate disk usage due to the data stored for a set of names
    Du {
        #[clap(name = "NAME", required = true)]
        /// Names to check
        names: Vec<String>,
    },

    /// Garbage collect unreferenced chunks
    Gc {
        #[clap(
            long = "grace",
            default_value = "86400",
            value_name = "SECONDS"
        )]
        /// Set grace time in seconds
        grace_time: u64,
    },

    /// Verify integrity of data stored in the repository
    Verify {
        #[clap(name = "NAME", required = true)]
        /// Names to verify
        names: Vec<String>,
    },
}

fn run() -> io::Result<()> {
    let cli_opts = CliOpts::parse();

    let url: Url = if let Some(loc) = cli_opts.repo_uri {
        let s = loc.into_string().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "URI not valid UTF-8 string".to_string(),
            )
        })?;
        parse_url(&s)?
    } else if let Some(dir) = cli_opts.repo_dir {
        Url::from_file_path(PathBuf::from(&dir).canonicalize()?).map_err(
            |_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("URI parsing error: {}", dir.to_string_lossy()),
                )
            },
        )?
    } else if let Some(loc) = env::var_os("RDEDUP_URI") {
        if env::var_os("RDEDUP_DIR").is_some() {
            eprintln!(
                "Can't use both RDEDUP_REPOSITORY and RDEDUP_DIR at the same time"
            );
            process::exit(-1);
        }

        let s = loc.into_string().map_err(|_e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "URI not valid UTF-8 string".to_string(),
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

    let log =
        create_logger(cli_opts.verbose as u32, cli_opts.verbose_timings as u32);

    match cli_opts.command {
        Command::Init {
            chunking,
            chunk_size,
            encryption,
            pwhash,
            compression,
            compression_level,
            nesting,
            hashing,
        } => {
            let chunk_size = Some(
                util::parse_size(&chunk_size)
                    .expect("Invalid chunk size option")
                    .trailing_zeros(),
            );
            options.set_chunking(&chunking, chunk_size);
            options.set_encryption(&encryption);
            options
                .settings
                .set_pwhash(settings::PWHash::from(pwhash.as_str()));
            options.set_compression(&compression);
            options.settings.set_compression_level(compression_level);
            options.set_nesting(nesting);
            options.set_hashing(&hashing);
            let _ = Repo::init(
                &options.url,
                &|| util::read_new_passphrase(),
                options.settings,
                log,
            )?;
        }
        Command::Store { name } => {
            let repo = Repo::open(&options.url, log)?;
            let enc = repo.unlock_encrypt(&|| util::read_passphrase())?;
            let stats = repo.write(&name, &mut io::stdin(), &enc)?;
            println!("{} new chunks", stats.new_chunks);
            println!("{} new bytes", stats.new_bytes);
        }
        Command::Load { name } => {
            let repo = Repo::open(&options.url, log)?;
            let dec = repo.unlock_decrypt(&|| util::read_passphrase())?;
            repo.read(&name, &mut io::stdout(), &dec)?;
        }
        Command::ChangePassphrase => {
            let mut repo = Repo::open(&options.url, log)?;
            repo.change_passphrase(&|| read_passphrase(), &|| {
                read_new_passphrase()
            })?;
        }
        Command::Remove { names } => {
            let repo = Repo::open(&options.url, log)?;
            for name in names {
                repo.rm(&name)?;
            }
        }
        Command::Du { names } => {
            let repo = Repo::open(&options.url, log)?;
            let dec = repo.unlock_decrypt(&|| read_passphrase())?;

            for name in names {
                let result = repo.du(&name, &dec)?;
                println!("{} chunks", result.chunks);
                println!("{} bytes", result.bytes);
            }
        }
        Command::Gc { grace_time } => {
            let repo = Repo::open(&options.url, log)?;

            repo.gc(grace_time)?;
        }
        Command::List => {
            let repo = Repo::open(&options.url, log)?;

            for name in repo.list_names()? {
                println!("{}", name);
            }
        }
        Command::Verify { names } => {
            let repo = Repo::open(&options.url, log)?;
            let dec = repo.unlock_decrypt(&|| read_passphrase())?;
            for name in names {
                let results = repo.verify(&name, &dec)?;
                println!("scanned {} chunk(s)", results.scanned);
                println!("found {} corrupted chunk(s)", results.errors.len());
                for err in results.errors {
                    println!("chunk {} - {}", hex::encode(&err.0), err.1);
                }
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(-1);
    }
}
