extern crate log;
extern crate rustc_serialize as serialize;
extern crate argparse;
extern crate env_logger;
extern crate rdedup_lib as lib;
extern crate rpassword;
#[macro_use]
extern crate slog;
extern crate slog_term;
extern crate slog_async;


use lib::Repo;
use lib::config::ChunkingAlgorithm;
use serialize::hex::ToHex;
use slog::Drain;
use std::{io, process, env};
use std::path;
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


fn read_passphrase(o: &Options) -> String {
    printerrln!("Warning: Use `--add-newline` option if you generated repo \
                 with rdedup version <= 0.2");
    printerr!("Enter passphrase to unlock: ");
    if o.add_newline {
        rpassword::read_password().unwrap() + "\n"
    } else {
        rpassword::read_password().unwrap()
    }
}

fn read_new_passphrase() -> String {
    loop {
        printerr!("Enter new passphrase: ");
        let p1 = rpassword::read_password().unwrap();
        printerr!("Enter new passphrase again: ");
        let p2 = rpassword::read_password().unwrap();
        if p1 == p2 {
            return p1;
        }
        printerrln!("\nPassphrases don't match, try again.");
    }
}
/// `parse_size` is a utility function to take a string representing a size
/// in bytes like 192k or 192K and turns it into a u64. Currently this parses up
/// to a Terabyte value but additional values are supported by simply expanding
/// the units array.
fn parse_size(input: &str) -> Option<u64> {
    let input = input.to_uppercase();

    if input.contains('.') {
        return None;
    }

    let units = ["K", "M", "G", "T", "P", "E"];
    let unit = input.matches(char::is_alphabetic).next();
    let str_size: String = input.matches(char::is_numeric).collect();

    let mut size = if !str_size.is_empty() {
        match u64::from_str(str_size.as_str()) {
            Ok(s) => s,
            Err(_) => return None,
        }
    } else {
        return None;
    };

    if let Some(unit) = unit {
        if let Some(idx) = units.iter().position(|&u| u == unit) {
            let modifier: u64 = 1024u64.pow(idx as u32 + 1);
            size *= modifier;
        } else {
            return None;
        }
    }
    Some(size)
}

#[test]
fn test_parse_size() {
    // tuples that are str, expected Option<u64>
    let tests = [("192K", Some(192 * 1024)),
                 ("1M", Some(1024u64.pow(2))),
                 ("Hello", None),
                 ("12345.6789", None),
                 ("1024B", None),
                 ("1024A", None),
                 ("1t", Some(1024u64.pow(4))),
                 ("1E", Some(1024u64.pow(6)))];

    for test in &tests {
        let result = parse_size(test.0);
        if result != test.1 {
            panic!("expected {:?}, got {:?}", test.1, result);
        }
    }
}

#[derive(Copy, Clone)]
enum Command {
    Help,
    Store,
    Load,
    Init,
    DU,
    GC,
    Remove,
    ChangePassphrase,
    List,
    Verify,
}

impl FromStr for Command {
    type Err = ();
    fn from_str(src: &str) -> Result<Command, ()> {
        match src {
            "help" => Ok(Command::Help),
            "store" => Ok(Command::Store),
            "load" => Ok(Command::Load),
            "init" => Ok(Command::Init),
            "rm" | "delete" | "del" => Ok(Command::Remove),
            "ls" | "list" => Ok(Command::List),
            "du" => Ok(Command::DU),
            "gc" => Ok(Command::GC),
            "chpasswd" |
            "chpassphrase" |
            "changepassphrase" => Ok(Command::ChangePassphrase),
            "verify" => Ok(Command::Verify),
            _ => Err(()),
        }
    }
}

struct Options {
    dir_str: String,
    args: Vec<String>,
    command: Command,
    add_newline: bool,
    usage: String,
    chunk_size: String,
    chunking: String,
    debug_level: u32,
}

impl Options {
    fn new() -> Self {
        let mut dir_str: String = env::var("RDEDUP_DIR").unwrap_or_default();
        println!("{}", dir_str);
        let mut args = vec![];
        let mut command = Command::Help;
        let mut usage = vec![];
        let mut add_newline = false;
        let mut chunk_size: String = "128k".to_owned();
        let mut chunking: String = "bup".to_owned();
        let mut debug_level = 0u32;

        {
            let mut ap = argparse::ArgumentParser::new();
            use argparse::*;
            ap.set_description("rdedup");
            ap.refer(&mut dir_str)
                .add_option(&["-d", "--dir"], Store, "destination dir");
            ap.refer(&mut add_newline)
                .add_option(&["-n", "--add-newline"],
                            StoreTrue,
                            "add newline to the password");
            ap.refer(&mut chunking)
                .add_option(&["--chunking"],
                            Store,
                            "chunking algorithm (bup - default)");
            ap.refer(&mut chunk_size)
                .add_option(&["--chunk-size"],
                            Store,
                            "chunking size, default: 128k");
            ap.refer(&mut debug_level)
                .add_option(&["-D", "--debug"],
                            IncrBy(1),
                            "increase debug level");
            ap.refer(&mut command)
                .add_argument("command", Store, r#"command to run"#);
            ap.refer(&mut args)
                .add_argument("arguments", List, r#"arguments for command"#);

            ap.add_option(&["-V", "--version"],
                          Print(env!("CARGO_PKG_VERSION").to_string()),
                          "show version");

            ap.stop_on_first_argument(true);
            ap.parse_args_or_exit();

            ap.print_help("rdedup", &mut usage).unwrap();
        }
        println!("{}", dir_str);

        Options {
            dir_str: dir_str,
            command: command,
            args: args,
            add_newline: add_newline,
            usage: String::from_utf8_lossy(&usage).to_string(),
            chunk_size: chunk_size,
            chunking: chunking,
            debug_level: debug_level,
        }
    }

    fn check_no_arguments(&self) {
        if !self.args.is_empty() {
            printerrln!("Unnecessary argument: {}", self.args[0]);
            process::exit(-1);
        }
    }

    fn check_command(&self) -> Command {
        self.command
    }

    fn check_name(&self) -> String {
        if self.args.len() != 1 {
            printerrln!("Name required");
            process::exit(-1);
        }
        self.args[0].clone()
    }

    fn check_dir(&self) -> path::PathBuf {
        if self.dir_str.is_empty() {
            printerrln!("No destination directory specified. Use `--dir` or \
                         `$RDEDUP_DIR`");
            process::exit(-1);
        }
        path::Path::new(&self.dir_str).to_owned()
    }
    fn check_chunking(&self, size: u64) -> ChunkingAlgorithm {
        match self.chunking.to_lowercase().as_str() {
            "bup" => {
                // Validate that the size provided works for the bup algorithm
                if !size.is_power_of_two() {
                    printerrln!("invalid chunk size provided for bup, must \
                                 be power of 2");
                    process::exit(-1);
                }
                let algo = ChunkingAlgorithm::Bup {
                    chunk_bits: size.trailing_zeros(),
                };
                if !algo.valid() {
                    printerrln!("invalid chunk size, value must be at least \
                                 1K and no more then 1G");
                    process::exit(-1);
                }
                algo
            }
            _ => {
                printerrln!("chunking algorithm {:} not supported",
                            self.chunking);
                process::exit(-1);
            }
        }
    }
    fn check_chunk_size(&self) -> u64 {
        match parse_size(&self.chunk_size) {
            Some(s) => s,
            None => {
                printerrln!("invalid chunk size provided, must be a number \
                             with a size suffix");
                process::exit(-1);
            }
        }
    }

    fn get_names(&self) -> Vec<String> {
        if self.args.len() < 1 {
            printerrln!("At least one name is required");
            process::exit(-1);
        }
        let mut names: Vec<String> = Vec::with_capacity(self.args.len());
        for name in &self.args {
            names.push(name.clone());
        }
        names
    }

    fn print_usage(&self) {
        printerrln!("{}", self.usage);

        printerrln!("Commands:
  store\t\t\tsave data under name
  load\t\t\tload data under name
  ls\t\t\tlist all stored names
  rm\t\t\tdelete name
  gc\t\t\tdelete unreachable data
  changepassphrase\tchange the passphrase
  verify\t\tverify integrity of chunks associated with a name");
    }
}

fn run(options: &Options) -> io::Result<()> {
    let log = match options.debug_level {
        0 => slog::Logger::root(slog::Discard, o!()),
        dl => {
            let level = match dl {
                0 => unreachable!(),
                1 => slog::Level::Info,
                2 => slog::Level::Debug,
                _ => slog::Level::Trace,
            };
            let drain = slog_term::term_compact();
            let drain = slog_async::Async::default(drain.fuse());
            let drain = slog::LevelFilter::new(drain, level);
            slog::Logger::root(drain.fuse(), o!())
        }
    };
    match options.check_command() {
        Command::Help => {
            options.print_usage();
        }
        Command::Store => {
            let name = options.check_name();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir, log));
            let stats = try!(repo.write(&name, &mut io::stdin()));
            println!("{} new chunks", stats.new_chunks);
            println!("{} new bytes", stats.new_bytes);
        }
        Command::Load => {
            let name = options.check_name();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir, log));
            let pass = read_passphrase(options);
            let seckey = try!(repo.get_seckey(&pass));
            try!(repo.read(&name, &mut io::stdout(), &seckey));
        }
        Command::ChangePassphrase => {
            let dir = options.check_dir();
            let repo = Repo::open(&dir, log)?;
            let pass = read_passphrase(options);
            let seckey = repo.get_seckey(&pass)?;
            let pass = read_new_passphrase();
            repo.change_passphrase(&seckey, &pass)?;
        }
        Command::Remove => {
            let names = options.get_names();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir, log));
            for name in &names {
                try!(repo.rm(&name));
            }
        }
        Command::Init => {
            let size = options.check_chunk_size();
            let chunking = options.check_chunking(size);
            let dir = options.check_dir();
            let pass = read_new_passphrase();
            try!(Repo::init(&dir, &pass, chunking, log));
        }
        Command::DU => {
            let name = options.check_name();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir, log));
            let pass = read_passphrase(options);
            let seckey = try!(repo.get_seckey(&pass));

            let result = try!(repo.du(&name, &seckey));
            println!("{} chunks", result.chunks);
            println!("{} bytes", result.bytes);
        }
        Command::GC => {
            options.check_no_arguments();
            let dir = options.check_dir();

            let repo = try!(Repo::open(&dir, log));

            let result = try!(repo.gc());
            println!("Removed {} chunks", result.chunks);
            println!("Freed {} bytes", result.bytes);
        }
        Command::List => {
            options.check_no_arguments();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir, log));

            for name in try!(repo.list_names()) {
                println!("{}", name);
            }
        }
        Command::Verify => {
            let name = options.check_name();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir, log));
            let pass = read_passphrase(options);
            let seckey = try!(repo.get_seckey(&pass));

            let results = try!(repo.verify(&name, &seckey));
            println!("scanned {} chunk(s)", results.scanned);
            println!("found {} corrupted chunk(s)", results.errors.len());
            for err in results.errors {
                println!("chunk {} - {}", &err.0.to_hex(), err.1);
            }
        }
    }

    Ok(())
}

fn main() {
    env_logger::init().unwrap();

    let options = Options::new();

    if let Err(err) = run(&options) {
        printerrln!("Error: {}", err);
    }
}
