#[macro_use]
extern crate log;
extern crate rustc_serialize as serialize;
extern crate argparse;
extern crate env_logger;
extern crate rdedup_lib as lib;

use std::io::{Read, Write};
use std::{io, process, env};
use std::path;
use serialize::hex::ToHex;
use std::str::FromStr;

use lib::Repo;

macro_rules! printerrln {
    ($($arg:tt)*) => ({
        use std::io::prelude::*;
        if let Err(e) = writeln!(&mut ::std::io::stderr(), "{}\n", format_args!($($arg)*)) {
            panic!("Failed to write to stderr.\nOriginal error output: {}\nSecondary error writing to stderr: {}", format!($($arg)*), e);
        }
    })
}


fn read_passphrase() -> String {
    printerrln!("Enter passphrase:");
    let mut s = String::new();
    io::stdin().read_line(&mut s).unwrap();
    s
}

#[derive(Copy, Clone)]
enum Command {
    Help,
    Store,
    Load,
    Init,
    DU,
    GC,
    Missing,
    Unreachable,
    Remove,
    List,
}

impl FromStr for Command {
    type Err = ();
    fn from_str(src: &str) -> Result<Command, ()> {
        match src {
            "help" => Ok(Command::Help),
            "store" => Ok(Command::Store),
            "load" => Ok(Command::Load),
            "init" => Ok(Command::Init),
            "rm" => Ok(Command::Remove),
            "delete" => Ok(Command::Remove),
            "del" => Ok(Command::Remove),
            "ls" => Ok(Command::List),
            "list" => Ok(Command::List),
            "du" => Ok(Command::DU),
            "gc" => Ok(Command::GC),
            "unreachable" => Ok(Command::Unreachable),
            "missing" => Ok(Command::Missing),
            _ => Err(()),
        }
    }
}

struct Options {
    dir_str : String,
    args : Vec<String>,
    command : Command,
    usage : String,
}

impl Options {
    fn new() -> Self {
        let mut dir_str = env::var("RDEDUP_DIR").unwrap_or("".to_owned());
        let mut args = vec!();
        let mut command = Command::Help;
        let mut usage = vec!();

        {
            let mut ap = argparse::ArgumentParser::new();
            use argparse::*;
            ap.set_description("rdedup");
            ap.refer(&mut dir_str)
                .add_option(&["-d", "--dir"], Store,
                            "destination dir");
            ap.refer(&mut command)
                .add_argument("command", Store,
                              r#"command to run"#);
            ap.refer(&mut args)
                .add_argument("arguments", List,
                              r#"arguments for command"#);

            ap.add_option(&["-V", "--version"],
                          Print(env!("CARGO_PKG_VERSION").to_string()), "show version");

            ap.stop_on_first_argument(true);
            ap.parse_args_or_exit();

            ap.print_help("rdedup", &mut usage).unwrap();
        }

        Options{
            dir_str : dir_str,
            command: command,
            args: args,
            usage : String::from_utf8_lossy(&usage).to_string(),
        }
    }

    fn check_no_arguments(&self) {
        if self.args.len() > 0 {
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
            printerrln!("No destination directory specified. Use `--dir` or `$RDEDUP_DIR`");
            process::exit(-1);
        }
        path::Path::new(&self.dir_str).to_owned()
    }
    fn print_usage(&self) {
        printerrln!("{}", self.usage);


        printerrln!("Commands:
  store\t\t\tsave data under name
  load\t\t\tload data under name
  ls\t\t\tlist all stored names
  rm\t\t\tdelete name
  gc\t\t\tdelete unreachable data");
    }
}

fn run(options : &Options) -> io::Result<()> {
    match options.check_command() {
        Command::Help => {
            options.print_usage();
        },
        Command::Store => {
            let name = options.check_name();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir));
            try!(repo.write(&name, &mut io::stdin()));
        },
        Command::Load => {
            let name = options.check_name();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir));
            let pass = read_passphrase();
            try!(repo.read(&name, &mut io::stdout(), &pass));
        },
        Command::Remove => {
            let name = options.check_name();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir));
            try!(repo.rm(&name));
        },
        Command::Init => {
            let dir = options.check_dir();
            let pass = read_passphrase();
            try!(Repo::init(&dir, &pass));
        },
        Command::DU => {
            let name = options.check_name();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir));
            let pass = read_passphrase();

            let size = try!(repo.du(&name, &pass));
            println!("{}", size);
        },
        Command::Unreachable => {
            options.check_no_arguments();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir));

            let reachable = try!(repo.list_reachable_chunks());
            let stored = try!(repo.list_stored_chunks());

            for digest in stored.difference(&reachable) {
                println!("{}", digest.to_hex());
            }
        },
        Command::GC => {
            options.check_no_arguments();
            let dir = options.check_dir();

            let repo = try!(Repo::open(&dir));

            let removed = try!(repo.gc());
            println!("Removed {} chunks", removed);
        },
        Command::Missing => {
            options.check_no_arguments();
            let dir = options.check_dir();

            let repo = try!(Repo::open(&dir));

            let reachable = try!(repo.list_reachable_chunks());
            let stored = try!(repo.list_stored_chunks());

            for digest in reachable.difference(&stored) {
                println!("{}", digest.to_hex());
            }
        }
        Command::List => {
            options.check_no_arguments();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir));

            for name in try!(repo.list_names()) {
                println!("{}", name);
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
