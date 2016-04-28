#[macro_use]
extern crate log;
extern crate rustc_serialize as serialize;
extern crate argparse;
extern crate env_logger;
extern crate rdedup_lib as lib;

use std::io::{Read, Write};
use std::{io, process};
use std::path::Path;
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

fn main() {
    env_logger::init().unwrap();

    let mut dir_str = String::from("backup");

    let mut subcommand = Command::Help;
    let mut args : Vec<String> = vec!();

    {
        use argparse::*;
        let mut ap = ArgumentParser::new();
        ap.set_description("rdedup");
        ap.refer(&mut dir_str)
            .add_option(&["-d", "--dir"], Store,
                        "Destination dir");
        ap.refer(&mut subcommand)
            .add_argument("command", Store,
                r#"Command to run"#);
        ap.refer(&mut args)
            .add_argument("arguments", List,
                r#"Arguments for command"#);
        ap.stop_on_first_argument(true);
        ap.parse_args_or_exit();
    }

    let dir_path = Path::new(&dir_str);
    match subcommand {
        Command::Help => {
            printerrln!("TODO: List of implemented commands");
        },
        Command::Store => {
            if args.len() != 1 {
                printerrln!("Name required");
                process::exit(-1);
            }
            let repo = Repo::open(dir_path).unwrap();
            repo.write(&args[0], &mut io::stdin()).unwrap();
        },
        Command::Load => {
            if args.len() != 1 {
                printerrln!("Name required");
                process::exit(-1);
            }
            let repo = Repo::open(dir_path).unwrap();
            let pass = read_passphrase();
            repo.read(&args[0], &mut io::stdout(), &pass).unwrap();
        },
        Command::Remove => {
            if args.len() != 1 {
                printerrln!("Name required");
                process::exit(-1);
            }
            let repo = Repo::open(dir_path).unwrap();
            repo.rm(&args[0]).unwrap();
        },
        Command::Init => {
            let pass = read_passphrase();
            Repo::init(dir_path, &pass).unwrap();
        },
        Command::DU => {
            if args.len() != 1 {
                printerrln!("Backup name required");
                process::exit(-1);
            }
            let repo = Repo::open(dir_path).unwrap();
            let pass = read_passphrase();

            let size = repo.du(&args[0], &pass).unwrap();
            println!("{}", size);
        },
        Command::Unreachable => {
            if args.len() != 0 {
                printerrln!("Unnecessary argument");
                process::exit(-1);
            }

            let repo = Repo::open(&dir_path).unwrap();

            let reachable = repo.list_reachable_chunks().unwrap();
            let stored = repo.list_stored_chunks().unwrap();

            for digest in stored.difference(&reachable) {
                println!("{}", digest.to_hex());
            }
        },
        Command::GC => {
            if args.len() != 0 {
                printerrln!("Unnecessary argument");
                process::exit(-1);
            }

            let repo = Repo::open(&dir_path).unwrap();

            let removed = repo.gc().unwrap();
            println!("Removed {} chunks", removed);
        },
        Command::Missing => {
            if args.len() != 0 {
                printerrln!("Unnecessary argument");
                process::exit(-1);
            }

            let repo = Repo::open(&dir_path).unwrap();

            let reachable = repo.list_reachable_chunks().unwrap();
            let stored = repo.list_stored_chunks().unwrap();

            for digest in reachable.difference(&stored) {
                println!("{}", digest.to_hex());
            }
        }
        Command::List => {
            if args.len() != 0 {
                printerrln!("Unnecessary argument");
                process::exit(-1);
            }

            let repo = Repo::open(&dir_path).unwrap();


            for name in repo.list_names().unwrap() {
                println!("{}", name);
            }
        }
    }
}
