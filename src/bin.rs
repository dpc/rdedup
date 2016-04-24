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


fn read_sec_key() -> lib::SecretKey {
    loop {
        printerrln!("Enter secret key:");
        let mut s = String::new();
        io::stdin().read_line(&mut s).unwrap();
        match lib::SecretKey::from_str(&s) {
            Some(sk) => return sk,
            None => {
                printerrln!("Invalid!");
            }
        }
    }
}

enum Command {
    Help,
    Write,
    Read,
    Init,
    DU,
    GC,
}

impl FromStr for Command {
    type Err = ();
    fn from_str(src: &str) -> Result<Command, ()> {
        match src {
            "help" => Ok(Command::Help),
            "write" => Ok(Command::Write),
            "read" => Ok(Command::Read),
            "init" => Ok(Command::Init),
            "du" => Ok(Command::DU),
            "gc" => Ok(Command::GC),
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
        Command::Write => {
            if args.len() != 1 {
                printerrln!("Name required");
                process::exit(-1);
            }
            let repo = Repo::open(dir_path).unwrap();
            repo.write(&args[0], &mut io::stdin()).unwrap();
        },
        Command::Read=> {
            if args.len() != 1 {
                printerrln!("Name required");
                process::exit(-1);
            }
            let repo = Repo::open(dir_path).unwrap();
            let sec_key = read_sec_key();
            repo.read(&args[0], &mut io::stdout(), &sec_key).unwrap();
        }
        Command::Init => {
            let (_, sec_key) = Repo::init(dir_path).unwrap();
                printerrln!("Write down the secret key:");
                println!("{}", sec_key.to_string());
        }
        Command::DU => {
            if args.len() != 1 {
                printerrln!("Backup name required");
                process::exit(-1);
            }
            let repo = Repo::open(dir_path).unwrap();
            let sec_key = read_sec_key();

            let size = repo.du(&args[0], &sec_key).unwrap();
            println!("{}", size);
        },
        Command::GC => {
            if args.len() != 0 {
                printerrln!("Unnecessary argument");
                process::exit(-1);
            }

            let repo = Repo::open(&dir_path).unwrap();

            let reachable = repo.list_reachable_chunks().unwrap();
            let all = repo.list_stored_chunks().unwrap();

            for digest in all.difference(&reachable) {
                println!("Unreachable: {}", digest.to_hex());
            }
            for digest in reachable.difference(&all) {
                println!("Missing: {}", digest.to_hex());
            }
        }
    }
}
