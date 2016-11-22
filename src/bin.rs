#[macro_use]
extern crate log;
extern crate rustc_serialize as serialize;
extern crate argparse;
extern crate env_logger;
extern crate rdedup_lib as lib;
extern crate rpassword;

use std::{io, process, env};
use std::path;
use std::str::FromStr;

use lib::Repo;


macro_rules! printerrln {
    ($($arg:tt)*) => ({
        use std::io::prelude::*;
        if let Err(e) = writeln!(&mut ::std::io::stderr(), "{}", format_args!($($arg)*)) {
            panic!(concat!(
                    "Failed to write to stderr.\n",
                    "Original error output: {}\n",
                    "Secondary error writing to stderr: {}"),
                    format!($($arg)*), e);
        }
    })
}

macro_rules! printerr {
    ($($arg:tt)*) => ({
        use std::io::prelude::*;
        if let Err(e) = write!(&mut ::std::io::stderr(), "{}", format_args!($($arg)*)) {
            panic!(concat!(
                    "Failed to write to stderr.\n",
                    "Original error output: {}\n",
                    "Secondary error writing to stderr: {}"),
                    format!($($arg)*), e);
        }
    })
}


fn read_passphrase(o: &Options) -> String {
    printerrln!("Warning: Use `--add-newline` option if you generated repo with rdedup version \
                 <= 0.2");
    printerr!("Enter passphrase: ");
    if o.add_newline {
        rpassword::read_password().unwrap() + "\n"
    } else {
        rpassword::read_password().unwrap()
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
            "rm" | "delete" | "del" => Ok(Command::Remove),
            "ls" | "list" => Ok(Command::List),
            "du" => Ok(Command::DU),
            "gc" => Ok(Command::GC),
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
}

impl Options {
    fn new() -> Self {
        let mut dir_str = env::var("RDEDUP_DIR").unwrap_or("".to_owned());
        let mut args = vec![];
        let mut command = Command::Help;
        let mut usage = vec![];
        let mut add_newline = false;

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

        Options {
            dir_str: dir_str,
            command: command,
            args: args,
            add_newline: add_newline,
            usage: String::from_utf8_lossy(&usage).to_string(),
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

fn run(options: &Options) -> io::Result<()> {
    match options.check_command() {
        Command::Help => {
            options.print_usage();
        }
        Command::Store => {
            let name = options.check_name();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir));
            try!(repo.write(&name, &mut io::stdin()));
        }
        Command::Load => {
            let name = options.check_name();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir));
            let pass = read_passphrase(&options);
            let seckey = try!(repo.get_seckey(&pass));
            try!(repo.read(&name, &mut io::stdout(), &seckey));
        }
        Command::Remove => {
            let name = options.check_name();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir));
            try!(repo.rm(&name));
        }
        Command::Init => {
            let dir = options.check_dir();
            let pass = read_passphrase(&options);
            try!(Repo::init(&dir, &pass));
        }
        Command::DU => {
            let name = options.check_name();
            let dir = options.check_dir();
            let repo = try!(Repo::open(&dir));
            let pass = read_passphrase(&options);
            let seckey = try!(repo.get_seckey(&pass));

            let size = try!(repo.du(&name, &seckey));
            println!("{}", size);
        }
        Command::GC => {
            options.check_no_arguments();
            let dir = options.check_dir();

            let repo = try!(Repo::open(&dir));

            let removed = try!(repo.gc());
            println!("Removed {} chunks", removed);
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
