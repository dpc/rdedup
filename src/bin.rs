extern crate rollsum;
extern crate crypto;
#[macro_use]
extern crate log;
extern crate rustc_serialize as serialize;
extern crate argparse;
extern crate sodiumoxide;

use std::io::{Read, Write, Seek};
use std::{fs, mem, thread, io, process};
use std::path::{Path, PathBuf};
use serialize::hex::{ToHex, FromHex};
use std::str::FromStr;

use std::sync::mpsc;

use rollsum::Engine;
use crypto::sha2;
use crypto::digest::Digest;

use argparse::{ArgumentParser, StoreTrue, Store, List};

macro_rules! printerrln {
    ($($arg:tt)*) => ({
        use std::io::prelude::*;
        if let Err(e) = writeln!(&mut ::std::io::stderr(), "{}\n", format_args!($($arg)*)) {
            panic!("Failed to write to stderr.\nOriginal error output: {}\nSecondary error writing to stderr: {}", format!($($arg)*), e);
        }
    })
}

#[derive(Copy, Clone, Debug)]
enum ChunkType {
    Index,
    Data,
}

enum ChunkWriterMessage {
    // ChunkType in every Data is somewhat redundant...
    Data(Vec<u8>, Vec<Edge>, ChunkType),
    Exit,
}

/// Edge: offset in the input and sha256 sum of the chunk
type Edge = (usize, Vec<u8>);

struct Chunker {
    roll : rollsum::Bup,
    sha256 : sha2::Sha256,
    bytes_total : usize,
    bytes_chunk: usize,
    chunks_total : usize,

    edges : Vec<Edge>,
}

impl Chunker {
    pub fn new() -> Self {
        Chunker {
            roll: rollsum::Bup::new(),
            sha256: sha2::Sha256::new(),
            bytes_total: 0,
            bytes_chunk: 0,
            chunks_total: 0,
            edges: vec!(),
        }
    }

    pub fn edge_found(&mut self, input_ofs : usize) {
        debug!("found edge at {}; sum: {:x}",
                 self.bytes_total,
                 self.roll.digest());

        debug!("sha256 hash: {}",
                 self.sha256.result_str());

        let mut sha256 = vec![0u8; 32];
        self.sha256.result(&mut sha256);

        self.edges.push((input_ofs, sha256));

        self.chunks_total += 1;
        self.bytes_chunk += 0;

        self.sha256.reset();
        self.roll = rollsum::Bup::new();
    }

    pub fn input(&mut self, buf : &[u8]) -> Vec<Edge> {
        let mut ofs : usize = 0;
        let len = buf.len();
        while ofs < len {
            if let Some(count) = self.roll.find_chunk_edge(&buf[ofs..len]) {
                self.sha256.input(&buf[ofs..ofs+count]);

                ofs += count;

                self.bytes_chunk += count;
                self.bytes_total += count;
                self.edge_found(ofs);
            } else {
                let count = len - ofs;
                self.sha256.input(&buf[ofs..len]);
                self.bytes_chunk += count;
                self.bytes_total += count;
                break
            }
        }
        mem::replace(&mut self.edges, vec!())
    }

    pub fn finish(&mut self) -> Vec<Edge> {
        if self.bytes_chunk != 0 {
            self.edge_found(0);
        }
        mem::replace(&mut self.edges, vec!())
    }
}

fn chunk_type(digest : &[u8], options : &GlobalOptions) -> Option<ChunkType> {
    for i in &[ChunkType::Index, ChunkType::Data] {
        let file_path = digest_to_path(digest, *i, options);
        if file_path.exists() {
            return Some(*i)
        }
    }
    None
}

/// Load a chunk by ID, using output_f to operate on its parts
fn restore_data_recursive<W : Write>(
    digest : &[u8],
    writer : &mut Write,
    options : &GlobalOptions,
    ctx : &mut Option<gpgme::Context>) {

    fn read_file_to_writer(path : &Path,
                      writer: &mut Write,
                      options : &GlobalOptions,
                      ctx : &mut Option<gpgme::Context>
                     ) {
        if options.use_gpg {
                printerrln!("Opening {:?}", path);
            let mut file = fs::File::open(path).unwrap();
            let mut cipher = gpgme::Data::new().unwrap();
            io::copy(&mut file, &mut cipher).unwrap();
            cipher.seek(io::SeekFrom::Start(0)).unwrap();
            let mut plain = gpgme::Data::new().unwrap();
            ctx.as_mut().unwrap().with_passphrase_handler(|_: gpgme::context::PassphraseRequest, out: &mut Write| {
                printerrln!("Asking for passphrase");
                //try!(out.write_all(b"some passphrase"));
                Ok(())
            }, |mut ctx| {
                ctx.decrypt(&mut cipher, &mut plain).unwrap();
            });
            plain.seek(io::SeekFrom::Start(0)).unwrap();
            io::copy(&mut plain, writer).unwrap();
        } else {
            let mut file = fs::File::open(path).unwrap();
            io::copy(&mut file, writer).unwrap();
        }
    }
    match chunk_type(digest, &options) {
        Some(ChunkType::Index) => {
            let path = digest_to_path(digest, ChunkType::Index, options);
            let mut index_data = vec!();

            read_file_to_writer(&path, &mut index_data, options, ctx);

                assert!(index_data.len() % 32 == 0);

            let _ = index_data.chunks(32).map(|slice| {
                restore_data_recursive::<W>(slice, writer, options, ctx)
            }).count();

        },
        Some(ChunkType::Data) => {
            let path = digest_to_path(digest, ChunkType::Data, options);

            read_file_to_writer(&path, writer, options, ctx);
        },
        None => {
            panic!("File for {} not found", digest.to_hex());
        },
    }
}

fn restore_data<W : Write+Send>(
    digest : &[u8],
    writer : &mut Write,
    options : &GlobalOptions) {


    let mut ctx = if options.use_gpg {
        let ctx = gpgme::create_context().unwrap();

        Some(ctx)
    } else {
        None
    };
    restore_data_recursive::<W>(digest, writer, options, &mut ctx)
}

/// Store data, using input_f to get chunks of data
///
/// Return final digest
fn store_data<R : Read>(tx : mpsc::Sender<ChunkWriterMessage>,
                      mut reader : &mut R,
                      chunk_type : ChunkType,
                      ) -> Vec<u8> {
    let mut chunker = Chunker::new();

    let mut index : Vec<u8> = vec!();
    loop {
        let mut buf = vec![0u8; 16 * 1024];
        let len = reader.read(&mut buf).unwrap();

        if len == 0 {
            break;
        }
        buf.truncate(len);

        let edges = chunker.input(&buf[..len]);

        for &(_, ref sum) in &edges {
            index.append(&mut sum.clone());
        }
        tx.send(ChunkWriterMessage::Data(buf, edges, chunk_type)).unwrap();
    }
    let edges = chunker.finish();

    for &(_, ref sum) in &edges {
        index.append(&mut sum.clone());
    }
    tx.send(ChunkWriterMessage::Data(vec!(), edges, chunk_type)).unwrap();

    if index.len() > 32 {
        store_data(tx, &mut io::Cursor::new(index), ChunkType::Index)
    } else {
        index
    }

}

/// Store stdio and return a digest
fn store_stdio(tx : mpsc::Sender<ChunkWriterMessage>) -> Vec<u8> {
    let mut stdin = io::stdin();
    store_data(tx, &mut stdin, ChunkType::Data)
}

fn digest_to_path(digest : &[u8], chunk_type : ChunkType, options : &GlobalOptions) -> PathBuf {
    let i_or_c = match chunk_type {
        ChunkType::Data => Path::new("chunks"),
        ChunkType::Index => Path::new("index"),
    };

    let mut path = options.dst_dir.join(i_or_c)
        .join(&digest[0..1].to_hex()).join(digest[1..2].to_hex()).join(&digest.to_hex());

    if options.use_gpg {
        path.set_extension("gpg");
    }

    path
}

/// Accept messages on rx and writes them to chunk files
fn chunk_writer(rx : mpsc::Receiver<ChunkWriterMessage>, options : &GlobalOptions) {

    let (mut ctx, key) = if options.use_gpg {
        let ctx = gpgme::create_context().unwrap();
        let key = ctx.find_key("dpc@dpc.pw").unwrap();

        (Some(ctx), Some(key))
    } else {
        (None, None)
    };

    let mut pending_data = vec!();
    loop {
        match rx.recv().unwrap() {
            ChunkWriterMessage::Exit => {
                assert!(pending_data.is_empty());
                return
            }
            ChunkWriterMessage::Data(data, edges, chunk_type) => if edges.is_empty() {
                pending_data.push(data)
            } else {
                let mut prev_ofs = 0;
                for &(ref ofs, ref sha256) in &edges {
                    let path = digest_to_path(&sha256, chunk_type, &options);
                    if !path.exists() {
                        fs::create_dir_all(path.parent().unwrap()).unwrap();
                        let mut chunk_file = fs::File::create(path).unwrap();

                        let (ephemeral_pub, ephemeral_sec) = box_::gen_keypair();

                        let whole_data = vec!();

                            for data in pending_data.drain(..) {
                                whole_data.append(&data);
                                let mut plain = gpgme::Data::from_buffer(&data).unwrap();
                                let cipher = box_::seal(&
                                ctx.as_mut().unwrap().encrypt(&key, gpgme::ops::EncryptFlags::empty(), &mut plain, &mut cipher).unwrap();
                            }
                            if *ofs != prev_ofs {
                                let mut plain = gpgme::Data::from_buffer(&data[prev_ofs..*ofs]).unwrap();
                                ctx.as_mut().unwrap().encrypt(&key, gpgme::ops::EncryptFlags::empty(), &mut plain, &mut cipher).unwrap();
                            }
                    } else {
                        pending_data.clear();
                    }
                    debug_assert!(pending_data.is_empty());

                    prev_ofs = *ofs;
                }
                if prev_ofs != data.len() {
                    let mut data = data;
                    pending_data.push(data.split_off(prev_ofs))
                }
            }
        }
    }
}

fn key_file_path(&options : &GlobalOptions) {
    options.dst_dir.join("key")
}

fn load_pub_key_into_options(options : &GlobalOptions) {
    let path = key_file_path(options);

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) => {
            printerrln!("Couldn't open {}: {}", path, e);
            process::exit(-1);
        }
    };

    file.read_to_end(&mut options.pub_key).unwrap();
}

fn load_sec_key_into_options(options : &mut GlobalOptions) {
    printerrln!("Enter secret key:");
    let mut s = String::new();
    io::stdio().read_line(&mut s);
    options.sec_key = s.from_hex().unwrap();
}

fn repo_init(options : &mut GlobalOptions) {
    fs::create_dir_all(options.dst_dir).unwrap();
    let path = key_file_path(options);

    if path.exists() {
        printerrln("{} exists - backup store initialized already");
        process::exit(-1);
    }

    let mut file = File::create(path);
    let (pk, sk) = box_::gen_keypair();

    file.write_all(pk).unwrap();
    file.flush().unwrap();
    println!("{}", sk.to_hex());
    printerrln!("Remember to write down above secret key!");
}

#[derive(Clone)]
struct GlobalOptions {
    verbose : bool,
    dst_dir : PathBuf,
    pub_key : Vec<u8>,
    sec_key : Vec<u8>,
}

enum Command {
    Help,
    Save,
    Load,
    Init,
}

impl FromStr for Command {
    type Err = ();
    fn from_str(src: &str) -> Result<Command, ()> {
        match src {
            "help" => Ok(Command::Help),
            "save" => Ok(Command::Save),
            "load" => Ok(Command::Load),
            "init" => Ok(Command::Init),
            _ => Err(()),
        }
    }
}

fn main() {
    let mut options = GlobalOptions {
        verbose: false,
        dst_dir: Path::new("backup").to_owned(),
    };

    let mut subcommand = Command::Help;
    let mut args : Vec<String> = vec!();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("rdedup");
        ap.refer(&mut options.verbose)
            .add_option(&["-v", "--verbose"], StoreTrue,
                        "Be verbose");
        ap.refer(&mut options.use_gpg)
            .add_option(&["--gpg"], StoreTrue, "Use gpg");
        ap.refer(&mut subcommand)
            .add_argument("command", Store,
                r#"Command to run (either "save" or "restore")"#);
        ap.refer(&mut args)
            .add_argument("arguments", List,
                r#"Arguments for command"#);
        ap.stop_on_first_argument(true);
        ap.parse_args_or_exit();
    }

    let (tx, rx) = mpsc::channel();

    match subcommand {
        Command::Help => {
            println!("Use save / restore argument");
        },
        Command::Save => {
            load_pub_key_into_options(&mut options);
            let chunk_writer_join = thread::spawn(move || chunk_writer(rx, &options));

            let final_digest = store_stdio(tx.clone());

            println!("Stored as {}", final_digest.to_hex());

            tx.send(ChunkWriterMessage::Exit).unwrap();
            chunk_writer_join.join().unwrap();
        },
        Command::Load => {
            if args.len() != 1 {
                println!("One argument required");
                process::exit(-1);
            }
            load_pub_key_into_options(&mut options);

            let digest = args[0].from_hex().unwrap();
            restore_data::<io::Stdout>(&digest, &mut io::stdout(), &options);
        }
        Command::Init => {
            repo_init(&options);
        }
    }
}
