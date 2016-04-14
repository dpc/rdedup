extern crate rollsum;
extern crate crypto;
#[macro_use]
extern crate log;
extern crate rustc_serialize as serialize;
extern crate argparse;
extern crate sodiumoxide;
extern crate flate2;

use std::io::{Read, Write};
use std::{fs, mem, thread, io, process};
use std::path::{Path, PathBuf};
use serialize::hex::{ToHex, FromHex};
use std::str::FromStr;

use std::sync::mpsc;

use rollsum::Engine;
use crypto::sha2;
use crypto::digest::Digest;

use sodiumoxide::crypto::box_;

use argparse::{ArgumentParser, StoreTrue, Store, List};

macro_rules! printerrln {
    ($($arg:tt)*) => ({
        use std::io::prelude::*;
        if let Err(e) = writeln!(&mut ::std::io::stderr(), "{}\n", format_args!($($arg)*)) {
            panic!("Failed to write to stderr.\nOriginal error output: {}\nSecondary error writing to stderr: {}", format!($($arg)*), e);
        }
    })
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum ChunkType {
    Index,
    Data,
}

impl ChunkType {
    fn should_compress(&self) -> bool {
        *self == ChunkType::Data
    }
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
        let file_path = chunk_path_by_digest(digest, *i, options);
        if file_path.exists() {
            return Some(*i)
        }
    }
    None
}

/// Load a chunk by ID, using output_f to operate on its parts
fn traverse_data_recursive(
    digest : &[u8],
    on_index_digest: &mut FnMut(&[u8],&GlobalOptions),
    on_data: &mut FnMut(&[u8], &GlobalOptions),
    options : &GlobalOptions,
    ) {

    let chunk_type = chunk_type(digest, &options);
    if chunk_type.is_none() {
        panic!("File for {} not found", digest.to_hex());
    }

    let chunk_type = chunk_type.unwrap();
    match chunk_type {
        ChunkType::Index => {
            let path = chunk_path_by_digest(digest, chunk_type, options);
            let mut index_data = vec!();

            read_file_to_writer(&path, digest, chunk_type, &mut index_data, options);

            assert!(index_data.len() % 32 == 0);

            let _ = index_data.chunks(32).map(|slice| {
                on_index_digest(&slice, options);
                traverse_data_recursive(slice, on_index_digest, on_data, options)
            }).count();

        },
        ChunkType::Data => {
            let path = chunk_path_by_digest(digest, chunk_type, options);

            let mut data = vec!();
            read_file_to_writer(&path, digest, chunk_type, &mut data, options);
            on_data(&data, options);
        },
    }
}

fn repo_du(digest : &[u8], options : &GlobalOptions) -> u64 {
    let mut bytes = 0u64;
    traverse_data_recursive(
    digest,
    &mut |_ : &[u8], _ : &GlobalOptions|{},
    &mut | data: &[u8], _ : &GlobalOptions| {
        bytes += data.len() as u64
    },
    options,
    );
    bytes
}

fn read_file_to_writer(path : &Path,
                       digest : &[u8],
                       chunk_type : ChunkType,
                       writer: &mut Write,
                       options : &GlobalOptions,
                       ) {
    let mut file = fs::File::open(path).unwrap();
    let mut ephemeral_pub = [0; box_::PUBLICKEYBYTES];
    file.read_exact(&mut ephemeral_pub).unwrap();

    let mut cipher = Vec::with_capacity(16 * 1024);
    file.read_to_end(&mut cipher).unwrap();

    let nonce = box_::Nonce::from_slice(&digest[0..box_::NONCEBYTES]).unwrap();
    let sec_key = options.sec_key.as_ref().unwrap();
    let data = box_::open(&cipher, &nonce, &box_::PublicKey(ephemeral_pub), sec_key).unwrap();

    let data = if chunk_type.should_compress() {
        let mut decompressor = flate2::write::DeflateDecoder::new(Vec::with_capacity(data.len()));

        decompressor.write_all(&data).unwrap();
        decompressor.finish().unwrap()
    } else {
        data
    };

    io::copy(&mut io::Cursor::new(data), writer).unwrap();
}

/// Load a chunk by ID, using output_f to operate on its parts
fn load_data_recursive<W : Write>(
    digest : &[u8],
    writer : &mut Write,
    options : &GlobalOptions,
    ) {


    let chunk_type = chunk_type(digest, &options);
    if chunk_type.is_none() {
        panic!("File for {} not found", digest.to_hex());
    }

    let chunk_type = chunk_type.unwrap();
    match chunk_type {
        ChunkType::Index => {
            let path = chunk_path_by_digest(digest, chunk_type, options);
            let mut index_data = vec!();

            read_file_to_writer(&path, digest, chunk_type, &mut index_data, options);

            assert!(index_data.len() % 32 == 0);

            let _ = index_data.chunks(32).map(|slice| {
                load_data_recursive::<W>(slice, writer, options)
            }).count();

        },
        ChunkType::Data => {
            let path = chunk_path_by_digest(digest, chunk_type, options);

            read_file_to_writer(&path, digest, chunk_type, writer, options);
        },
    }
}

fn restore_data<W : Write+Send>(
    digest : &[u8],
    writer : &mut Write,
    options : &GlobalOptions) {

    load_data_recursive::<W>(digest, writer, options)
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

fn chunk_path_by_digest(digest : &[u8], chunk_type : ChunkType, options : &GlobalOptions) -> PathBuf {
    let i_or_c = match chunk_type {
        ChunkType::Data => Path::new("chunks"),
        ChunkType::Index => Path::new("index"),
    };

    options.dst_dir.join(i_or_c)
        .join(&digest[0..1].to_hex()).join(digest[1..2].to_hex()).join(&digest.to_hex())
}

/// Accept messages on rx and writes them to chunk files
fn chunk_writer(rx : mpsc::Receiver<ChunkWriterMessage>, options : &GlobalOptions) {
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
                    let path = chunk_path_by_digest(&sha256, chunk_type, &options);
                    if !path.exists() {
                        fs::create_dir_all(path.parent().unwrap()).unwrap();
                        let mut chunk_file = fs::File::create(path).unwrap();

                        let (ephemeral_pub, ephemeral_sec) = box_::gen_keypair();

                        let mut whole_data = vec!();

                        for data in pending_data.drain(..) {
                            whole_data.write_all(&data).unwrap();
                        }
                        if *ofs != prev_ofs {
                            whole_data.write_all(&data[prev_ofs..*ofs]).unwrap();
                        }

                        let pub_key = &options.pub_key.as_ref().unwrap();

                        let compress = chunk_type.should_compress();

                        let whole_data = if compress {
                            let mut compressor = flate2::write::DeflateEncoder::new(
                                Vec::with_capacity(whole_data.len()), flate2::Compression::Default
                                );

                            compressor.write_all(&whole_data).unwrap();
                            compressor.finish().unwrap()
                        } else {
                            whole_data
                        };

                        let nonce = box_::Nonce::from_slice(&sha256[0..box_::NONCEBYTES]).unwrap();

                        let cipher = box_::seal(
                            &whole_data,
                            &nonce,
                            &pub_key,
                            &ephemeral_sec
                            );
                        chunk_file.write_all(&ephemeral_pub.0).unwrap();
                        chunk_file.write_all(&cipher).unwrap();
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

fn store_digest_as_backup_name(digest : &[u8], name : &str, options : &GlobalOptions) {
    let backup_dir = options.dst_dir.join("backup");
    fs::create_dir_all(&backup_dir).unwrap();
    let backup_path = backup_dir.join(name);

    if backup_path.exists() {
        panic!("Backup {} already exists!", name);
    }

    let mut file = fs::File::create(&backup_path).unwrap();

    file.write_all(digest).unwrap();
}

fn backup_name_to_digest(name : &str, options : &GlobalOptions) -> Vec<u8> {
    let backup_path = options.dst_dir.join("backup").join(name);

    let mut file = fs::File::open(&backup_path).unwrap();
    let mut buf = vec!();
    file.read_to_end(&mut buf).unwrap();

    buf
}

fn pub_key_file_path(options : &GlobalOptions) -> PathBuf {
    options.dst_dir.join("pub_key")
}

fn sec_key_file_path(options : &GlobalOptions) -> PathBuf {
    options.dst_dir.join("sec_key")
}

fn load_pub_key_into_options(options : &mut GlobalOptions) {
    let path = pub_key_file_path(options);

    let mut file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(e) => {
            printerrln!("Couldn't open {:?}: {}", path, e);
            process::exit(-1);
        }
    };

    let mut buf = vec!();
    file.read_to_end(&mut buf).unwrap();
    let s = std::str::from_utf8(&buf).unwrap();
    options.pub_key = Some(box_::PublicKey::from_slice(&s.from_hex().unwrap()).unwrap());
}

fn load_sec_key_into_options(options : &mut GlobalOptions) {
    let path = sec_key_file_path(options);

    if path.exists() {
        let mut file = fs::File::open(&path).unwrap();
        let mut buf = vec!();
        file.read_to_end(&mut buf).unwrap();
        let s = std::str::from_utf8(&buf).unwrap();
        options.sec_key = Some(box_::SecretKey::from_slice(&s.from_hex().unwrap()).unwrap());
    } else {
        printerrln!("Enter secret key:");
        let mut s = String::new();
        io::stdin().read_line(&mut s).unwrap();
        options.sec_key = Some(box_::SecretKey::from_slice(&s.from_hex().unwrap()).unwrap());
    }
}

fn repo_init(options : &GlobalOptions) {
    fs::create_dir_all(&options.dst_dir).unwrap();
    let path = pub_key_file_path(options);

    if path.exists() {
        printerrln!("{:?} exists - backup store initialized already", path);
        process::exit(-1);
    }

    let mut file = fs::File::create(path).unwrap();
    let (pk, sk) = box_::gen_keypair();

    file.write_all(&pk.0.to_hex().as_bytes()).unwrap();
    file.flush().unwrap();
    println!("{}", sk.0.to_hex());
    printerrln!("Remember to write down above secret key!");
}

#[derive(Clone)]
struct GlobalOptions {
    verbose : bool,
    dst_dir : PathBuf,
    backup_name : String,
    pub_key : Option<box_::PublicKey>,
    sec_key : Option<box_::SecretKey>,
}

enum Command {
    Help,
    Save,
    Load,
    Init,
    DiskUsage,
}

impl FromStr for Command {
    type Err = ();
    fn from_str(src: &str) -> Result<Command, ()> {
        match src {
            "help" => Ok(Command::Help),
            "du" => Ok(Command::DiskUsage),
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
        backup_name : String::new(),
        dst_dir: Path::new("backup").to_owned(),
        pub_key: None,
        sec_key: None,
    };

    let mut subcommand = Command::Help;
    let mut args : Vec<String> = vec!();

    {
        let mut ap = ArgumentParser::new();
        ap.set_description("rdedup");
        ap.refer(&mut options.verbose)
            .add_option(&["-v", "--verbose"], StoreTrue,
                        "Be verbose");
        ap.refer(&mut subcommand)
            .add_argument("command", Store,
                r#"Command to run (either "save" or "load")"#);
        ap.refer(&mut args)
            .add_argument("arguments", List,
                r#"Arguments for command"#);
        ap.stop_on_first_argument(true);
        ap.parse_args_or_exit();
    }

    let (tx, rx) = mpsc::channel();

    match subcommand {
        Command::Help => {
            printerrln!("Use save / restore argument");
        },
        Command::Save => {
            if args.len() != 1 {
                printerrln!("Backup name required");
                process::exit(-1);
            }
            load_pub_key_into_options(&mut options);
            let chunk_writer_join = thread::spawn({let options = options.clone(); move || chunk_writer(rx, &options)});

            let final_digest = store_stdio(tx.clone());


            tx.send(ChunkWriterMessage::Exit).unwrap();
            chunk_writer_join.join().unwrap();

            printerrln!("Storing {} as backup {}", final_digest.to_hex(), &args[0]);
            store_digest_as_backup_name(&final_digest, &args[0], &options);
        },
        Command::Load => {
            if args.len() != 1 {
                printerrln!("Backup name required");
                process::exit(-1);
            }
            load_pub_key_into_options(&mut options);
            load_sec_key_into_options(&mut options);

            let digest = backup_name_to_digest(&args[0], &options);
            restore_data::<io::Stdout>(&digest, &mut io::stdout(), &options);
        }
        Command::Init => {
            repo_init(&mut options);
        }
        Command::DiskUsage => {
            if args.len() != 1 {
                printerrln!("Backup name required");
                process::exit(-1);
            }
            load_pub_key_into_options(&mut options);
            load_sec_key_into_options(&mut options);

            let digest = backup_name_to_digest(&args[0], &options);
            let size = repo_du(&digest, &options);
            println!("{}", size);
        }
    }
}
