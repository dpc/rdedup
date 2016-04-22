extern crate rollsum;
extern crate crypto;
#[macro_use]
extern crate log;
extern crate rustc_serialize as serialize;
extern crate argparse;
extern crate sodiumoxide;
extern crate flate2;
extern crate env_logger;

use std::io::{Read, Write};
use std::{fs, mem, thread, io, process};
use std::path::{Path, PathBuf};
use serialize::hex::{ToHex, FromHex};
use std::str::FromStr;
use std::collections::HashSet;

use std::sync::mpsc;
use std::cell::RefCell;

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

    fn should_encrypt(&self) -> bool {
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

fn traverse_storage_recursively(
    digest : &[u8],
    on_index: &mut FnMut(&[u8], &mut FnMut(&[u8], &GlobalOptions), &GlobalOptions),
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
            on_index(digest, on_data, options);
        },
        ChunkType::Data => {
            on_data(digest, options);
        },
    }
}

fn repo_all_backups(options : &GlobalOptions) -> Vec<String> {
    let mut ret : Vec<String> = vec!();

    let backup_dir = options.dst_dir.join("backup");
    for entry in fs::read_dir(backup_dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().to_string();
        info!("Found backup: {}", name);
        ret.push(name)
    }

    ret
}

fn repo_backup_add_to_reachable(digest : &[u8],
                                reachable_digests : &RefCell<HashSet<Vec<u8>>>,
                                options : &GlobalOptions) {
    reachable_digests.borrow_mut().insert(digest.to_owned());

    traverse_storage_recursively(
        digest,
        &mut |digest, on_data, options| {
            reachable_digests.borrow_mut().insert(digest.to_owned());
            traverse_index(digest, on_data, options);
        },
        &mut |digest, _| {
            reachable_digests.borrow_mut().insert(digest.to_owned());
        },
        options
        );
}

fn repo_reachable(options : &GlobalOptions) -> HashSet<Vec<u8>> {
    let reachable_digests = RefCell::new(HashSet::new());
    for backup in repo_all_backups(&options) {
        let digest = backup_name_to_digest(&backup, &options);
        repo_backup_add_to_reachable(&digest, &reachable_digests, &options);
    }
    reachable_digests.into_inner()
}

fn repo_insert_all_digest_in_dir_into(path : &Path, reachable : &mut HashSet<Vec<u8>>) {
    for out_entry in fs::read_dir(path).unwrap() {
        let out_entry = out_entry.unwrap();
        for mid_entry in fs::read_dir(out_entry.path()).unwrap() {
            let mid_entry = mid_entry.unwrap();
            for entry in fs::read_dir(mid_entry.path()).unwrap() {
                let entry = entry.unwrap();
                let name= entry.file_name().to_string_lossy().to_string();
                let entry_digest = name.from_hex().unwrap();
                reachable.insert(entry_digest);
            }
        }
    }
}

fn repo_list_all_digest(options : &GlobalOptions) -> HashSet<Vec<u8>> {
    let mut digests = HashSet::new();
    repo_insert_all_digest_in_dir_into(&options.dst_dir.join("index"), &mut digests);
    repo_insert_all_digest_in_dir_into(&options.dst_dir.join("chunks"), &mut digests);
    digests
}

fn repo_du(digest : &[u8], options : &GlobalOptions) -> u64 {
    let mut bytes = 0u64;

    traverse_storage_recursively(
        digest,
        &mut traverse_index,
        &mut |digest, options| {
            let mut data = vec!();
            read_file_to_writer(digest, ChunkType::Data, &mut data, options);
            bytes += data.len() as u64;
        },
        options
        );
    bytes
}

fn read_file_to_writer(digest : &[u8],
                       chunk_type : ChunkType,
                       writer: &mut Write,
                       options : &GlobalOptions,
                       ) {

    let path = chunk_path_by_digest(digest, chunk_type, options);
    let mut file = fs::File::open(path).unwrap();
    let mut data = Vec::with_capacity(16 * 1024);

    let data = if chunk_type.should_encrypt() {
        let mut ephemeral_pub = [0; box_::PUBLICKEYBYTES];
        file.read_exact(&mut ephemeral_pub).unwrap();
        file.read_to_end(&mut data).unwrap();
        let nonce = box_::Nonce::from_slice(&digest[0..box_::NONCEBYTES]).unwrap();
        let sec_key = options.sec_key.as_ref().unwrap();
        box_::open(&data, &nonce, &box_::PublicKey(ephemeral_pub), sec_key).unwrap()
    } else {
        file.read_to_end(&mut data).unwrap();
        data
    };

    let data = if chunk_type.should_compress() {
        let mut decompressor = flate2::write::DeflateDecoder::new(Vec::with_capacity(data.len()));

        decompressor.write_all(&data).unwrap();
        decompressor.finish().unwrap()
    } else {
        data
    };

    let mut sha256 = sha2::Sha256::new();
    sha256.input(&data);
    let mut sha256_digest = vec![0u8; 32];
    sha256.result(&mut sha256_digest);
    if sha256_digest != digest {
        panic!("{} corrupted, data read: {}", digest.to_hex(), sha256_digest.to_hex());
    }
    io::copy(&mut io::Cursor::new(data), writer).unwrap();
}

fn traverse_index(digest : &[u8], on_data : &mut FnMut(&[u8], &GlobalOptions), options :&GlobalOptions) {
    let mut index_data = vec!();

    read_file_to_writer(digest, ChunkType::Index, &mut index_data, options);

    assert!(index_data.len() % 32 == 0);

    let _ = index_data.chunks(32).map(|slice| {
        traverse_storage_recursively(slice, &mut traverse_index, on_data, options);
    }).count();
}

fn restore_data<W : Write+Send>(
    digest : &[u8],
    writer : &mut Write,
    options : &GlobalOptions) {

    traverse_storage_recursively(
        digest,
        &mut traverse_index,
        &mut |digest, options| {
            read_file_to_writer(digest, ChunkType::Data, writer, options);
        },
        options
        )
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
    let mut previous_parts = vec!();

    loop {
        match rx.recv().unwrap() {
            ChunkWriterMessage::Exit => {
                assert!(previous_parts.is_empty());
                return
            }
            ChunkWriterMessage::Data(part, edges, chunk_type) => {
                if edges.is_empty() {
                    previous_parts.push(part)
                } else {
                    let mut prev_ofs = 0;
                    for &(ref ofs, ref sha256) in &edges {
                        let path = chunk_path_by_digest(&sha256, chunk_type, &options);
                        if !path.exists() {
                            fs::create_dir_all(path.parent().unwrap()).unwrap();
                            let mut chunk_file = fs::File::create(path).unwrap();

                            let (ephemeral_pub, ephemeral_sec) = box_::gen_keypair();

                            let mut chunk_data = Vec::with_capacity(16 * 1024);

                            for previous_part in previous_parts.drain(..) {
                                chunk_data.write_all(&previous_part).unwrap();
                            }
                            if *ofs != prev_ofs {
                                chunk_data.write_all(&part[prev_ofs..*ofs]).unwrap();
                            }

                            let compress = chunk_type.should_compress();

                            let chunk_data = if compress {
                                let mut compressor = flate2::write::DeflateEncoder::new(
                                    Vec::with_capacity(chunk_data.len()), flate2::Compression::Default
                                    );

                                compressor.write_all(&chunk_data).unwrap();
                                compressor.finish().unwrap()
                            } else {
                                chunk_data
                            };

                            if chunk_type.should_encrypt() {
                                let pub_key = &options.pub_key.as_ref().unwrap();
                                let nonce = box_::Nonce::from_slice(&sha256[0..box_::NONCEBYTES]).unwrap();

                                let cipher = box_::seal(
                                    &chunk_data,
                                    &nonce,
                                    &pub_key,
                                    &ephemeral_sec
                                    );
                                chunk_file.write_all(&ephemeral_pub.0).unwrap();
                                chunk_file.write_all(&cipher).unwrap();
                            } else {
                                chunk_file.write_all(&chunk_data).unwrap();
                            }
                        } else {
                            previous_parts.clear();
                        }
                        debug_assert!(previous_parts.is_empty());

                        prev_ofs = *ofs;
                    }
                    if prev_ofs != part.len() {
                        let mut part = part;
                        previous_parts.push(part.split_off(prev_ofs))
                    }
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
    DU,
    GC,
}

impl FromStr for Command {
    type Err = ();
    fn from_str(src: &str) -> Result<Command, ()> {
        match src {
            "help" => Ok(Command::Help),
            "save" => Ok(Command::Save),
            "load" => Ok(Command::Load),
            "init" => Ok(Command::Init),
            "du" => Ok(Command::DU),
            "gc" => Ok(Command::GC),
            _ => Err(()),
        }
    }
}

fn main() {
    env_logger::init().unwrap();

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
        Command::DU => {
            if args.len() != 1 {
                printerrln!("Backup name required");
                process::exit(-1);
            }
            load_pub_key_into_options(&mut options);
            load_sec_key_into_options(&mut options);

            let digest = backup_name_to_digest(&args[0], &options);
            let size = repo_du(&digest, &options);
            println!("{}", size);
        },
        Command::GC => {
            if args.len() != 0 {
                printerrln!("Unnecessary argument");
                process::exit(-1);
            }
            load_pub_key_into_options(&mut options);

            let reachable = repo_reachable(&options);
            let all_digest = repo_list_all_digest(&options);

            for digest in all_digest.difference(&reachable) {
                println!("Unreachable: {}", digest.to_hex());
            }
            for digest in reachable.difference(&all_digest) {
                println!("Missing: {}", digest.to_hex());
            }
        }
    }
}
