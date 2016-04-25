extern crate rollsum;
extern crate crypto;
#[macro_use]
extern crate log;
extern crate rustc_serialize as serialize;
extern crate argparse;
extern crate sodiumoxide;
extern crate flate2;
#[cfg(test)]
extern crate rand;

use std::io::{Read, Write, Result, Error};

use std::{fs, mem, thread, io};
use std::path::{Path, PathBuf};
use serialize::hex::{ToHex, FromHex};
use std::collections::HashSet;

use std::sync::mpsc;

use rollsum::Engine;
use crypto::sha2;
use crypto::digest::Digest;

use sodiumoxide::crypto::box_;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum DataType {
    Index,
    Data,
}

impl DataType {
    fn should_compress(&self) -> bool {
        *self == DataType::Data
    }

    fn should_encrypt(&self) -> bool {
        *self == DataType::Data
    }
}

enum ChunkWriterMessage {
    // DataType in every Data is somewhat redundant...
    Data(Vec<u8>, Vec<Edge>, DataType, DataType),
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
        if self.bytes_chunk != 0 || self.bytes_total == 0 {
            self.edge_found(0);
        }
        mem::replace(&mut self.edges, vec!())
    }
}

fn quick_sha256(data : &[u8]) -> Vec<u8> {

    let mut sha256 = sha2::Sha256::new();
    sha256.input(&data);
    let mut sha256_digest = vec![0u8; 32];
    sha256.result(&mut sha256_digest);

    return sha256_digest
}

/// Store data, using input_f to get chunks of data
///
/// Return final digest
fn chunk_and_send_to_writer<R : Read>(tx : &mpsc::Sender<ChunkWriterMessage>,
                      mut reader : &mut R,
                      data_type : DataType,
                      ) -> Result<Vec<u8>> {
    let mut chunker = Chunker::new();

    let mut index : Vec<u8> = vec!();
    loop {
        let mut buf = vec![0u8; 16 * 1024];
        let len = try!(reader.read(&mut buf));

        if len == 0 {
            break;
        }
        buf.truncate(len);

        let edges = chunker.input(&buf[..len]);

        for &(_, ref sum) in &edges {
            index.append(&mut sum.clone());
        }
        tx.send(ChunkWriterMessage::Data(buf, edges, DataType::Data, data_type)).unwrap();
    }
    let edges = chunker.finish();

    for &(_, ref sum) in &edges {
        index.append(&mut sum.clone());
    }
    tx.send(ChunkWriterMessage::Data(vec!(), edges, DataType::Data, data_type)).unwrap();

    if index.len() > 32 {
        let digest = try!(chunk_and_send_to_writer(tx, &mut io::Cursor::new(index), DataType::Index));
        assert!(digest.len() == 32);
        let index_digest = quick_sha256(&digest);
        tx.send(ChunkWriterMessage::Data(digest.clone(), vec![(digest.len(), index_digest.clone())], DataType::Index, DataType::Index)).unwrap();
        Ok(index_digest)
    } else {
        Ok(index)
    }
}


fn pub_key_file_path(path : &Path) -> PathBuf {
    path.join("pub_key")
}

pub struct SecretKey(box_::SecretKey);

impl SecretKey {
    pub fn from_str(s : &str) -> Option<Self> {
        s.from_hex().ok()
            .and_then(|bytes| box_::SecretKey::from_slice(&bytes))
            .map(|sk| SecretKey(sk))
    }

    pub fn to_string(&self) -> String {
        (self.0).0.to_hex()
    }
}

struct CounterWriter {
    count : u64,
}

impl CounterWriter {
    fn new() -> Self {
        CounterWriter { count: 0 }
    }
}

impl Write for CounterWriter {
    fn write(&mut self,  bytes : &[u8]) -> Result<usize> {
        self.count += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> Result<()> { Ok(()) }
}

type OnDataF<'a> = Box<FnMut(&'a Repo, &[u8], DataType, Option<&'a box_::SecretKey>) -> Result<()> + 'a>;

// Can be feed Index data, will call
// on_data for every data digest
struct IndexTranslator<'a> {
    repo : &'a Repo,
    digest : Vec<u8>,
    data_type : DataType,
    sec_key : Option<&'a box_::SecretKey>,
    on_data : OnDataF<'a>,
}

impl<'a> IndexTranslator<'a>{
    fn new(
        repo : &'a Repo,
        data_type : DataType,
        on_data : OnDataF<'a>,
        sec_key : Option<&'a box_::SecretKey>
        ) -> Self {
        IndexTranslator {
            repo: repo,
            digest : vec!(),
            data_type : data_type,
            sec_key : sec_key,
            on_data : on_data,
        }
    }
}

impl<'a> Write for IndexTranslator<'a>
{
    fn write(&mut self, mut bytes : &[u8]) -> Result<usize> {
        let total_len = bytes.len();
        loop {
            let has_already = self.digest.len();
            if (has_already + bytes.len()) < 32 {
                self.digest.extend_from_slice(bytes);
                return Ok(total_len);
            }

            let needs = 32 - has_already;
            self.digest.extend_from_slice(&bytes[..needs]);
            bytes = &bytes[needs..];
            try!((self.on_data)(self.repo, &self.digest, self.data_type, self.sec_key));
            self.digest.clear();
        }
    }

    fn flush(&mut self) -> Result<()> { Ok(()) }
}

// Can be feed Index data, will
// write translated data to `writer`.
struct IndexTranslatorWriter<'a> {
    translator : IndexTranslator<'a>
}

impl<'a> IndexTranslatorWriter<'a> {
    fn new(repo : &'a Repo, writer : &'a mut Write, data_type : DataType, sec_key : Option<&'a box_::SecretKey>) -> Self {
        let on_data = move |repo : &Repo, digest : &[u8], data_type : DataType, sec_key : Option<&box_::SecretKey>| {
            repo.read_recursively(digest, writer, data_type, sec_key)
        };
        IndexTranslatorWriter {
            translator: IndexTranslator::new(
                            repo,
                            data_type,
                            Box::new(on_data),
                            sec_key)
        }
    }
}

impl<'a> Write for IndexTranslatorWriter<'a> {
    fn write(&mut self,  bytes : &[u8]) -> Result<usize> {
        self.translator.write(bytes)
    }

    fn flush(&mut self) -> Result<()> {
        self.translator.flush()
    }
}

#[derive(Clone, Debug)]
pub struct Repo {
    path : PathBuf,
    pub_key : box_::PublicKey,
}

impl Repo {
    pub fn init(repo_path : &Path) -> Result<(Repo, SecretKey)> {
        if repo_path.exists() {
            return Err(Error::new(io::ErrorKind::AlreadyExists, "repo already exists"));
        }

        try!(fs::create_dir_all(&repo_path));
        let pubkey_path = pub_key_file_path(&repo_path);

        let mut pubkey_file = try!(fs::File::create(pubkey_path));
        let (pk, sk) = box_::gen_keypair();

        try!((&mut pubkey_file as &mut Write).write_all(&pk.0.to_hex().as_bytes()));
        try!(pubkey_file.flush());

        let repo = Repo {
            path : repo_path.to_owned(),
            pub_key : pk,
        };
        Ok((repo, SecretKey(sk)))
    }

    pub fn open(repo_path : &Path) -> Result<Repo> {

        if !repo_path.exists() {
            return Err(Error::new(io::ErrorKind::NotFound, "repo not found"));
        }

        let pubkey_path = pub_key_file_path(&repo_path);
        if !pubkey_path.exists() {
            return Err(Error::new(io::ErrorKind::NotFound, "pubkey file not found"));
        }

        let mut file = try!(fs::File::open(&pubkey_path));

        let mut buf = vec!();
        try!(file.read_to_end(&mut buf));

        let pubkey_str = try!(
            std::str::from_utf8(&buf)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pubkey data invalid: not utf8"))
            );
        let pubkey_bytes = try!(
            pubkey_str.from_hex()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "pubkey data invalid: not hex"))
            );
        let pub_key = try!(
            box_::PublicKey::from_slice(&pubkey_bytes)
            .ok_or(io::Error::new(io::ErrorKind::InvalidData, "pubkey data invalid: can't convert to pubkey"))
            );

        Ok(Repo {
            path : repo_path.to_owned(),
            pub_key : pub_key,
        })
    }

    /// Accept messages on rx and writes them to chunk files
    fn chunk_writer(&self, rx : mpsc::Receiver<ChunkWriterMessage>) {
        let mut previous_parts = vec!();

        loop {
            match rx.recv().unwrap() {
                ChunkWriterMessage::Exit => {
                    assert!(previous_parts.is_empty());
                    return
                }
                ChunkWriterMessage::Data(part, edges, chunk_type, data_type) => {
                    if edges.is_empty() {
                        previous_parts.push(part)
                    } else {
                        let mut prev_ofs = 0;
                        for &(ref ofs, ref sha256) in &edges {
                            let path = self.chunk_path_by_digest(&sha256, chunk_type);
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

                                let chunk_data = if data_type.should_compress() {
                                    let mut compressor = flate2::write::DeflateEncoder::new(
                                        Vec::with_capacity(chunk_data.len()), flate2::Compression::Default
                                        );

                                    compressor.write_all(&chunk_data).unwrap();
                                    compressor.finish().unwrap()
                                } else {
                                    chunk_data
                                };

                                if data_type.should_encrypt() {
                                    let pub_key = &self.pub_key;
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

    pub fn write<R : Read>(&self, name : &str, reader : &mut R) -> Result<()> {
        let (tx, rx) = mpsc::channel();
        let self_clone = self.clone();
        let chunk_writer_join = thread::spawn(move || self_clone.chunk_writer(rx));

        let final_digest = try!(chunk_and_send_to_writer(&tx, reader, DataType::Data));

        tx.send(ChunkWriterMessage::Exit).unwrap();
        chunk_writer_join.join().unwrap();

        self.store_digest_as_backup_name(&final_digest, name)
    }

    pub fn read<W : Write>(&self, name : &str, writer: &mut W, sec_key : &SecretKey) -> Result<()> {
        let digest = try!(self.name_to_digest(name));

        self.read_recursively(
            &digest,
            writer,
            DataType::Data,
            Some(&sec_key.0)
            )
    }

    pub fn name_to_digest(&self, name : &str) -> Result<Vec<u8>> {
        let backup_path = self.path.join("backup").join(name);
        if !backup_path.exists() {
            return Err(Error::new(io::ErrorKind::NotFound, "name file not found"));
        }

        let mut file = try!(fs::File::open(&backup_path));
        let mut buf = vec!();
        try!(file.read_to_end(&mut buf));

        Ok(buf)
    }

    fn store_digest_as_backup_name(&self, digest : &[u8], name : &str) -> Result<()> {
        let backup_dir = self.path.join("backup");
        try!(fs::create_dir_all(&backup_dir));
        let backup_path = backup_dir.join(name);

        if backup_path.exists() {
            return Err(Error::new(io::ErrorKind::AlreadyExists, "name already exists"));
        }

        let mut file = try!(fs::File::create(&backup_path));

        try!(file.write_all(digest));
        Ok(())
    }

    pub fn du(&self, name : &str, sec_key : &SecretKey) -> Result<u64> {

        let digest = try!(self.name_to_digest(name));

        self.du_by_digest(&digest, sec_key)
    }


    pub fn du_by_digest(&self, digest : &[u8], sec_key : &SecretKey) -> Result<u64> {
        let mut counter = CounterWriter::new();
        try!(self.read_recursively(
            &digest,
            &mut counter,
            DataType::Data,
            Some(&sec_key.0)
            ));

        Ok(counter.count)
    }

    fn read_recursively(
        &self,
        digest : &[u8],
        writer : &mut Write,
        data_type : DataType,
        sec_key : Option<&box_::SecretKey>
        ) -> Result<()> {

        let chunk_type = try!(self.chunk_type(digest));

        match chunk_type {
            DataType::Index => {
                let mut index_data = vec!();
                try!(self.read_chunk_into(digest, DataType::Index, DataType::Index, &mut index_data, sec_key));

                assert!(index_data.len() == 32);

                let mut translator = IndexTranslatorWriter::new(self, writer, data_type, sec_key);
                try!(self.read_recursively(&index_data, &mut translator, DataType::Index,  None))
            },
            DataType::Data => {
                try!(self.read_chunk_into(digest, DataType::Data, data_type, writer, sec_key))
            },
        }
        Ok(())
    }

    fn reachable_recursively_insert(&self,
                               digest : &[u8],
                               reachable_digests : &mut HashSet<Vec<u8>>,
                               ) -> Result<()> {
        reachable_digests.insert(digest.to_owned());

        let mut writer = IndexTranslator::new(self,
                            DataType::Data,
                            Box::new(|_repo : &Repo, digest : &[u8], _data_type : DataType, _sec_key : Option<&box_::SecretKey>| {
                                reachable_digests.insert(digest.to_owned()); Ok(())
                            }),
                            None);

        self.read_recursively(
            &digest,
            &mut writer,
            DataType::Data,
            None,
            )
    }

    /// List all backups
    pub fn list_names(&self) -> Result<Vec<String>> {
        let mut ret : Vec<String> = vec!();

        let backup_dir = self.path.join("backup");
        for entry in try!(fs::read_dir(backup_dir)) {
            let entry = try!(entry);
            let name = entry.file_name().to_string_lossy().to_string();
            ret.push(name)
        }

        Ok(ret)
    }

    pub fn list_stored_chunks(&self) -> Result<HashSet<Vec<u8>>> {
        fn insert_all_digest(path : &Path, reachable : &mut HashSet<Vec<u8>>) {
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

        let mut digests = HashSet::new();
        insert_all_digest(&self.path.join("index"), &mut digests);
        insert_all_digest(&self.path.join("chunks"), &mut digests);
        Ok(digests)
    }

    /// Return all reachable chunks
    pub fn list_reachable_chunks(&self) -> Result<HashSet<Vec<u8>>> {
        let mut reachable_digests = HashSet::new();
        let all_names = try!(self.list_names());
        for name in &all_names {
            let digest = try!(self.name_to_digest(&name));
            try!(self.reachable_recursively_insert(&digest, &mut reachable_digests));
        }
        Ok(reachable_digests)
    }

    fn chunk_type(&self, digest : &[u8]) -> Result<DataType> {
        for i in &[DataType::Index, DataType::Data] {
            let file_path = self.chunk_path_by_digest(digest, *i);
            if file_path.exists() {
                return Ok(*i)
            }
        }
        Err(Error::new(io::ErrorKind::NotFound, "chunk file not found"))
    }

    fn chunk_path_by_digest(&self, digest : &[u8], chunk_type : DataType) -> PathBuf {
        let i_or_c = match chunk_type {
            DataType::Data => Path::new("chunks"),
            DataType::Index => Path::new("index"),
        };

        self.path.join(i_or_c)
            .join(&digest[0..1].to_hex())
            .join(digest[1..2].to_hex())
            .join(&digest.to_hex())
    }

    fn read_chunk_into(&self,
                        digest : &[u8],
                        chunk_type : DataType,
                        data_type : DataType,
                        writer: &mut Write,
                        sec_key : Option<&box_::SecretKey>,
                        ) -> Result<()> {
        let path = self.chunk_path_by_digest(digest, chunk_type);
        let mut file = try!(fs::File::open(path));
        let mut data = Vec::with_capacity(16 * 1024);

        let data = if data_type.should_encrypt() {
            let mut ephemeral_pub = [0; box_::PUBLICKEYBYTES];
            try!(file.read_exact(&mut ephemeral_pub));
            try!(file.read_to_end(&mut data));
            let nonce = box_::Nonce::from_slice(&digest[0..box_::NONCEBYTES]).unwrap();
            try!(
                box_::open(&data, &nonce, &box_::PublicKey(ephemeral_pub), sec_key.unwrap())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "can't decrypt chunk file"))
                )
        } else {
            try!(file.read_to_end(&mut data));
            data
        };

        let data = if data_type.should_compress() {
            let mut decompressor = flate2::write::DeflateDecoder::new(Vec::with_capacity(data.len()));

            try!(decompressor.write_all(&data));
            try!(decompressor.finish())
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
        try!(io::copy(&mut io::Cursor::new(data), writer));
        Ok(())
    }
}


#[cfg(test)]
mod tests;
