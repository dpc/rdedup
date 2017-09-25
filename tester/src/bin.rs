extern crate digest;
extern crate hex;
extern crate rand;
extern crate sha2;

use std::process::{Command, Stdio};
use std::io::Write;
use std::default::Default;
use std::collections::HashMap;
use std::io;
use rand::{thread_rng, Rng};
use digest::{FixedOutput, Input};
use hex::ToHex;

/// Generate data that has plenty of redundancy
struct ExampleDataGen {
    a: Vec<u8>,
    b: Vec<u8>,
    c: Vec<u8>,
}

impl ExampleDataGen {
    fn new() -> Self {
        ExampleDataGen {
            a: rand_data(1024),
            b: rand_data(1024),
            c: rand_data(1024),
        }
    }

    fn gen(&self, size_kb: usize) -> Vec<u8> {
        let mut res = vec![];
        for _ in 0..size_kb {
            res.extend_from_slice(match thread_rng().gen_range(0, 3) {
                0 => &self.a,
                1 => &self.b,
                2 => &self.c,
                _ => panic!("WTF?"),
            })
        }

        res
    }
}

fn rand_data(len: usize) -> Vec<u8> {
    rand::weak_rng().gen_iter().take(len).collect::<Vec<u8>>()
}

fn simple_digest(data: &[u8]) -> Vec<u8> {
    let mut sha256 = sha2::Sha256::default();

    sha256.process(data);

    let mut vec_result = vec![0u8; 32];
    vec_result.copy_from_slice(&sha256.fixed_result());

    vec_result
}

fn run_rdedup_with(args: &[&str], input: Vec<u8>) -> std::process::Output {
    let mut child = Command::new("target/release/rdedup")
        .args(args)
        .env("RDEDUP_PASSPHRASE", "foobar!@%!@#$!")
        .env("RDEDUP_DIR", "/tmp/rdedup-tester")
        .env("RUST_BACKTRACE", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::piped())
        .spawn()
        .expect("failed to execute child");


    {
        // limited borrow of stdin
        let stdin = child.stdin.as_mut().expect("failed to get stdin");
        stdin.write_all(&input).expect("failed to write to stdin");
    }

    let out = child.wait_with_output().expect("failed to wait on child");

    if !out.status.success() {
        eprintln!("stdout:");
        std::io::stderr().write_all(&out.stdout).unwrap();
        eprintln!("stderr:");
        std::io::stderr().write_all(&out.stderr).unwrap();
    }

    assert!(out.status.success());

    out
}

#[derive(Clone)]
struct NameStats {
    digest: String,
    len: usize,
}

struct TestState {
    names: HashMap<String, NameStats>,
    data_gen: ExampleDataGen,
}

impl TestState {
    fn new() -> Self {
        TestState {
            names: Default::default(),
            data_gen: ExampleDataGen::new(),
        }
    }

    fn init(&mut self) -> io::Result<()> {
        eprintln!("Creating new repo");
        let _out = run_rdedup_with(
            &vec!["init", "--pwhash", "weak", "--chunk-size", "2K"],
            vec![],
        );

        Ok(())
    }

    fn store_one(&mut self) -> io::Result<()> {
        let data = self.data_gen.gen(16 * 1024);

        let name = NameStats {
            digest: simple_digest(&data).to_hex(),
            len: data.len(),
        };
        eprintln!("Storing name: {} of size {}", name.digest, name.len);
        let _out = run_rdedup_with(&vec!["store", &name.digest], data);
        self.names.insert(name.digest.clone(), name);

        Ok(())
    }


    fn select_random_name(&self) -> NameStats {

        let random_name = rand::sample(&mut thread_rng(), self.names.keys(), 1)[0];

        self.names.get(random_name).unwrap().clone()
    }

    fn load_one(&mut self) -> io::Result<()> {
        if self.names.is_empty() {
            return Ok(())
        }
        let name = self.select_random_name();

        eprintln!("Read name: {}", name.digest);
        let out = run_rdedup_with(&vec!["load", &name.digest], vec![]);
        assert_eq!(out.stdout.len(), name.len);
        let digest = simple_digest(&out.stdout).to_hex();
        assert_eq!(digest, name.digest);

        Ok(())
    }

    fn verify_one(&mut self) -> io::Result<()> {
        if self.names.is_empty() {
            return Ok(())
        }
        let name = self.select_random_name();

        eprintln!("Verify name: {}", name.digest);
        let _out = run_rdedup_with(&vec!["verify", &name.digest], vec![]);

        Ok(())
    }



    fn rm_one(&mut self) -> io::Result<()> {
        if self.names.is_empty() {
            return Ok(())
        }
        let name = self.select_random_name();

        eprintln!("Remove name: {}", name.digest);
        let _out = run_rdedup_with(&vec!["rm", &name.digest], vec![]);

        self.names.remove(&name.digest);
        Ok(())
    }


    fn gc(&mut self) -> io::Result<()> {
        eprintln!("GC");
        let grace = thread_rng().gen_range(0, 20);
        let _out = run_rdedup_with(&vec!["gc", "--grace", &grace.to_string()], vec![]);
        Ok(())
    }
}

fn main() {
    let mut test = TestState::new();
    eprintln!("Ctrl+C to stop");
    test.init().unwrap();
    loop {
        if test.names.len() > 100 {
            test.rm_one().unwrap()
        }

        match  thread_rng().gen_range(0, 5) {
            0 => test.store_one().unwrap(),
            1 => test.load_one().unwrap(),
            2 => test.rm_one().unwrap(),
            3 => test.verify_one().unwrap(),
            4 => test.gc().unwrap(),
            _ => panic!(),
        }
    }
}
