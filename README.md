<!-- README.md is auto-generated from README.tpl with `cargo readme` -->

<p align="center">
  <a href="https://travis-ci.org/dpc/rdedup">
      <img src="https://img.shields.io/travis/dpc/rdedup/master.svg?style=flat-square" alt="Travis CI Build Status">
  </a>
  <a href="https://crates.io/crates/rdedup">
      <img src="http://meritbadge.herokuapp.com/rdedup?style=flat-square" alt="crates.io">
  </a>
  <a href="https://gitter.im/dpc/rdedup">
      <img src="https://img.shields.io/badge/GITTER-join%20chat-green.svg?style=flat-square" alt="Gitter Chat">
  </a>
  <br>
</p>

# rdedup

See [wiki](https://github.com/dpc/rdedup/wiki) for current project status.

`rdedup` is the data deduplication engine and backup software

`rdedup` is written in Rust and provides both command line tool
and library API (`rdedup-lib`).

`rdedup` is generally similar to existing software like
 duplicacy, restic, attic, duplicity, zbackup, etc.

 ## Features

 * support for public-key encryption (the only tool like that I'm aware of,
   and primary reason `rdedup` was created)
 * flat-file synchronization friendly (Dropbox/syncthing, rsync, rclone)
   * cloud backends are WIP
 * incremental, scalable garbage collection
 * variety of supported algorithms:
   * chunking: bup, gear, fastcdc
   * hashing: blake2b, sha256
   * compression: deflate, xz2, bzip2, zstd, none
   * encryption: curve25519, none
   * very easy to add new ones
   * check `rdedup init --help` output for up-to-date list
 * extreme performance and parallelism - see
   [Rust fearless concurrency in `rdedup`](https://dpc.pw/blog/2017/04/rusts-fearless-concurrency-in-rdedup/)
 * attention to reliability (eg. `rdedup` is using `fsync` + `rename`
   to avoid data corruption even in case of hardware crash)

### Strong parts

It's written in Rust. It's a modern language, that is actually really nice
to use.
Rust makes it easy to have a very robust and fast software.

The author is a nice person, welcomes contributions, and helps users. Or at
least he's trying... :)

### Shortcomings and missing features:

`rdedup` currently does not implement own backup/restore functionality (own
directory traversal), and because of that it's typically paired with `tar`
or `rdup` tools. Built-in directory traversal could improve deduplication
ratio for workloads with many small, frequently changing files.

Cloud storage integrations are missing. The architecture to support it is
mostly implemented, but the actual backends are not.

### Installation

If you have `cargo` installed:

```rust
cargo install rdedup
```

If not, I highly recommend installing [rustup][rustup] (think `pip`, `npm`
but for Rust)

If you're interested in running `rdedup` with maximum possible performance,
try:

```rust
RUSTFLAGS="-C target-cpu=native" cargo install rdedup
```

[rustup]: https://www.rustup.rs/

In case of troubles, check [rdedup building issues][building-issues] or
report a new one (sorry)!

[building-issues]: http://bit.ly/2ypLPtJ

### Usage

See `rdedup -h` for help.

Rdedup always operates on a *repo*, that you provide as an argument
(eg. `--dir <DIR>`), or via environment variable (eg. `RDEDUP_DIR`).

Supported commands:

* `rdedup init` - create a *repo* directory with keypair used for
encryption.
* `rdedup ls` - list all stored names.
* `rdedup store <name>` - store data read from standard input under given
*name*.
* `rdedup load <name>` - load data stored under given *name* and write it
on standard output
* `rdedup rm <name>` - remove the given *name*. This by itself does not
remove the data.
* `rdedup gc` - remove any no longer reachable data

Check `rdedup init --help` for repository configuration options.

In combination with [rdup][rdup] this can be used to store and restore your
backup like this:

```rust
rdup -x /dev/null "$HOME" | rdedup store home
rdedup load home | rdup-up "$HOME.restored"
```

`rdedup` is data agnostic, so formats like `tar`, `cpio` and other will
work,
but to get benefits of deduplication, archive format should not be
compressed
or encrypted already.

## `RDEDUP_PASSPHRASE` environment variable

While it's not advised, if `RDEDUP_PASSPHRASE` is defined, it will be used
instead of interactively asking user for password.

[bup]: https://github.com/bup/bup/
[rdup]: https://github.com/miekg/rdup
[syncthing]: https://syncthing.net
[zbackup]: http://zbackup.org/
[zbackup-issue]: https://github.com/zbackup/zbackup/issues/109
[ddar]: https://github.com/basak/ddar/
[ddar-issue]: https://github.com/basak/ddar/issues/10

# License

rdedup is licensed under: MPL-2.0
