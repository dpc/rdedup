# rdedup - data deduplication with compression and public key encryption

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


## Introduction


`rdedup` is a tool providing data deduplication with compression and public key
encryption written in Rust programming language. The primary use case is storing
deduplicated and encrypted backups.

**Warning: beta quality software ahead** - I use rdedup personally for a long while
and it works well and noone reported any problems. I would really appreciate feedback
from people using `rdedup`.

### My use case

I use [rdup][rdup] to create backup archive, and [syncthing][syncthing] to
duplicate my backups over a lot of systems. Some of them are more trusted
(desktops with disk-level encryption, firewalls, stored in the vault etc.), and
some not so much (semi-personal laptops, phones etc.)

As my backups tend to contain a lot of shared data (even backups taken on
different systems), it makes perfect sense to deduplicate them.

However I don't want one of my hosts being physically or
remotely compromised, give access to data inside all my backups from all my
systems.  Existing deduplication software like [ddar][ddar] or
[zbackup][zbackup] provide encryption, but only symmetrical ([zbackup
issue][zbackup-issue], [ddar issue][ddar-issue]) which means you have to share
the same key on all your hosts and one compromised system gives access to all your
backup data.

To fill the missing piece in my master backup plan, I've decided to write it
myself using my beloved Rust programming language.

## How it works

`rdedup` works very much like [zbackup][zbackup] and other deduplication software
with a little twist:

* Thanks to public key cryptography, secure passpharse is required only
  when restoring data, while adding and deduplicating new data does not.
* Everything is synchronization friendly. Dropbox, Syncthing and similar
  should work fine for data synchronization.

When storing data, `rdedup` will split it into smaller pieces - *chunks* - using
rolling sum, and store each *chunk* under unique id (sha256 *digest*) in a
special format directory: *repo*. Then the whole backup will be described as
*index*: a list of *digests*.

*Index* will be stored internally just like the data itself. Recursively, this
reduces each backup to one unique *digest*, which is saved under given *name*.

When restoring data, `rdedup` will read the *index*, then restore the data, reading
each *chunk* listed in it.

Thanks to rolling sum chunking scheme, when saving frequently similar data, a
lot of common *chunks* will be reused, saving space.

What makes `rdedup` unique, is that every time new *repo* directory is created,
a pair of keys (public and secret) is generated. Public key is saved in the
storage directory in plain text, while secret key is encrypted with key
derived from a passphrase.

Every time `rdedup` saves a new chunk file, its data is encrypted using public
key so it can only be decrypted using the corresponding secret key. This way
new data can always be added, with full deduplication, while only restoring
data requires providing the passphrase to unlock the private key.

Nice little detail: `rdedup` supports removing old *names* and no longer
needed chunks (garbage collection) without passphrase. Only the data chunks
are encrypted, making operations like garbage collection safe even on untrusted
machines.

### Technical Details

* [bup][bup] methods of splitting files into chunks is used
* sha256 sum of chunk data is used as digest id
* [libsodium][libsodium]'s [sealed boxes][libsodium-sealed-boxes-doc] are used for encryption/decryption:
  * ephemeral keys are used for sealing
  * chunk digest is used as nonce
* private key is encrypted using [libsodium][libsodium] `crypto secretbox`
  using random nonce, and key derived from passphrase using password hashing
  and random salt

## Installation

If you have `cargo` installed:

```
cargo install rdedup
```

If not, I highly recommend installing [rustup][rustup] (think `pip`, `npm` for Rust, only better)

[rustup]: https://www.rustup.rs/

In case of troubles, check [rdedup building issues](https://github.com/dpc/rdedup/issues?q=is%3Aissue+is%3Aclosed+label%3Abuilding)
or report a new one!

## Usage

See `rdedup -h` for help.

Supported commands:

* `rdedup init` - create a *repo* directory with keypair used for encryption.
* `rdedup ls` - list all stored names.
* `rdedup store <name>` - store data read from standard input under given *name*.
* `rdedup load <name>` - load data stored under given *name* and write it on standard output
* `rdedup rm <name>` - remove the given *name*. This by itself does not remove the data.
* `rdedup gc` - remove any no longer reachable data


In combination with [rdup][rdup] this can be used to store and restore your backup like this:

```
rdup -x /dev/null "$HOME" | rdedup store home
rdedup load home | rdup-up "$HOME.restored"
```

Rdedup is data agnostic, so formats like `tar`, `cpio` and other will work,
but to get benefits of deduplication, archive format should not be compressed
or encrypted already.

[bup]: https://github.com/bup/bup/
[rdup]: https://github.com/miekg/rdup
[syncthing]: https://syncthing.net
[zbackup]: http://zbackup.org/
[zbackup-issue]: https://github.com/zbackup/zbackup/issues/109
[ddar]: https://github.com/basak/ddar/
[ddar-issue]: https://github.com/basak/ddar/issues/10
[libsodium-sealed-boxes-doc]: https://download.libsodium.org/doc/public-key_cryptography/sealed_boxes.html
[libsodium]: https://github.com/jedisct1/libsodium

# License

MPL-2
