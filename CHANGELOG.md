
# v3.1.0 - 2019-01-27
### Changed

- Update `hyper-native-tls` dependency

# v3.0.0 - 2018-07-29
### Changed

- New, incompatible with v2, repo format
- Generational, incremental GC
- Internal improvements

# v2.0.0 - 2017-09-11
## Added

- End to End testing to make sure stored data is loaded correctly
- Configurable settings for most algorithms used
- CDC: fastcdc, gear
- Compression: zstd, xz2, bzip2
- Hashing: blake2
- No-Encryption mode
- Asynchronous IO architecture
- Timings (`-t`, `-tt` ... flags)
- Debugging and tracing (`-v`, `-vv`... flags)

## Changed

- Default settings
- Huge `store` performance improvements in `rdedup store` path
- rdedup can now initialize an existing but empty directory

# v1.0.2
## Added

- Support to remove multiple names in a single call in lib and command line
- Missing "changepassphrase" command to rdedup
- Improved stats to store, du, gc api calls and commands
- Changelog to repository
- Optimized GC to use an iterator of stored chunks instead of an in memory set

# v1.0.1
## Added

- Ability to change the passphrase for the private key

## Changed

- Cleaned up code by removing unnecessary code and utilizing constants as well as
running rustfmt on the code base.
- Reduced memory consumption by shrinking channels for store pipeline
- Ignore invalid files in chunk and index folders and assembling chunks list
- Deferred syncing and renaming of new chunks to optimize file io

# v1.0.0

- Started changelog, see commits for details leading up to this release
