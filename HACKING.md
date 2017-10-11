# Hello!

You are more than welcome to participate in `rdedup` development.
I advise you to join `rdedup` gitter channel and say hello.

## Some basics

`rdedup` is structured as rather typical Rust project. It is split between
binary crate and a library. The library is the more interesting part.

Check out [wiki](https://github.com/dpc/rdedup/wiki) and especially
[Rust's fearless concurrency in rdedup][1] for some design information.

[1]: https://github.com/dpc/rdedup/wiki/Rust's-fearless-concurrency-in-rdedup

More design documentation should follow. `docs` subdirectory would be a place to put it.

## Exploring the code

You can generate documentation that includes private items:

```
cargo rustdoc -- --no-defaults --passes "collapse-docs" --passes "unindent-comments"
cd lib
cargo rustdoc -- --no-defaults --passes "collapse-docs" --passes "unindent-comments"
cd ..
xdg-open target/doc/rdedup/index.html
```


