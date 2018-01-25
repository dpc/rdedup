Very crude `rdedup` tester.

This is a program that tests `rdedup` binary
by running it randomly, writing, reading, removing, GCing
etc. data and checking if everything seems in order.

How to use:

```
cd <main_rdedup_src_dir>
cargo build --release; and ./target/debug/tester 20000
```

Let it run for a while, and check if it doesn't complain.
