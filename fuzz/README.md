# Parser fuzzing

The fuzz workspace exercises the pure CLI rule, journald JSON and syslog parsers.
The rule target checks that accepted rules round-trip through their canonical CLI
arguments. The syslog target checks that the returned message is a suffix of the
input and the program name is nonempty. The journal target passes arbitrary bytes
to the production decoder and checks for panics and sanitizer errors.

Install a C++ compiler and the nightly Rust toolchain, then run from the repo root.

```bash
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --version 0.12.0 --locked
for target in rules journal syslog; do
    mkdir -p "fuzz/corpus/$target"
    cargo +nightly fuzz run "$target" "fuzz/corpus/$target" "fuzz/seeds/$target" \
        -- -max_total_time=60 -max_len=16384 || break
done
```

The first corpus directory collects new inputs. The second contains the checked-in
seeds. Rule seeds use NUL between arguments. Logs use synthetic messages and
documentation addresses. See the [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz/tutorial.html)
for libFuzzer options and corpus handling.
