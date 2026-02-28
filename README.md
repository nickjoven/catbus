# catbus

CLI for agent handoffs powered by `ket`.

## Goal
Reduce recompute across multi-agent workflows by storing handoff packets in ket's
content-addressed store and linking them in the DAG for provenance.

## Status
Early scaffold. Commands are functional for basic packet storage and retrieval.

## Usage
```sh
cargo run -- init
cargo run -- pack --summary "handoff summary" --file path/to/file.rs
cargo run -- list
cargo run -- show <node-cid>
cargo run -- unpack <node-cid> --out-dir ./out
cargo run -- diff <node-cid> <node-cid>
```

## Switching ket deps to git
Currently `Cargo.toml` uses local path dependencies:
```toml
ket-cas = { path = "../ket/ket-cas" }
ket-dag = { path = "../ket/ket-dag" }
ket-sql = { path = "../ket/ket-sql" }
```

To switch to git, replace with something like:
```toml
ket-cas = { git = "https://github.com/<org>/ket", package = "ket-cas" }
ket-dag = { git = "https://github.com/<org>/ket", package = "ket-dag" }
ket-sql = { git = "https://github.com/<org>/ket", package = "ket-sql" }
```
