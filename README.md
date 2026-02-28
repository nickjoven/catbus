# catbus

CLI for multi-model handoffs with token limits, powered by `ket`.

## Why
If you work with multiple models, you pay a tax every time you re-explain context.
`catbus` stores compact, content-addressed handoff packets so you can reuse the
exact same context across models without recompute.

## What You Get
- Immutable handoff packets with provenance (linked in the ket DAG)
- Model-agnostic context transfer via CIDs
- Optional CDOM symbol summaries to reduce prompt size

## Quickstart
```sh
cargo run -- init
cargo run -- pack --summary "handoff summary" --file path/to/file.rs
cargo run -- list
cargo run -- show <node-cid>
cargo run -- unpack <node-cid> --out-dir ./out
cargo run -- diff <node-cid> <node-cid>
```

## Example Workflow
1. Model A explores and summarizes the task.
1. Store the handoff once, rehydrate it anywhere.
1. Model B continues with exact context, no re-upload.

```sh
# Model A: initial analysis
cargo run -- pack \
  --summary "API surface stabilized, next: implement X" \
  --file src/lib.rs \
  --cdom

# Model B: retrieve handoff
cargo run -- show <node-cid>
cargo run -- unpack <node-cid> --out-dir ./handoff
```

## CDOM (optional)
Use `--cdom` to generate a minimal CDOM bundle from provided files/dirs.
The bundle is stored as a separate CAS blob and referenced from the packet.

```sh
cargo run -- pack --summary "handoff summary" --file src/lib.rs --cdom
cargo run -- pack --summary "handoff summary" --cdom-path src/
```

## GitHub Pages Example
The example workflow is also published on GitHub Pages:
```text
https://nickjoven.github.io/catbus/
```

## ket dependency
`Cargo.toml` uses the remote ket repo:
```toml
ket-cas = { git = "https://github.com/nickjoven/ket", package = "ket-cas" }
ket-dag = { git = "https://github.com/nickjoven/ket", package = "ket-dag" }
ket-sql = { git = "https://github.com/nickjoven/ket", package = "ket-sql" }
ket-cdom = { git = "https://github.com/nickjoven/ket", package = "ket-cdom" }
```
