# catbus

**Purpose:** CLI tool for multi-model context handoffs — store compact, content-addressed handoff packets so you can transfer exact context between LLMs without recompute. Built on [ket](https://github.com/nickjoven/ket).

---

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
cargo run -- stats <node-cid>      # bytes + est. tokens: handoff vs. full artifacts
```

For the full story — context, tokens, retrieval, generation, with real output —
see [the ket + catbus demo](https://github.com/nickjoven/ket/blob/main/docs/DEMO.md).

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

## How Much It Saves
`catbus stats` prints bytes and an estimated token count (~4 bytes/token) for the
handoff block, the packet, the CDOM bundle and every artifact, plus the ratio.
The handoff block also lists the packet's parent CIDs, so the consuming model can
walk lineage (`ket dag lineage`) without being told anything else.

```sh
cargo run -- stats <node-cid>
#                               bytes  est. tokens
# handoff block                   619          155
# cdom bundle                   10801         2701
#   artifact dag.rs             31675         7919
# handoff is 51.2x smaller than re-sending the artifacts (~4 bytes/token)
```

## Enforce Handoffs
Use `catbus validate` to ensure packets meet requirements, and `catbus handoff`
to emit a prompt-friendly block. For strict enforcement, wrap agent execution
with `scripts/catbus-guard.sh`.

```sh
cargo run -- validate <node-cid> --require-artifacts
cargo run -- handoff <node-cid>
CATBUS_CID=<node-cid> ./scripts/catbus-guard.sh -- your-agent-command
catbus guard --cid <node-cid> -- your-agent-command
```

## Paste Into Agent Instructions
```text
You MUST consume the provided catbus handoff CID before starting work.
Do not recompute or re-derive context already in the handoff.
If required information is missing, request an updated handoff packet.
At the end of your work, produce a new catbus handoff packet.
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
