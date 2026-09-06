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
handoff block, the packet JSON, the CDOM bundle (if any), every artifact and the
artifacts total, plus the ratio. The ratio is artifacts total ÷ handoff block:
what re-sending the artifacts would cost relative to the handoff that points at
them. The CDOM bundle is listed but not counted in the ratio, since the handoff
references it rather than replacing it. A packet with no artifacts gets
`no artifacts to compare against` (`"savings_ratio": null` with `--json`).
The handoff block also lists the packet's parent CIDs, so the consuming model can
walk lineage (`ket dag lineage`) without being told anything else.

```sh
cargo run -- stats <node-cid>
#                               bytes  est. tokens
# handoff block                   502          126
# packet json                     503          126
# cdom bundle                   11176         2794
#   artifact dag.rs             33614         8404
# artifacts total               33614         8404
# handoff is 67.0x smaller than re-sending the artifacts (~4 bytes/token)
```

## Enforce Handoffs
Use `catbus validate` to ensure packets meet requirements, and `catbus handoff`
to emit a prompt-friendly block. To gate an agent on a handoff, wrap its
execution with `catbus guard` or `scripts/catbus-guard.sh`.

```sh
cargo run -- validate <node-cid> --require-artifacts
cargo run -- handoff <node-cid>
catbus guard --cid <node-cid> --require-artifacts -- your-agent-command
CATBUS_CID=<node-cid> ./scripts/catbus-guard.sh -- your-agent-command
```

A bare `validate` checks that the node is a catbus packet with a summary, that
its CDOM format is known, and that every CID it references (parents, artifacts,
CDOM bundle) exists in the store. Pass `--require-artifacts` / `--require-cdom`
to also demand that those be present at all.

Both guards validate, print the block, then run the command with the context in
its environment, not just on your terminal. They differ in what they enforce:

| | `catbus guard` | `scripts/catbus-guard.sh` |
|---|---|---|
| validation | bare `validate`; `--require-artifacts` / `--require-cdom` are opt-in | always `validate --require-artifacts` (reasons go to stderr) |
| `CATBUS_CID` | set | set |
| `CATBUS_HANDOFF_FILE` | always: a private temp file (0600), removed after the command exits | always: a `mktemp` file, removed on exit |
| `CATBUS_HANDOFF` (the block) | only when the block is under 64 KiB | only when the block is under 64 KiB |
| exit status | the command's (128 + signal if it was killed) | the command's |

The 64 KiB cutoff keeps a large packet from failing at exec with "Argument list
too long" (Linux caps one environment string at 128 KiB); read
`CATBUS_HANDOFF_FILE` when `CATBUS_HANDOFF` is unset. The script needs `catbus`
on `PATH`.

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
`Cargo.toml` pins ket by tag (see ket's STACK.md for the bump ritual):
```toml
ket-cas  = { git = "https://github.com/nickjoven/ket.git", tag = "v0.3.0", package = "ket-cas" }
ket-dag  = { git = "https://github.com/nickjoven/ket.git", tag = "v0.3.0", package = "ket-dag" }
ket-sql  = { git = "https://github.com/nickjoven/ket.git", tag = "v0.3.0", package = "ket-sql" }
ket-cdom = { git = "https://github.com/nickjoven/ket.git", tag = "v0.3.0", package = "ket-cdom" }
```
