# catbus handoff runbook

Tested end-to-end 2026-05-18. This is the operational guide for moving a
content-addressed handoff packet from a producer to a downstream receiver.

## Build & install (non-git, local ket)

`Cargo.toml` pins the ket crates by **path**, not git:

```toml
ket-cas  = { path = "../ket/ket-cas" }
ket-dag  = { path = "../ket/ket-dag" }
ket-sql  = { path = "../ket/ket-sql" }
ket-cdom = { path = "../ket/ket-cdom" }
```

So catbus only builds when the `ket` workspace is a sibling directory
(always true in this sandbox). Network-free build, tracks in-tree ket.

```sh
cd /home/njoven/AI/sandbox/catbus
cargo build --release
ln -s "$PWD/target/release/catbus" ~/.local/bin/catbus   # PATH parity with ket
```

`catbus` and `ket` are both symlinked into `~/.local/bin/`.

## How a packet is stored (and the one gotcha)

`catbus pack` writes the packet **node** into the ket DAG and stores any
attached files as **loose CAS blobs referenced by CID inside the packet** —
they are NOT DAG ancestors. Consequence:

> `ket export <node>` walks DAG ancestors only, so it carries the handoff
> *text* but NOT attached artifact file contents. A fresh receiver's
> `catbus unpack` then fails with `Content not found` until the artifact
> CAS blobs are shipped separately.

This gotcha does **not** apply when packing with no `--file` (pure-context
packet) or when the whole `.ket` travels (git clone / whole-substrate tar).

## Decision: do you transfer bytes at all?

| Receiver is… | Transfer | Action |
|---|---|---|
| Another agent/shell on the **same machine** | None | `catbus --ket-home <store>/.ket handoff <CID>` |
| Different dir/store, **same machine** | Local copy | `ket import bundle.json` + untar `cas.tgz`, or just point `--ket-home` at the store |
| **Different machine**, repo is git-tracked | **Use git** | Push the substrate; receiver pulls. Carries all CAS blobs. Idiomatic (federation model). |
| Different machine, no shared remote | scp/rsync | Ship `handoff.tgz` (whole `.ket`) — simplest, carries everything |

Sunshine/Moonlight is a pixel+input stream, **not** a file channel — you
never transfer "through" it. It only proves a network path exists.

## Producer (paste-safe)

`--file` is OPTIONAL (repeat for multiple, or omit). `$NODE` is auto-captured.

```sh
KH=/home/njoven/AI/sandbox/harmonics/.ket

NODE=$(catbus --ket-home "$KH" pack \
  --title "task X" \
  --summary "API stable; next: wire solve() into CLI" \
  --agent claude --json \
  | python3 -c "import sys,json;print(json.load(sys.stdin)['node_cid'])")
echo "NODE=$NODE"            # the CID you give the receiver

# Transport A — git (preferred when the repo has a remote):
git -C /home/njoven/AI/sandbox/harmonics add .ket
git -C /home/njoven/AI/sandbox/harmonics commit -m "handoff packet $NODE"
git -C /home/njoven/AI/sandbox/harmonics push          # ask before pushing

# Transport B — whole substrate tarball (no shared remote):
tar czf handoff.tgz -C /home/njoven/AI/sandbox/harmonics .ket

# Transport C — surgical subgraph (NOTE the artifact-blob gotcha above):
ket --home "$KH" export "$NODE" -o bundle.json
tar czf cas.tgz -C "$KH" cas                            # the piece export drops
```

`harmonics/.ket` is git-tracked — always commit the packet so it isn't left
as uncommitted drift.

## Receiver (paste-safe)

`NODE` is a string from the other machine — set it once, the rest is literal.
Receiver prerequisite: the `catbus` binary on that box (build it the same
non-git way), or read the packet JSON directly from `.ket/cas/<CID>`.

```sh
NODE=<paste-the-cid-string>

# from git:
git clone <repo-url> && cd <repo> && git checkout <branch>
catbus --ket-home .ket handoff "$NODE"

# from handoff.tgz:
mkdir -p recv && tar xzf handoff.tgz -C recv
catbus --ket-home recv/.ket handoff "$NODE"
catbus --ket-home recv/.ket unpack  "$NODE" --out-dir ./in

# from bundle.json + cas.tgz:
KH=./.ket
ket --home "$KH" init
ket --home "$KH" import bundle.json
tar xzf cas.tgz -C "$KH"                                 # restores artifact blobs
catbus --ket-home "$KH" handoff "$NODE"
catbus --ket-home "$KH" unpack  "$NODE" --out-dir ./in

# validate before trusting:
catbus --ket-home "$KH" validate "$NODE" --require-artifacts   # -> valid

# chain the reply handoff:
catbus --ket-home "$KH" pack --parent "$NODE" --summary "did X; next: Y" --agent claude
```

## Common paste errors

- `put file work.py … No such file` — `--file` arg pointed at a nonexistent
  path. It's optional; supply a real path or drop the flag.
- `zsh: no such file or directory: NODE` — `<NODE>` pasted literally. It is a
  fill-in marker; use the captured `$NODE` (producer) or `NODE=<cid>` (receiver).
