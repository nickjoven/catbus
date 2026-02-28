use anyhow::{anyhow, Context, Result};
use clap::{Args, Parser, Subcommand};
use ket_cas::{Cid, Store as CasStore};
use ket_dag::{Dag, DagNode, NodeKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(
    name = "catbus",
    about = "CLI for agent handoffs powered by ket",
    long_about = None
)]
struct Cli {
    /// Path to .ket directory (env: KET_HOME)
    #[arg(long, global = true, env = "KET_HOME")]
    ket_home: Option<PathBuf>,

    /// Emit JSON output where available
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialize a ket store at --ket-home (default: .ket in current dir)
    Init(InitArgs),
    /// Create a handoff packet and store it in ket
    Pack(PackArgs),
    /// Retrieve a handoff packet by CID
    Unpack(UnpackArgs),
    /// List known handoff packets (best effort)
    List(ListArgs),
    /// Show a handoff packet by CID
    Show(ShowArgs),
    /// Diff two handoff packets
    Diff(DiffArgs),
    /// Garbage-collect unreferenced packet blobs (noop placeholder)
    Gc,
}

#[derive(Args, Debug)]
struct InitArgs {
    /// Skip SQL (Dolt) initialization
    #[arg(long)]
    no_sql: bool,
}

#[derive(Args, Debug)]
struct PackArgs {
    /// A short title for the handoff
    #[arg(long)]
    title: Option<String>,

    /// Required summary (keep it short)
    #[arg(long)]
    summary: String,

    /// Agent name for provenance
    #[arg(long, default_value = "human")]
    agent: String,

    /// Parent node CID(s) to link to
    #[arg(long)]
    parent: Vec<String>,

    /// Add file(s) to CAS and attach by name
    #[arg(long)]
    file: Vec<PathBuf>,

    /// Metadata key=value (repeatable)
    #[arg(long)]
    meta: Vec<String>,
}

#[derive(Args, Debug)]
struct UnpackArgs {
    /// CID of the handoff packet node
    cid: String,

    /// Optional output directory to materialize artifacts
    #[arg(long)]
    out_dir: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ListArgs {
    /// Maximum number of packets to return
    #[arg(long, default_value_t = 50)]
    limit: usize,
}

#[derive(Args, Debug)]
struct ShowArgs {
    /// CID of the handoff packet node
    cid: String,
}

#[derive(Args, Debug)]
struct DiffArgs {
    /// First packet CID
    left: String,
    /// Second packet CID
    right: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct HandoffPacket {
    version: u32,
    created_at: String,
    title: Option<String>,
    summary: String,
    artifacts: Vec<ArtifactRef>,
    meta: BTreeMap<String, String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ArtifactRef {
    name: String,
    cid: Cid,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let ket_home = ket_dir(&cli.ket_home);

    match cli.command {
        Command::Init(args) => cmd_init(&ket_home, args, cli.json),
        Command::Pack(args) => cmd_pack(&ket_home, args, cli.json),
        Command::Unpack(args) => cmd_unpack(&ket_home, args, cli.json),
        Command::List(args) => cmd_list(&ket_home, args, cli.json),
        Command::Show(args) => cmd_show(&ket_home, args, cli.json),
        Command::Diff(args) => cmd_diff(&ket_home, args, cli.json),
        Command::Gc => cmd_gc(&ket_home, cli.json),
    }
}

fn cmd_init(base: &PathBuf, args: InitArgs, json: bool) -> Result<()> {
    let cas_dir = base.join("cas");
    fs::create_dir_all(base).context("create ket home")?;
    CasStore::init(&cas_dir).context("init cas")?;

    if !args.no_sql {
        let db_path = base.join("ket.db");
        match ket_sql::DoltDb::init(&db_path) {
            Ok(_) => info!("initialized dolt at {}", db_path.display()),
            Err(e) => {
                warn!("dolt init failed: {e}");
                warn!("continuing without SQL; pass --no-sql to silence");
            }
        }
    }

    if json {
        let payload = serde_json::json!({
            "ket_home": base.display().to_string(),
            "cas": cas_dir.display().to_string(),
            "sql": if args.no_sql { "skipped" } else { "attempted" }
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("Initialized catbus at {}", base.display());
    }
    Ok(())
}

fn cmd_pack(base: &PathBuf, args: PackArgs, json: bool) -> Result<()> {
    let cas = open_cas(base)?;
    let dag = Dag::new(&cas);

    let mut artifacts = Vec::new();
    for path in &args.file {
        let name = path_to_name(path)?;
        let cid = cas.put_file(path).with_context(|| format!("put file {}", path.display()))?;
        artifacts.push(ArtifactRef { name, cid });
    }

    let mut meta = parse_meta(&args.meta)?;
    meta.insert("catbus_packet".into(), "true".into());

    let packet = HandoffPacket {
        version: 1,
        created_at: chrono::Utc::now().to_rfc3339(),
        title: args.title.clone(),
        summary: args.summary.clone(),
        artifacts,
        meta,
    };

    let packet_bytes = serde_json::to_vec_pretty(&packet)?;
    let parents: Vec<Cid> = args.parent.iter().map(|p| Cid::from(p.as_str())).collect();
    let (node_cid, content_cid) =
        dag.store_with_node(&packet_bytes, NodeKind::Context, parents, &args.agent)?;

    if json {
        let payload = serde_json::json!({
            "node_cid": node_cid,
            "content_cid": content_cid
        });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("node: {node_cid}");
        println!("content: {content_cid}");
    }
    Ok(())
}

fn cmd_unpack(base: &PathBuf, args: UnpackArgs, json: bool) -> Result<()> {
    let cas = open_cas(base)?;
    let dag = Dag::new(&cas);

    let node = dag
        .get_node(&Cid::from(args.cid.as_str()))
        .context("get node")?;
    let packet = load_packet(&cas, &node)?;

    if let Some(out_dir) = args.out_dir {
        materialize_artifacts(&cas, &packet, &out_dir)?;
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&packet)?);
    } else {
        print_packet(&args.cid, &node, &packet);
    }
    Ok(())
}

fn cmd_list(base: &PathBuf, args: ListArgs, json: bool) -> Result<()> {
    let cas = open_cas(base)?;

    let mut results = Vec::new();
    for cid in cas.list().context("list cas")? {
        if results.len() >= args.limit {
            break;
        }
        let data = match cas.get(&cid) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let node = match DagNode::from_bytes(&data) {
            Ok(n) => n,
            Err(_) => continue,
        };
        if node.get_meta("catbus_packet") == Some("true") {
            results.push((cid, node));
        }
    }

    if json {
        let items: Vec<_> = results
            .into_iter()
            .map(|(cid, node)| {
                serde_json::json!({
                    "node_cid": cid,
                    "output_cid": node.output_cid,
                    "agent": node.agent,
                    "timestamp": node.timestamp,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&items)?);
    } else if results.is_empty() {
        println!("No packets found.");
    } else {
        for (cid, node) in results {
            println!("{cid}  {}  {}", node.agent, node.timestamp);
        }
    }
    Ok(())
}

fn cmd_show(base: &PathBuf, args: ShowArgs, json: bool) -> Result<()> {
    let cas = open_cas(base)?;
    let dag = Dag::new(&cas);
    let node = dag
        .get_node(&Cid::from(args.cid.as_str()))
        .context("get node")?;
    let packet = load_packet(&cas, &node)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&packet)?);
    } else {
        print_packet(&args.cid, &node, &packet);
    }
    Ok(())
}

fn cmd_diff(base: &PathBuf, args: DiffArgs, json: bool) -> Result<()> {
    let cas = open_cas(base)?;
    let dag = Dag::new(&cas);

    let left_node = dag.get_node(&Cid::from(args.left.as_str()))?;
    let right_node = dag.get_node(&Cid::from(args.right.as_str()))?;
    let left = load_packet(&cas, &left_node)?;
    let right = load_packet(&cas, &right_node)?;

    let diff = diff_packets(&left, &right);

    if json {
        println!("{}", serde_json::to_string_pretty(&diff)?);
    } else {
        println!("Summary changed: {}", diff.summary_changed);
        if diff.title_changed {
            println!(
                "Title: {:?} -> {:?}",
                diff.left_title.as_deref(),
                diff.right_title.as_deref()
            );
        }
        if !diff.added.is_empty() {
            println!("Added artifacts:");
            for name in diff.added {
                println!("  + {name}");
            }
        }
        if !diff.removed.is_empty() {
            println!("Removed artifacts:");
            for name in diff.removed {
                println!("  - {name}");
            }
        }
        if !diff.changed.is_empty() {
            println!("Changed artifacts:");
            for name in diff.changed {
                println!("  * {name}");
            }
        }
    }
    Ok(())
}

fn cmd_gc(_base: &PathBuf, json: bool) -> Result<()> {
    if json {
        let payload = serde_json::json!({ "status": "noop", "reason": "not implemented" });
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!("gc: noop (not implemented yet)");
    }
    Ok(())
}

fn ket_dir(home: &Option<PathBuf>) -> PathBuf {
    if let Some(path) = home {
        return path.clone();
    }
    PathBuf::from(".ket")
}

fn open_cas(base: &PathBuf) -> Result<CasStore> {
    let cas_dir = base.join("cas");
    Ok(CasStore::open(cas_dir)?)
}

fn parse_meta(pairs: &[String]) -> Result<BTreeMap<String, String>> {
    let mut meta = BTreeMap::new();
    for pair in pairs {
        let mut parts = pair.splitn(2, '=');
        let key = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("invalid meta: {pair}"))?;
        let value = parts
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow!("invalid meta: {pair}"))?;
        meta.insert(key.to_string(), value.to_string());
    }
    Ok(meta)
}

fn load_packet(cas: &CasStore, node: &DagNode) -> Result<HandoffPacket> {
    let bytes = cas.get(&node.output_cid)?;
    let packet: HandoffPacket = serde_json::from_slice(&bytes)?;
    Ok(packet)
}

fn print_packet(node_cid: &str, node: &DagNode, packet: &HandoffPacket) {
    println!("node: {node_cid}");
    println!("agent: {}", node.agent);
    println!("timestamp: {}", node.timestamp);
    println!("title: {}", packet.title.as_deref().unwrap_or("(none)"));
    println!("summary: {}", packet.summary);
    if !packet.artifacts.is_empty() {
        println!("artifacts:");
        for artifact in &packet.artifacts {
            println!("  - {} {}", artifact.name, artifact.cid);
        }
    }
    if !packet.meta.is_empty() {
        println!("meta:");
        for (k, v) in &packet.meta {
            println!("  - {k}={v}");
        }
    }
}

fn path_to_name(path: &Path) -> Result<String> {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("invalid file name: {}", path.display()))?;
    Ok(name.to_string())
}

fn materialize_artifacts(cas: &CasStore, packet: &HandoffPacket, out_dir: &Path) -> Result<()> {
    fs::create_dir_all(out_dir).context("create output dir")?;
    for artifact in &packet.artifacts {
        let rel = Path::new(&artifact.name);
        if !is_safe_rel_path(rel) {
            warn!("skipping unsafe artifact name: {}", artifact.name);
            continue;
        }
        let target = out_dir.join(rel);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).context("create parent dir")?;
        }
        let bytes = cas.get(&artifact.cid)?;
        fs::write(&target, bytes).with_context(|| format!("write {}", target.display()))?;
    }
    Ok(())
}

fn is_safe_rel_path(path: &Path) -> bool {
    path.components().all(|c| match c {
        std::path::Component::Normal(_) => true,
        _ => false,
    })
}

#[derive(Debug, Serialize)]
struct PacketDiff {
    summary_changed: bool,
    title_changed: bool,
    left_title: Option<String>,
    right_title: Option<String>,
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
}

fn diff_packets(left: &HandoffPacket, right: &HandoffPacket) -> PacketDiff {
    let left_map: BTreeMap<&str, &Cid> = left
        .artifacts
        .iter()
        .map(|a| (a.name.as_str(), &a.cid))
        .collect();
    let right_map: BTreeMap<&str, &Cid> = right
        .artifacts
        .iter()
        .map(|a| (a.name.as_str(), &a.cid))
        .collect();

    let names: BTreeSet<&str> = left_map
        .keys()
        .copied()
        .chain(right_map.keys().copied())
        .collect();

    let mut added = Vec::new();
    let mut removed = Vec::new();
    let mut changed = Vec::new();

    for name in names {
        match (left_map.get(name), right_map.get(name)) {
            (None, Some(_)) => added.push(name.to_string()),
            (Some(_), None) => removed.push(name.to_string()),
            (Some(l), Some(r)) => {
                if *l != *r {
                    changed.push(name.to_string());
                }
            }
            _ => {}
        }
    }

    PacketDiff {
        summary_changed: left.summary != right.summary,
        title_changed: left.title != right.title,
        left_title: left.title.clone(),
        right_title: right.title.clone(),
        added,
        removed,
        changed,
    }
}
