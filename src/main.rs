use std::{fs, path::PathBuf, str::FromStr, sync::atomic::{AtomicU64, Ordering}, time::{Duration, Instant}};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use rayon::prelude::*;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signature, Signer, read_keypair_file},
    system_program,
    transaction::Transaction,
};
use zenore::{pow_hash, leading_zero_bits};

#[derive(Parser, Debug)]
#[command(name="zenore", version, about="zenORE – testnet PoW miner & tools")]
struct Cli {
    /// RPC url (testnet by default)
    #[arg(long, default_value="https://api.testnet.solana.com")]
    rpc: String,

    /// Program ID for the Anchor program
    #[arg(long, default_value="TeStoRe111111111111111111111111111111111111")]
    program: String,

    /// Path to keypair file
    #[arg(long, default_value="~/.config/solana/id.json")]
    keypair: String,

    /// Optional path to a newline-delimited list of keypair files (team mining)
    #[arg(long)]
    keypair_list: Option<PathBuf>,

    /// Number of threads to use (0 = all cores)
    #[arg(long, default_value_t=0)]
    threads: usize,

    /// Show metrics while mining
    #[arg(long, default_value_t=true)]
    metrics: bool,

    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Start mining on testnet
    Mine {
        /// Difficulty in leading zero bits (default: 20 for testnet)
        #[arg(long, default_value_t=20)]
        difficulty: u32,
        /// Optional static seed as base58 (otherwise derived from program id)
        #[arg(long)]
        seed_b58: Option<String>,
    },

    /// Submit a single proof (nonce) for debugging
    Submit {
        #[arg(long)]
        nonce: u64,
        #[arg(long, default_value_t=20)]
        difficulty: u32,
        #[arg(long)]
        seed_b58: Option<String>,
    },
}

fn expand_tilde(path: &str) -> String {
    if let Some(stripped) = path.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(stripped).to_string_lossy().to_string();
        }
    }
    path.to_string()
}

fn read_keypairs(cli: &Cli) -> Result<Vec<Keypair>> {
    if let Some(list_path) = &cli.keypair_list {
        let txt = fs::read_to_string(list_path)?;
        let mut v = vec![];
        for line in txt.lines() {
            let p = expand_tilde(line.trim());
            if p.is_empty() { continue; }
            v.push(read_keypair_file(p).map_err(|e| anyhow!("Failed reading {}: {}", line, e))?);
        }
        Ok(v)
    } else {
        let p = expand_tilde(&cli.keypair);
        Ok(vec![read_keypair_file(p)?])
    }
}

fn program_pubkey(cli: &Cli) -> Result<Pubkey> {
    Ok(Pubkey::from_str(&cli.program)?)
}

fn seed_from(cli: &Cli) -> [u8; 32] {
    if let Some(b58) = &cli.seed_b58() {
        let mut out = [0u8; 32];
        let decoded = bs58::decode(b58).into_vec().unwrap_or_default();
        for (i, b) in decoded.iter().take(32).enumerate() { out[i] = *b; }
        return out;
    }
    // Default: derive from program id for testnet reproducibility
    let mut out = [0u8; 32];
    let pid = bs58::decode(&cli.program).into_vec().unwrap_or_default();
    for (i, b) in pid.iter().take(32).enumerate() { out[i] = *b; }
    out
}

impl Cli {
    fn seed_b58(&self) -> Option<String> {
        match &self.cmd {
            Command::Mine { seed_b58, .. } => seed_b58.clone(),
            Command::Submit { seed_b58, .. } => seed_b58.clone(),
        }
    }
}

fn build_client(rpc: &str) -> RpcClient {
    RpcClient::new_with_commitment(rpc.to_string(), CommitmentConfig::confirmed())
}

fn submit_tx(
    client: &RpcClient,
    kp: &Keypair,
    program_id: Pubkey,
    miner_pubkey: Pubkey,
    nonce: u64,
) -> Result<Signature> {
    let (miner_pda, _bump) = Pubkey::find_program_address(&[b"miner", miner_pubkey.as_ref()], &program_id);
    let (config_pda, _cb) = Pubkey::find_program_address(&[b"config"], &program_id);
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(miner_pda, false),
            AccountMeta::new_readonly(config_pda, false),
            AccountMeta::new(miner_pubkey, true),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: {
            // Anchor discriminator for "submit_proof" + nonce (LE)
            let disc = {
                use sha2::{Digest, Sha256};
                let mut h = Sha256::new();
                h.update(b"global:submit_proof");
                let d = h.finalize();
                let mut a = vec![0u8; 8];
                a.copy_from_slice(&d[..8]);
                a
            };
            let mut data = disc;
            data.extend_from_slice(&nonce.to_le_bytes());
            data
        },
    };

    let bh = client.get_latest_blockhash()?;
    let msg = Message::new(&[ix], Some(&kp.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);
    tx.sign(&[kp], bh);
    let sig = client.send_and_confirm_transaction(&tx)?;
    Ok(sig)
}

fn mine_with_key(
    client: &RpcClient,
    program_id: Pubkey,
    keypair: &Keypair,
    difficulty: u32,
    seed: [u8;32],
    metrics: bool,
) -> Result<()> {
    let miner_pk = keypair.pubkey();
    let mut rng = rand::thread_rng();
    let counter = AtomicU64::new(0);
    let start = std::time::Instant::now();
    let pb = if metrics {
        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::with_template("{spinner} hashes: {pos}  rate: {per_sec}/s  elapsed: {elapsed}").unwrap());
        pb.enable_steady_tick(Duration::from_millis(120));
        Some(pb)
    } else { None };

    loop {
        let batch: Vec<u64> = (0..10000).map(|_| rng.gen()).collect();
        let found = batch.par_iter().find_map_any(|nonce| {
            let pk32 = miner_pk.to_bytes();
            let h = pow_hash(&seed, &pk32, *nonce);
            let lz = leading_zero_bits(&h);
            if lz >= difficulty {
                Some(*nonce)
            } else {
                counter.fetch_add(1, Ordering::Relaxed);
                None
            }
        });
        if let Some(nonce) = found {
            if let Some(pb) = &pb {
                let c = counter.load(Ordering::Relaxed);
                pb.set_position(c);
            }
            match submit_tx(client, keypair, program_id, miner_pk, nonce) {
                Ok(sig) => {
                    println!("\n✅ proof accepted: nonce={} sig={}", nonce, sig);
                },
                Err(e) => {
                    eprintln!("\n❌ submit failed: {e}");
                }
            }
        } else if let Some(pb) = &pb {
            let c = counter.load(Ordering::Relaxed);
            let secs = start.elapsed().as_secs_f64();
            pb.set_position(c);
            if secs > 0.0 {
                pb.set_message(format!("~{:.2} MH", c as f64 / 1_000_000.0));
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let client = build_client(&cli.rpc);
    let program_id = program_pubkey(&cli)?;
    let mut keys = read_keypairs(&cli)?;
    if cli.threads > 0 {
        std::env::set_var("RAYON_NUM_THREADS", cli.threads.to_string());
    }

    match &cli.cmd {
        Command::Mine { difficulty, .. } => {
            let seed = seed_from(&cli);
            if keys.len() == 1 {
                mine_with_key(&client, program_id, &keys[0], *difficulty, seed, cli.metrics)?;
            } else {
                let handles: Vec<_> = keys
                    .drain(..)
                    .map(|kp| {
                        let client = build_client(&cli.rpc);
                        let pid = program_id;
                        let sd = seed;
                        let diff = *difficulty;
                        tokio::spawn(async move {
                            let _ = mine_with_key(&client, pid, &kp, diff, sd, true);
                        })
                    }).collect();
                for h in handles { let _ = h.await; }
            }
        }
        Command::Submit { nonce, difficulty, .. } => {
            let seed = seed_from(&cli);
            let kp = &keys[0];
            let pk32 = kp.pubkey().to_bytes();
            let h = pow_hash(&seed, &pk32, *nonce);
            let lz = leading_zero_bits(&h);
            if lz < *difficulty {
                eprintln!("⚠️  This nonce does NOT meet difficulty (has {} leading zero bits, need >= {})", lz, difficulty);
            }
            let sig = submit_tx(&client, &kp, program_id, kp.pubkey(), *nonce)?;
            println!("Submitted proof. sig={sig} (lzbits={lz})");
        }
    }

    Ok(())
}
