#[cfg(test)]
#[macro_use]
extern crate hex_literal;

pub mod api;
pub mod block;
pub mod blockchain;
pub mod crypto;
pub mod miner;
pub mod network;
pub mod transaction;
pub mod visualization;
pub mod mempool;
pub mod transaction_generator;

use clap::clap_app;
use crossbeam::channel;
use log::{error, info};
use api::Server as ApiServer;
use network::{server, worker};
use std::net;
use std::process;
use std::thread;
use std::time;
use std::sync::{Arc, Mutex};
use crate::blockchain::Blockchain;
use crate::crypto::hash::Hashable;
use crate::visualization::Visualizer;
use crate::mempool::Mempool;
use crate::transaction_generator::TransactionGenerator;

fn main() {
    // parse command line arguments
    let matches = clap_app!(Bitcoin =>
     (version: "0.1")
     (about: "Bitcoin client")
     (@arg verbose: -v ... "Increases the verbosity of logging")
     (@arg peer_addr: --p2p [ADDR] default_value("127.0.0.1:6000") "Sets the IP address and the port of the P2P server")
     (@arg api_addr: --api [ADDR] default_value("127.0.0.1:7000") "Sets the IP address and the port of the API server")
     (@arg known_peer: -c --connect ... [PEER] "Sets the peers to connect to at start")
     (@arg p2p_workers: --("p2p-workers") [INT] default_value("4") "Sets the number of worker threads for P2P server")
     (@arg miner: --miner [MINER] default_value("account0") "Sets the miner address")
    )
    .get_matches();

    // init logger
    let verbosity = matches.occurrences_of("verbose") as usize;
    stderrlog::new().verbosity(verbosity).init().unwrap();

    // parse p2p server address
    let p2p_addr = matches
        .value_of("peer_addr")
        .unwrap()
        .parse::<net::SocketAddr>()
        .unwrap_or_else(|e| {
            error!("Error parsing P2P server address: {}", e);
            process::exit(1);
        });

    // parse api server address
    let api_addr = matches
        .value_of("api_addr")
        .unwrap()
        .parse::<net::SocketAddr>()
        .unwrap_or_else(|e| {
            error!("Error parsing API server address: {}", e);
            process::exit(1);
        });

    // create channels between server and worker
    let (msg_tx, msg_rx) = channel::unbounded();

    // start the p2p server
    let (server_ctx, server_handle) = server::new(p2p_addr, msg_tx).unwrap();
    server_ctx.start().unwrap();
    let server = Arc::new(server_handle);

    // start the worker
    let p2p_workers = matches
        .value_of("p2p_workers")
        .unwrap()
        .parse::<usize>()
        .unwrap_or_else(|e| {
            error!("Error parsing P2P workers: {}", e);
            process::exit(1);
        });

    // Initialize blockchain
    let blockchain = Arc::new(Mutex::new(Blockchain::new()));
    // Log initial state balances
    {
        let blockchain = blockchain.lock().unwrap();
        let state = blockchain.get_state_for_tip();
        state.log_balances();
    }
    // Initialize mempool
    let mempool = Arc::new(Mutex::new(Mempool::new()));
    // Initialize visualizer
    let visualizer = Arc::new(Mutex::new(Visualizer::new(blockchain.clone())));

    // Initialize and start transaction generator
    let txgen = TransactionGenerator::new(&server, &mempool, &blockchain);
    txgen.start();
    info!("[Node] Transaction generator started");

    let worker_ctx = worker::new(
        p2p_workers,
        msg_rx,
        &server,
        &blockchain,
        &mempool,
    );
    worker_ctx.start();

    let miner_address = matches.value_of("miner").unwrap_or("account0").to_string();
    // start the miner
    let (miner_ctx, miner) = miner::new(
        &server,
        &blockchain,
        &mempool,
        miner_address,
    );
    miner_ctx.start();

    // connect to known peers
    if let Some(known_peers) = matches.values_of("known_peer") {
        let known_peers: Vec<String> = known_peers.map(|x| x.to_owned()).collect();
        let server = server.clone();
        thread::spawn(move || {
            for peer in known_peers {
                loop {
                    let addr = match peer.parse::<net::SocketAddr>() {
                        Ok(x) => x,
                        Err(e) => {
                            error!("Error parsing peer address {}: {}", &peer, e);
                            break;
                        }
                    };
                    match server.connect(addr) {
                        Ok(_) => {
                            info!("Connected to outgoing peer {}", &addr);
                            break;
                        }
                        Err(e) => {
                            error!(
                                "Error connecting to peer {}, retrying in one second: {}",
                                addr, e
                            );
                            thread::sleep(time::Duration::from_millis(1000));
                            continue;
                        }
                    }
                }
            }
        });
    }

    // start the API server
    ApiServer::start(
        api_addr,
        &miner,
        &server,
        visualizer,
        mempool,
    );

    // Periodic blockchain status printout
    {
        let blockchain = blockchain.clone();
        thread::spawn(move || {
            loop {
                thread::sleep(time::Duration::from_secs(5));
                let blockchain = blockchain.lock().unwrap();
                let tip_hash = blockchain.tip();
                let tip_height = blockchain.hash_to_height.get(&tip_hash).cloned().unwrap_or(0);
                let total_blocks = blockchain.hash_to_block.len();
                println!("[Node] Tip: height={}, hash={}, total blocks={}", tip_height, tip_hash, total_blocks);
                // Log current state balances
                let state = blockchain.get_state_for_tip();
                state.log_balances();
            }
        });
    }

    loop {
        std::thread::park();
    }
}