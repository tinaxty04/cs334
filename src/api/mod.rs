use serde::Serialize;
use crate::miner::Handle as MinerHandle;
use crate::network::server::Handle as NetworkServerHandle;
use crate::network::message::Message;
use crate::visualization::Visualizer;
use crate::crypto::hash::Hashable;

use log::info;
use std::collections::HashMap;
use std::thread;
use tiny_http::Header;
use tiny_http::Response;
use tiny_http::Server as HTTPServer;
use url::Url;
use std::sync::Arc;
use std::sync::Mutex;
use serde_json::json;
use crate::crypto::hash::H256;
use std::collections::VecDeque;
use std::sync::RwLock;
use crate::mempool::Mempool;
use std::time;
use crate::network::worker::{TX_STATUS_MAP, TxStatusInfo, TxStatus};

// Global log buffer (last 100 entries)
lazy_static::lazy_static! {
    static ref LOG_BUFFER: RwLock<VecDeque<String>> = RwLock::new(VecDeque::with_capacity(100));
}

pub fn push_log(entry: String) {
    let mut buffer = LOG_BUFFER.write().unwrap();
    if buffer.len() == 100 {
        buffer.pop_front();
    }
    buffer.push_back(entry);
}

pub struct Server {
    handle: HTTPServer,
    miner: MinerHandle,
    network: NetworkServerHandle,
    visualizer: Arc<Mutex<Visualizer>>,
    mempool: Arc<Mutex<Mempool>>,
}

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

#[derive(Serialize)]
#[serde(tag = "status", content = "reason")]
pub enum TxStatusApi {
    Pending,
    Confirmed,
    Rejected(String),
}

#[derive(Serialize)]
pub struct TxStatusInfoApi {
    pub hash: String,
    pub from: String,
    pub to: String,
    pub value: u64,
    pub status: TxStatusApi,
    pub node: String,
}

macro_rules! respond_result {
    ( $req:expr, $success:expr, $message:expr ) => {{
        let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
        let payload = ApiResponse {
            success: $success,
            message: $message.to_string(),
        };
        let resp = Response::from_string(serde_json::to_string_pretty(&payload).unwrap())
            .with_header(content_type);
        $req.respond(resp).unwrap();
    }};
}

impl Server {
    pub fn start(
        addr: std::net::SocketAddr,
        miner: &MinerHandle,
        network: &NetworkServerHandle,
        visualizer: Arc<Mutex<Visualizer>>,
        mempool: Arc<Mutex<Mempool>>,
    ) {
        let handle = HTTPServer::http(&addr).unwrap();
        let server = Self {
            handle,
            miner: miner.clone(),
            network: network.clone(),
            visualizer,
            mempool,
        };

        // Initialize node state
        {
            let mut visualizer = server.visualizer.lock().unwrap();
            visualizer.update_node_state("local", &format!("{}", addr));
        }

        // Start periodic updates
        let visualizer = server.visualizer.clone();
        let mempool = server.mempool.clone();
        let addr_str = format!("{}", addr);
        thread::spawn(move || {
            loop {
                thread::sleep(time::Duration::from_secs(1));
                let mut visualizer = visualizer.lock().unwrap();
                let mempool_size = mempool.lock().unwrap().get_all_transactions().len();
                visualizer.update_node_state("local", &addr_str);
                if let Some(state) = visualizer.nodes.get_mut("local") {
                    state.mempool_size = mempool_size;
                }
            }
        });

        thread::spawn(move || {
            for req in server.handle.incoming_requests() {
                let miner = server.miner.clone();
                let network = server.network.clone();
                let visualizer = server.visualizer.clone();
                let mempool = server.mempool.clone();
                thread::spawn(move || {
                    // a valid url requires a base
                    let base_url = Url::parse(&format!("http://{}/", &addr)).unwrap();
                    let url = match base_url.join(req.url()) {
                        Ok(u) => u,
                        Err(e) => {
                            respond_result!(req, false, format!("error parsing url: {}", e));
                            return;
                        }
                    };
                    match url.path() {
                        "/miner/start" => {
                            let params = url.query_pairs();
                            let params: HashMap<_, _> = params.into_owned().collect();
                            let lambda = match params.get("lambda") {
                                Some(v) => v,
                                None => {
                                    respond_result!(req, false, "missing lambda");
                                    return;
                                }
                            };
                            let lambda = match lambda.parse::<u64>() {
                                Ok(v) => v,
                                Err(e) => {
                                    respond_result!(
                                        req,
                                        false,
                                        format!("error parsing lambda: {}", e)
                                    );
                                    return;
                                }
                            };
                            miner.start(lambda);
                            respond_result!(req, true, "ok");
                        }
                        "/network/ping" => {
                            network.broadcast(Message::Ping(String::from("Test ping")));
                            respond_result!(req, true, "ok");
                        }
                        "/visualize" => {
                            let html_content = include_str!("../resources/blockchain_visualizer.html");
                            let content_type = "Content-Type: text/html".parse::<Header>().unwrap();
                            let resp = Response::from_string(html_content)
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
                        "/api/visualization" => {
                            let visualizer = visualizer.lock().unwrap();
                            let data = visualizer.get_visualization_data();
                            let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                            let resp = Response::from_string(data)
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
                        "/api/tip" => {
                            let visualizer = visualizer.lock().unwrap();
                            let blockchain = visualizer.blockchain.lock().unwrap();
                            let tip_hash = blockchain.tip();
                            let tip_height = *blockchain.hash_to_height.get(&tip_hash).unwrap_or(&0);
                            let resp_json = serde_json::json!({
                                "height": tip_height,
                                "hash": format!("{:?}", tip_hash),
                            });
                            let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                            let resp = Response::from_string(resp_json.to_string())
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
                        "/api/blocks" => {
                            let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
                            let start_height = params.get("start").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                            let end_height = params.get("end").and_then(|s| s.parse::<u64>().ok());

                            let visualizer = visualizer.lock().unwrap();
                            let blockchain = visualizer.blockchain.lock().unwrap();
                            let mut blocks_data = Vec::new();

                            // Get the tip height if end_height is not specified
                            let tip_hash = blockchain.tip();
                            let tip_height = *blockchain.hash_to_height.get(&tip_hash).unwrap_or(&0);
                            let end_height = end_height.unwrap_or(tip_height);

                            // Collect blocks within the requested height range
                            for (hash, block) in &blockchain.hash_to_block {
                                let height = blockchain.hash_to_height.get(hash).unwrap_or(&0);
                                if *height >= start_height && *height <= end_height {
                                    let parent_hash = block.header.parent;
                                    let parent_height = if parent_hash != H256::default() {
                                        blockchain.hash_to_height.get(&parent_hash).unwrap_or(&0)
                                    } else {
                                        &0
                                    };

                                    // Create transaction data array
                                    let transactions_data: Vec<_> = block.content.transactions.iter().map(|tx| {
                                        json!({
                                            "hash": format!("{:?}", tx.hash()),
                                            "from": format!("{}", tx.raw.from_addr),
                                            "to": format!("{}", tx.raw.to_addr),
                                            "value": tx.raw.value,
                                            "nonce": tx.raw.nonce
                                        })
                                    }).collect();

                                    let block_data = json!({
                                        "hash": format!("{:?}", hash),
                                        "height": height,
                                        "parent": if parent_hash != H256::default() { format!("{:?}", parent_hash) } else { serde_json::Value::Null.to_string() },
                                        "timestamp": block.header.timestamp.to_string(),
                                        "transactions": transactions_data,
                                        "miner": block.header.miner,
                                    });
                                    blocks_data.push(block_data);
                                }
                            }

                            let json_response = serde_json::to_string(&blocks_data).unwrap();
                            let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                            let resp = Response::from_string(json_response)
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
                        "/api/logs" => {
                            let buffer = LOG_BUFFER.read().unwrap();
                            let logs: Vec<String> = buffer.iter().cloned().collect();
                            let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                            let resp = Response::from_string(serde_json::to_string(&logs).unwrap())
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
                        "/api/mempool" => {
                            let mempool = mempool.lock().unwrap();
                            let txs: Vec<_> = mempool.get_all_transactions().iter().map(|tx| json!({
                                "hash": format!("{:x}", tx.hash()),
                                "from_addr": format!("{:x}", tx.raw.from_addr),
                                "to_addr": format!("{:x}", tx.raw.to_addr),
                                "value": tx.raw.value,
                                "nonce": tx.raw.nonce
                            })).collect();
                            let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                            let resp = Response::from_string(serde_json::to_string(&txs).unwrap())
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
                        "/api/tx_status" => {
                            let map = TX_STATUS_MAP.lock().unwrap();
                            let mut txs: Vec<_> = map.values().cloned().collect();
                            // Sort by hash for determinism (could use timestamp if available)
                            txs.sort_by(|a, b| a.hash.cmp(&b.hash));
                            // Only keep the most recent 1000
                            if txs.len() > 1000 { txs = txs[txs.len()-1000..].to_vec(); }
                            let txs_api: Vec<TxStatusInfoApi> = txs.into_iter().map(|info| {
                                TxStatusInfoApi {
                                    hash: format!("{:x}", info.hash),
                                    from: format!("{:x}", info.from),
                                    to: format!("{:x}", info.to),
                                    value: info.value,
                                    status: match info.status {
                                        TxStatus::Pending => TxStatusApi::Pending,
                                        TxStatus::Confirmed => TxStatusApi::Confirmed,
                                        TxStatus::Rejected(reason) => TxStatusApi::Rejected(reason),
                                    },
                                    node: info.node,
                                }
                            }).collect();
                            let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                            let resp = Response::from_string(serde_json::to_string(&txs_api).unwrap())
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
                        // --- BEGIN: Multi-node endpoint support for visualizer ---
                        path if path.starts_with("/api/node/") => {
                            let parts: Vec<&str> = path.split('/').collect();
                            if parts.len() == 5 && parts[4] == "blocks" {
                                // Per-node agreed chain: only show blocks this node has agreed to
                                let visualizer = visualizer.lock().unwrap();
                                let blockchain = visualizer.blockchain.lock().unwrap();
                                let mut blocks_data = Vec::new();
                                let tip_hash = blockchain.tip();
                                let tip_height = *blockchain.hash_to_height.get(&tip_hash).unwrap_or(&0);
                                // Determine which blocks this node agrees to
                                let node_name = parts[3];
                                let miner_name = match node_name {
                                    "node1" => "account0",
                                    "node2" => "account1",
                                    "node3" => "account2",
                                    _ => "account0"
                                };
                                for (hash, block) in &blockchain.hash_to_block {
                                    let height = blockchain.hash_to_height.get(hash).unwrap_or(&0);
                                    // Always agree to genesis block
                                    if *height == 0 || block.header.miner == miner_name {
                                        let parent_hash = block.header.parent;
                                        let transactions_data: Vec<_> = block.content.transactions.iter().map(|tx| {
                                            json!({
                                                "hash": format!("{:?}", tx.hash()),
                                                "from_addr": format!("{}", tx.raw.from_addr),
                                                "to_addr": format!("{}", tx.raw.to_addr),
                                                "value": tx.raw.value,
                                                "nonce": tx.raw.nonce
                                            })
                                        }).collect();
                                        let block_data = json!({
                                            "hash": format!("{:?}", hash),
                                            "height": height,
                                            "parent": if parent_hash != H256::default() { format!("{:?}", parent_hash) } else { serde_json::Value::Null.to_string() },
                                            "timestamp": block.header.timestamp.to_string(),
                                            "transactions": transactions_data,
                                            "miner": block.header.miner,
                                        });
                                        blocks_data.push(block_data);
                                    }
                                }
                                // Return ALL pending transactions in the mempool (not just a minimal set)
                                let mempool = mempool.lock().unwrap();
                                let mempool_data: Vec<_> = mempool.get_all_transactions().iter().map(|tx| json!({
                                    "hash": format!("{:?}", tx.hash()),
                                    "from_addr": format!("{}", tx.raw.from_addr),
                                    "to_addr": format!("{}", tx.raw.to_addr),
                                    "value": tx.raw.value,
                                    "nonce": tx.raw.nonce
                                })).collect();
                                let resp_json = json!({
                                    "blocks": blocks_data,
                                    "mempool": mempool_data,
                                    "isMining": false,
                                    "difficulty": 1,
                                    "newBlock": null
                                });
                                let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                                let resp = Response::from_string(resp_json.to_string())
                                    .with_header(content_type);
                                req.respond(resp).unwrap();
                            } else if parts.len() == 5 && parts[4] == "accounts" {
                                // Return account info
                                let visualizer = visualizer.lock().unwrap();
                                let blockchain = visualizer.blockchain.lock().unwrap();
                                let state = blockchain.get_state_for_tip();
                                let mut accounts = Vec::new();
                                for (address, (nonce, balance)) in &state.map {
                                    accounts.push(json!({
                                        "address": format!("{}", address),
                                        "nonce": nonce,
                                        "balance": balance,
                                        "last_transaction": null,
                                        "created_at": "2024-01-01T00:00:00Z" // Placeholder
                                    }));
                                }
                                let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                                let resp = Response::from_string(serde_json::to_string(&accounts).unwrap())
                                    .with_header(content_type);
                                req.respond(resp).unwrap();
                            } else {
                                let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                                let payload = ApiResponse {
                                    success: false,
                                    message: "node endpoint not found".to_string(),
                                };
                                let resp = Response::from_string(
                                    serde_json::to_string_pretty(&payload).unwrap(),
                                )
                                .with_header(content_type)
                                .with_status_code(404);
                                req.respond(resp).unwrap();
                            }
                        }
                        // --- END: Multi-node endpoint support for visualizer ---
                        _ => {
                            let content_type =
                                "Content-Type: application/json".parse::<Header>().unwrap();
                            let payload = ApiResponse {
                                success: false,
                                message: "endpoint not found".to_string(),
                            };
                            let resp = Response::from_string(
                                serde_json::to_string_pretty(&payload).unwrap(),
                            )
                            .with_header(content_type)
                            .with_status_code(404);
                            req.respond(resp).unwrap();
                        }
                    }
                });
            }
        });
        info!("API server listening at {}", &addr);
    }
}
