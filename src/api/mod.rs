use serde::Serialize;
use crate::miner::Handle as MinerHandle;
use crate::network::server::Handle as NetworkServerHandle;
use crate::network::message::Message;
use crate::visualization::Visualizer;
use crate::crypto::hash::Hashable;
use crate::mempool::Mempool;

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
            mempool: mempool.clone(),
        };
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

                            // Use all_blocks_in_longest_chain to get blocks in order
                            let block_hashes = blockchain.all_blocks_in_longest_chain();
                            for hash in block_hashes {
                                let height = blockchain.hash_to_height.get(&hash).unwrap_or(&0);
                                if *height >= start_height && *height <= end_height {
                                    if let Some(block) = blockchain.get_block(&hash) {
                                        let parent_hash = block.header.parent;
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
                        "/api/accounts" => {
                            let visualizer = visualizer.lock().unwrap();
                            let blockchain = visualizer.blockchain.lock().unwrap();
                            let state = blockchain.get_state_for_tip();
                            let accounts: Vec<_> = state.all_accounts().into_iter().map(|(addr, nonce, balance)| {
                                json!({
                                    "address": format!("{}", addr),
                                    "nonce": nonce,
                                    "balance": balance
                                })
                            }).collect();
                            let json_response = serde_json::to_string(&accounts).unwrap();
                            let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                            let resp = Response::from_string(json_response)
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
                        "/api/mempool" => {
                            let mut mempool = mempool.lock().unwrap();
                            let transactions: Vec<_> = mempool.get_transactions(1000).into_iter().map(|tx| {
                                json!({
                                    "hash": format!("{:?}", tx.hash()),
                                    "from": format!("{}", tx.raw.from_addr),
                                    "to": format!("{}", tx.raw.to_addr),
                                    "value": tx.raw.value,
                                    "nonce": tx.raw.nonce
                                })
                            }).collect();
                            let json_response = serde_json::to_string(&transactions).unwrap();
                            let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                            let resp = Response::from_string(json_response)
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
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
