use serde::{Serialize, Deserialize};
use crate::miner::Handle as MinerHandle;
use crate::network::server::Handle as NetworkServerHandle;
use crate::blockchain::Blockchain;
use crate::network::message::Message;
use crate::crypto::hash::{H256, Hashable};

use log::info;
use std::collections::HashMap;
use std::thread;
use tiny_http::Header;
use tiny_http::Response;
use tiny_http::Server as HTTPServer;
use url::Url;
use std::sync::{Arc, Mutex};
use serde_json::{json, Value};

pub struct Server {
    handle: HTTPServer,
    miner: MinerHandle,
    network: NetworkServerHandle,
}

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

#[derive(Serialize, Deserialize)]
struct TipInfo {
    hash: String,
    height: u64,
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
        blockchain: &Arc<Mutex<Blockchain>>,
    ) {
        let handle = HTTPServer::http(&addr).unwrap();
        let server = Self {
            handle,
            miner: miner.clone(),
            network: network.clone(),
        };
        thread::spawn(move || {
            for req in server.handle.incoming_requests() {
                let miner = server.miner.clone();
                let network = server.network.clone();
                thread::spawn(move || {
                    // Check if this is a visualization request
                    if req.url() == "/visualize" {
                        let html_content = include_str!("../resources/blockchain_visualizer.html");
                        let content_type = "Content-Type: text/html".parse::<Header>().unwrap();
                        let resp = Response::from_string(html_content)
                            .with_header(content_type);
                        req.respond(resp).unwrap();
                        return;
                    }

                    // API endpoint for getting tip info
                    if req.url() == "/api/tip" {
                        let blockchain = blockchain.lock().unwrap();
                        let tip_hash = blockchain.tip();
                        let tip_height = blockchain.hash_to_height.get(&tip_hash).unwrap_or(&0);

                        let tip_info = TipInfo {
                            hash: format!("{:?}", tip_hash),
                            height: *tip_height,
                        };

                        let json_response = serde_json::to_string(&tip_info).unwrap();
                        let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                        let resp = Response::from_string(json_response)
                            .with_header(content_type);
                        req.respond(resp).unwrap();
                        return;
                    }

<<<<<<< HEAD
=======
                    // API endpoint for getting all account balances
                    if req.url() == "/api/accounts" {
                        let blockchain = blockchain.lock().unwrap();
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
                        return;
                    }

>>>>>>> b920444 (Initial commit for demo done)
                    // a valid url requires a base
                    let base_url = Url::parse(&format!("http://{}/", &addr)).unwrap();
                    let url = match base_url.join(req.url()) {
                        Ok(u) => u,
                        Err(e) => {
                            respond_result!(req, false, format!("error parsing url: {}", e));
                            return;
                        }
                    };

                    // Parse URL path and query parameters
                    match url.path() {
                        "/api/blocks" => {
                            let params: HashMap<_, _> = url.query_pairs().into_owned().collect();
                            let start_height = params.get("start").and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
                            let end_height = params.get("end").and_then(|s| s.parse::<u64>().ok());

                            let blockchain = blockchain.lock().unwrap();
                            let mut blocks_data = Vec::new();

                            // Get the tip height if end_height is not specified
                            let tip_hash = blockchain.tip();
                            let tip_height = *blockchain.hash_to_height.get(&tip_hash).unwrap_or(&0);
                            let end_height = end_height.unwrap_or(tip_height);

                            // Collect blocks within the requested height range
                            for (hash, block) in &blockchain.hash_to_block {
                                let height = blockchain.hash_to_height.get(hash).unwrap_or(&0);

                                if *height >= start_height && *height <= end_height {
                                    // Also include parent blocks if they're needed for drawing arrows
                                    let parent_hash = block.header.parent;
                                    let parent_height = if parent_hash != H256::default() {
                                        blockchain.hash_to_height.get(&parent_hash).unwrap_or(&0)
                                    } else {
                                        &0
                                    };

                                    // Include block data
                                    let block_data = json!({
                                        "hash": format!("{:?}", hash),
                                        "height": height,
                                        "parent": if parent_hash != H256::default() { format!("{:?}", parent_hash) } else { serde_json::Value::Null.to_string() },
                                        "timestamp": block.header.timestamp.to_string(),
                                        "transactions": block.content.transactions.len()
                                    });

                                    blocks_data.push(block_data);

                                    // If parent is not in range but needed for visualization
                                    if *parent_height < start_height && parent_hash != H256::default() {
                                        if let Some(parent_block) = blockchain.hash_to_block.get(&parent_hash) {
                                            let parent_data = json!({
                                                "hash": format!("{:?}", parent_hash),
                                                "height": parent_height,
                                                "parent": serde_json::Value::Null.to_string(),
                                                "timestamp": parent_block.header.timestamp.to_string(),
                                                "transactions": parent_block.content.transactions.len()
                                            });

                                            blocks_data.push(parent_data);
                                        }
                                    }
                                }
                            }

                            let json_response = serde_json::to_string(&blocks_data).unwrap();
                            let content_type = "Content-Type: application/json".parse::<Header>().unwrap();
                            let resp = Response::from_string(json_response)
                                .with_header(content_type);
                            req.respond(resp).unwrap();
                        }
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
<<<<<<< HEAD
=======

>>>>>>> b920444 (Initial commit for demo done)
