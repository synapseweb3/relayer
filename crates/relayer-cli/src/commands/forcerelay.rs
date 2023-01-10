use core::convert::Infallible;
use core::time::Duration;
use std::ops::Deref;

use abscissa_core::clap::Parser;
use abscissa_core::{Command, Runnable};
use tracing::error_span;

use ibc_relayer::chain::handle::{CachingChainHandle, ChainHandle};
use ibc_relayer::event::monitor::{Error as EventError, ErrorDetail as EventErrorDetail};
use ibc_relayer::registry::SharedRegistry;
use ibc_relayer::supervisor::forcerelay::handle_event_batch;
use ibc_relayer::util::task::{spawn_background_task, Next, TaskError};
use ibc_relayer_types::core::ics24_host::identifier::ChainId;

use crate::conclude::Output;
use crate::prelude::*;

#[derive(Clone, Command, Debug, Parser, PartialEq, Eq)]
pub struct ForcerelayCmd {
    #[clap(
        long = "ethereum-chain-id",
        required = true,
        help = "Identifier of the Ethereum chain that hosts the client"
    )]
    eth_chain: ChainId,

    #[clap(
        long = "ckb-chain-id",
        required = true,
        help = "Identifier of the Ckb chain that hosts the client"
    )]
    ckb_chain: ChainId,
}

impl Runnable for ForcerelayCmd {
    fn run(&self) {
        let config = (*app_config()).clone();
        let registry = SharedRegistry::<CachingChainHandle>::new(config.clone());
        let eth = registry.get_or_spawn(&self.eth_chain).unwrap_or_else(|e| {
            Output::error(format!("Forcerelay failed to start ethereum: {}", e)).exit()
        });
        let ckb = registry.get_or_spawn(&self.ckb_chain).unwrap_or_else(|e| {
            Output::error(format!("Forcerelay failed to start ckb: {}", e)).exit()
        });
        let eth_subscription = eth.subscribe().unwrap_or_else(|e| {
            Output::error(format!(
                "Forcerelay failed to subscribe ethereum events: {}",
                e
            ))
            .exit()
        });

        spawn_background_task(
            error_span!("worker.batch", eth_chain = %self.eth_chain, ckb_chain = %self.ckb_chain),
            Some(Duration::from_millis(5)),
            move || -> Result<Next, TaskError<Infallible>> {
                if let Ok(batch) = eth_subscription.try_recv() {
                    match batch.deref() {
                        Ok(batch) => {
                            handle_event_batch(&eth, &ckb, batch);
                        }
                        Err(EventError(EventErrorDetail::SubscriptionCancelled(_), _)) => {
                            warn!("event subscription was cancelled, clearing pending packets");
                        }
                        Err(e) => {
                            error!("error when receiving event batch: {}", e)
                        }
                    }
                }

                Ok(Next::Continue)
            },
        )
        .join();
    }
}

// Step test header sent from eth to ckb.
// Run: RUST_BACKTRACE=1 cargo test send_eth_header -- --ignored
#[test]
#[ignore]
fn send_eth_header() {
    // parameters
    let height = 100;
    let eth_chain: ChainId = "ibc-eth-0".parse().unwrap();
    let ckb_chain: ChainId = "ibc-ckb-0".parse().unwrap();

    let config_path = super::default_config_file().unwrap();
    let config = ibc_relayer::config::load(config_path).unwrap();
    // let config = (*app_config()).clone();

    let registry = SharedRegistry::<CachingChainHandle>::new(config.clone());
    let src_chain = registry.get_or_spawn(&eth_chain).unwrap_or_else(|e| {
        Output::error(format!("Forcerelay failed to start ethereum: {}", e)).exit()
    });
    let dst_chain = registry
        .get_or_spawn(&ckb_chain)
        .unwrap_or_else(|e| Output::error(format!("Forcerelay failed to start ckb: {}", e)).exit());

    let height = ibc_relayer_types::core::ics02_client::height::Height::new(0, height).unwrap();
    let client_state = src_chain
        .build_client_state(height, ibc_relayer::chain::client::ClientSettings::Other)
        .unwrap();
    let tracked_msgs = ibc_relayer::chain::tracking::TrackedMsgs {
        msgs: vec![client_state.into()],
        tracking_id: ibc_relayer::chain::tracking::TrackingId::Static(
            ibc_relayer::chain::tracking::NonCosmosTrackingId::ETH_UPDATE_CLIENT,
        ),
    };

    let ret = dst_chain.send_messages_and_wait_commit(tracked_msgs);
    info!("{:?}", ret);
}
