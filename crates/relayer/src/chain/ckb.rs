use ckb_jsonrpc_types::OutputsValidator;
use ckb_sdk::NetworkType;
use eth2_types::MainnetEthSpec;
use eth_light_client_in_ckb_verification::types::{
    core::{Client as EthLcClient, Header as EthLcHeader},
    packed::{self, Client as PackedClient, ProofUpdate as PackedProofUpdate},
    prelude::*,
};
use ibc_relayer_storage::{error::Error as StorageError, prelude::*, Storage};
use ibc_relayer_types::clients::ics07_ckb::{
    client_state::ClientState as CkbClientState,
    consensus_state::ConsensusState as CkbConsensusState, header::Header as CkbHeader,
    light_block::LightBlock as CkbLightBlock,
};
use ibc_relayer_types::clients::ics07_eth::{
    client_state::ClientState as EthClient,
    types::{Header as EthHeader, Update as EthUpdate},
};
use ibc_relayer_types::{
    core::{
        ics02_client::events::UpdateClient,
        ics03_connection::connection::{ConnectionEnd, IdentifiedConnectionEnd},
        ics04_channel::{
            channel::{ChannelEnd, IdentifiedChannelEnd},
            packet::Sequence,
        },
        ics23_commitment::{commitment::CommitmentPrefix, merkle::MerkleProof},
        ics24_host::identifier::{ChannelId, ConnectionId, PortId},
    },
    signer::Signer,
    Height,
};
use semver::Version;
use std::sync::Arc;
use tendermint_light_client::errors::Error as LightClientError;
use tendermint_rpc::endpoint::broadcast::tx_sync::Response;
use tokio::runtime::Runtime as TokioRuntime;

use crate::keyring::{KeyRing, Secp256k1KeyPair};
use crate::{
    account::Balance,
    chain::cosmos::encode::key_pair_to_signer,
    chain::endpoint::{ChainEndpoint, ChainStatus, HealthCheck},
    client_state::{AnyClientState, IdentifiedAnyClientState},
    config::ckb::ChainConfig as CkbChainConfig,
    config::ChainConfig,
    consensus_state::{AnyConsensusState, AnyConsensusStateWithHeight},
    denom::DenomTrace,
    error::Error,
    event::IbcEventWithHeight,
    misbehaviour::MisbehaviourEvidence,
};

pub use self::rpc_client::{CkbRpcClient, RpcClient};

use super::tracking::{NonCosmosTrackingId as NonCosmos, TrackedMsgs, TrackingId};
use super::{
    client::ClientSettings,
    requests::{
        IncludeProof, QueryChannelClientStateRequest, QueryChannelRequest, QueryChannelsRequest,
        QueryClientConnectionsRequest, QueryClientStateRequest, QueryClientStatesRequest,
        QueryConnectionRequest, QueryConnectionsRequest, QueryConsensusStateRequest,
        QueryConsensusStatesRequest, QueryHostConsensusStateRequest,
        QueryNextSequenceReceiveRequest, QueryPacketAcknowledgementRequest,
        QueryPacketAcknowledgementsRequest, QueryPacketCommitmentsRequest,
        QueryUnreceivedAcksRequest, QueryUnreceivedPacketsRequest, QueryUpgradedClientStateRequest,
        QueryUpgradedConsensusStateRequest,
    },
};

mod assembler;
mod helper;
mod rpc_client;
mod signer;
use assembler::TxAssembler;

pub struct CkbChain<C: CkbRpcClient> {
    pub rt: Arc<TokioRuntime>,
    pub rpc_client: Arc<C>,
    pub config: CkbChainConfig,
    pub keybase: KeyRing<Secp256k1KeyPair>,
    pub tx_assembler: TxAssembler<C>,
    // TODO the spec of Ethereum should be selectable.
    pub storage: Storage<MainnetEthSpec>,
}

impl<C: CkbRpcClient> CkbChain<C> {
    fn create_eth_client(&mut self) -> Result<Vec<IbcEventWithHeight>, Error> {
        Ok(vec![])
    }

    fn update_eth_client(
        &mut self,
        header_updates: Vec<EthUpdate>,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        let (packed_client, packed_proof_update) =
            self.get_verified_packed_client_and_proof_update(header_updates)?;

        let (tx, inputs) =
            self.rt
                .block_on(self.tx_assembler.assemble_updates_into_transaction(
                    packed_client,
                    packed_proof_update,
                    &self.config.lightclient_contract_typeargs,
                    &self.config.id.to_string(),
                ))?;
        let key: Secp256k1KeyPair = self
            .keybase
            .get_key(&self.config.key_name)
            .map_err(Error::key_base)?;
        let tx = signer::sign(tx, &inputs, vec![], key).map_err(Error::key_base)?;
        self.rt
            .block_on(
                self.rpc_client
                    .send_transaction(&tx.data().into(), Some(OutputsValidator::Passthrough)),
            )
            .map_err(|e| Error::rpc_response(e.to_string()))?;

        Ok(vec![])
    }

    pub(self) fn get_verified_packed_client_and_proof_update(
        &self,
        header_updates: Vec<EthUpdate>,
    ) -> Result<(PackedClient, PackedProofUpdate), Error> {
        if header_updates.is_empty() {
            return Err(Error::empty_upgraded_client_state());
        }
        let start_slot = header_updates[0].finalized_header.slot;
        for (i, item) in header_updates.iter().enumerate() {
            if item.finalized_header.slot != i as u64 + start_slot {
                return Err(Error::send_tx("uncontinuous header slot".to_owned()));
            }
        }

        let mut is_creation = true;
        // Check the tip in storage and the tip in the client cell are the same.
        if let Some(stored_tip_slot) = self.storage.get_tip_beacon_header_slot()? {
            if start_slot != stored_tip_slot + 1 {
                let height = (stored_tip_slot + 1).try_into().expect("slot too big");
                return Err(Error::light_client_verification(
                    self.id().to_string(),
                    LightClientError::missing_last_block_id(height),
                ));
            }
            is_creation = false;
        }
        let onchain_packed_client = self.rt.block_on(self.tx_assembler.fetch_packed_client(
            &self.config.lightclient_contract_typeargs,
            &self.config.id.to_string(),
        ))?;
        if let Some(client) = onchain_packed_client {
            let onchain_tip_slot: u64 = client.maximal_slot().unpack();
            if start_slot != onchain_tip_slot + 1 {
                let height = (onchain_tip_slot + 1).try_into().expect("slot too big");
                return Err(Error::light_client_verification(
                    self.id().to_string(),
                    LightClientError::missing_last_block_id(height),
                ));
            }
        }

        let finalized_headers = header_updates
            .iter()
            .map(|update| {
                let EthHeader {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body_root,
                } = update.finalized_header.clone();
                let header = EthLcHeader {
                    slot,
                    proposer_index,
                    parent_root,
                    state_root,
                    body_root,
                };
                header.calc_cache()
            })
            .collect::<Vec<_>>();

        let minimal_slot = self
            .storage
            .get_base_beacon_header_slot()?
            .unwrap_or(start_slot);
        let last_finalized_header = &finalized_headers[finalized_headers.len() - 1];
        let maximal_slot = last_finalized_header.inner.slot;
        let tip_header_root = last_finalized_header.root;

        // Saves all header digests into storage for MMR.
        {
            let mut finalized_headers_iter = finalized_headers.iter();

            let mut last_slot = if self.storage.is_initialized()? {
                start_slot - 1
            } else {
                let first = finalized_headers_iter.next().expect("checked");
                self.storage
                    .initialize_with(first.inner.slot, first.digest())?;
                self.storage.put_tip_beacon_header_slot(first.inner.slot)?;
                first.inner.slot
            };

            let mut mmr = self.storage.chain_root_mmr(last_slot)?;

            for header in finalized_headers_iter {
                last_slot = header.inner.slot;
                mmr.push(header.digest()).map_err(StorageError::from)?;
            }
            mmr.commit().map_err(StorageError::from)?;

            self.storage.put_tip_beacon_header_slot(last_slot)?;
        };

        // Gets the new root and a proof for all new headers.
        let (packed_headers_mmr_root, packed_headers_mmr_proof) = {
            let positions = (start_slot..=maximal_slot)
                .into_iter()
                .map(|slot| slot - minimal_slot)
                .collect::<Vec<_>>();

            let mmr = self.storage.chain_root_mmr(maximal_slot)?;

            let headers_mmr_root = mmr.get_root().map_err(StorageError::from)?;
            let headers_mmr_proof_items = mmr
                .gen_proof(positions)
                .map_err(StorageError::from)?
                .proof_items()
                .iter()
                .map(Clone::clone)
                .collect::<Vec<_>>();
            let headers_mmr_proof = packed::MmrProof::new_builder()
                .set(headers_mmr_proof_items)
                .build();

            (headers_mmr_root, headers_mmr_proof)
        };

        // Build the packed client.
        let client = EthLcClient {
            minimal_slot,
            maximal_slot,
            tip_header_root,
            headers_mmr_root: packed_headers_mmr_root.unpack(),
        };

        // Build the packed proof update.
        let packed_proof_update = {
            let updates_items = finalized_headers
                .iter()
                .map(|header| {
                    packed::FinalityUpdate::new_builder()
                        .finalized_header(header.inner.pack())
                        .build()
                })
                .collect::<Vec<_>>();
            let updates = packed::FinalityUpdateVec::new_builder()
                .set(updates_items)
                .build();
            packed::ProofUpdate::new_builder()
                .new_headers_mmr_root(packed_headers_mmr_root)
                .new_headers_mmr_proof(packed_headers_mmr_proof)
                .updates(updates)
                .build()
        };

        // Invoke verification from core::Client on packed_proof_update
        if is_creation {
            EthLcClient::new_from_packed_proof_update(packed_proof_update.as_reader())
                .map_err(|_| Error::send_tx("failed to create header".to_owned()))?;
        } else {
            client
                .try_apply_packed_proof_update(packed_proof_update.as_reader())
                .map_err(|_| Error::send_tx("failed to update header".to_owned()))?;
        }

        Ok((client.pack(), packed_proof_update))
    }
}

impl<C: CkbRpcClient> ChainEndpoint for CkbChain<C> {
    type LightBlock = CkbLightBlock;
    type Header = CkbHeader;
    type ConsensusState = CkbConsensusState;
    type ClientState = CkbClientState;
    type SigningKeyPair = Secp256k1KeyPair;

    fn config(&self) -> ChainConfig {
        ChainConfig::Ckb(self.config.clone())
    }

    fn bootstrap(config: ChainConfig, rt: Arc<TokioRuntime>) -> Result<Self, Error> {
        let config: CkbChainConfig = config.try_into()?;
        let rpc_client = Arc::new(C::new(&config.ckb_rpc, &config.ckb_indexer_rpc));
        let keybase = KeyRing::new(crate::keyring::Store::Memory, "ckb", &config.id)
            .map_err(Error::key_base)?;
        let storage = Storage::new(&config.data_dir)?;

        let chain_info = rt
            .block_on(rpc_client.get_blockchain_info())
            .map_err(|e| Error::rpc_response(e.to_string()))?;
        let network = if chain_info.chain == "ckb" {
            NetworkType::Mainnet
        } else {
            NetworkType::Testnet
        };
        let key: Secp256k1KeyPair = keybase.get_key(&config.key_name).map_err(Error::key_base)?;
        let tx_assembler = TxAssembler::new(rpc_client.clone(), &key.public_key, network);

        Ok(CkbChain {
            rt,
            rpc_client,
            config,
            keybase,
            tx_assembler,
            storage,
        })
    }

    fn shutdown(self) -> Result<(), Error> {
        Ok(())
    }

    fn health_check(&self) -> Result<HealthCheck, Error> {
        Ok(HealthCheck::Healthy)
    }

    fn keybase(&self) -> &KeyRing<Self::SigningKeyPair> {
        &self.keybase
    }

    fn keybase_mut(&mut self) -> &mut KeyRing<Self::SigningKeyPair> {
        &mut self.keybase
    }

    fn get_signer(&self) -> Result<Signer, Error> {
        let key_entry = self
            .keybase()
            .get_key(&self.config.key_name)
            .map_err(Error::key_base)?;
        let signer = key_pair_to_signer(&key_entry)?;
        Ok(signer)
    }

    fn ibc_version(&self) -> Result<Option<Version>, Error> {
        Ok(None)
    }

    fn send_messages_and_wait_commit(
        &mut self,
        tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        match tracked_msgs.tracking_id {
            TrackingId::Static(NonCosmos::ETH_CREATE_CLIENT) => self.create_eth_client(),
            TrackingId::Static(NonCosmos::ETH_UPDATE_CLIENT) => {
                let updates = tracked_msgs
                    .msgs
                    .into_iter()
                    .map(|msg| msg.try_into())
                    .collect::<Result<Vec<EthClient>, _>>()
                    .map_err(|e| Error::send_tx(e.to_string()))?
                    .into_iter()
                    .map(|client| client.lightclient_update)
                    .collect();
                self.update_eth_client(updates)
            }
            _ => Err(Error::send_tx("unknown msg".to_owned())),
        }
    }

    fn send_messages_and_wait_check_tx(
        &mut self,
        _tracked_msgs: TrackedMsgs,
    ) -> Result<Vec<Response>, Error> {
        todo!()
    }

    fn verify_header(
        &mut self,
        _trusted: Height,
        _target: Height,
        _client_state: &AnyClientState,
    ) -> Result<Self::LightBlock, Error> {
        todo!()
    }

    fn check_misbehaviour(
        &mut self,
        _update: &UpdateClient,
        _client_state: &AnyClientState,
    ) -> Result<Option<MisbehaviourEvidence>, Error> {
        todo!()
    }

    fn query_balance(
        &self,
        _key_name: Option<&str>,
        _denom: Option<&str>,
    ) -> Result<Balance, Error> {
        todo!()
    }

    fn query_all_balances(&self, _key_name: Option<&str>) -> Result<Vec<Balance>, Error> {
        todo!()
    }

    fn query_denom_trace(&self, _hash: String) -> Result<DenomTrace, Error> {
        todo!()
    }

    fn query_commitment_prefix(&self) -> Result<CommitmentPrefix, Error> {
        todo!()
    }

    fn query_application_status(&self) -> Result<ChainStatus, Error> {
        todo!()
    }

    fn query_clients(
        &self,
        _request: QueryClientStatesRequest,
    ) -> Result<Vec<IdentifiedAnyClientState>, Error> {
        todo!()
    }

    fn query_client_state(
        &self,
        _request: QueryClientStateRequest,
        _include_proof: IncludeProof,
    ) -> Result<(AnyClientState, Option<MerkleProof>), Error> {
        todo!()
    }

    fn query_consensus_state(
        &self,
        _request: QueryConsensusStateRequest,
        _include_proof: IncludeProof,
    ) -> Result<(AnyConsensusState, Option<MerkleProof>), Error> {
        todo!()
    }

    fn query_consensus_states(
        &self,
        _request: QueryConsensusStatesRequest,
    ) -> Result<Vec<AnyConsensusStateWithHeight>, Error> {
        todo!()
    }

    fn query_upgraded_client_state(
        &self,
        _request: QueryUpgradedClientStateRequest,
    ) -> Result<(AnyClientState, MerkleProof), Error> {
        todo!()
    }

    fn query_upgraded_consensus_state(
        &self,
        _request: QueryUpgradedConsensusStateRequest,
    ) -> Result<(AnyConsensusState, MerkleProof), Error> {
        todo!()
    }

    fn query_connections(
        &self,
        _request: QueryConnectionsRequest,
    ) -> Result<Vec<IdentifiedConnectionEnd>, Error> {
        todo!()
    }

    fn query_client_connections(
        &self,
        _request: QueryClientConnectionsRequest,
    ) -> Result<Vec<ConnectionId>, Error> {
        todo!()
    }

    fn query_connection(
        &self,
        _request: QueryConnectionRequest,
        _include_proof: IncludeProof,
    ) -> Result<(ConnectionEnd, Option<MerkleProof>), Error> {
        todo!()
    }

    fn query_connection_channels(
        &self,
        _request: super::requests::QueryConnectionChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        todo!()
    }

    fn query_channels(
        &self,
        _request: QueryChannelsRequest,
    ) -> Result<Vec<IdentifiedChannelEnd>, Error> {
        todo!()
    }

    fn query_channel(
        &self,
        _request: QueryChannelRequest,
        _include_proof: IncludeProof,
    ) -> Result<(ChannelEnd, Option<MerkleProof>), Error> {
        todo!()
    }

    fn query_channel_client_state(
        &self,
        _request: QueryChannelClientStateRequest,
    ) -> Result<Option<IdentifiedAnyClientState>, Error> {
        todo!()
    }

    fn query_packet_commitment(
        &self,
        _request: super::requests::QueryPacketCommitmentRequest,
        _include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        todo!()
    }

    fn query_packet_commitments(
        &self,
        _request: QueryPacketCommitmentsRequest,
    ) -> Result<(Vec<Sequence>, Height), Error> {
        todo!()
    }

    fn query_packet_receipt(
        &self,
        _request: super::requests::QueryPacketReceiptRequest,
        _include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        todo!()
    }

    fn query_unreceived_packets(
        &self,
        _request: QueryUnreceivedPacketsRequest,
    ) -> Result<Vec<Sequence>, Error> {
        todo!()
    }

    fn query_packet_acknowledgement(
        &self,
        _request: QueryPacketAcknowledgementRequest,
        _include_proof: IncludeProof,
    ) -> Result<(Vec<u8>, Option<MerkleProof>), Error> {
        todo!()
    }

    fn query_packet_acknowledgements(
        &self,
        _request: QueryPacketAcknowledgementsRequest,
    ) -> Result<(Vec<Sequence>, Height), Error> {
        todo!()
    }

    fn query_unreceived_acknowledgements(
        &self,
        _request: QueryUnreceivedAcksRequest,
    ) -> Result<Vec<Sequence>, Error> {
        todo!()
    }

    fn query_next_sequence_receive(
        &self,
        _request: QueryNextSequenceReceiveRequest,
        _include_proof: IncludeProof,
    ) -> Result<(Sequence, Option<MerkleProof>), Error> {
        todo!()
    }

    fn query_txs(
        &self,
        _request: super::requests::QueryTxRequest,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        todo!()
    }

    fn query_packet_events(
        &self,
        _request: super::requests::QueryPacketEventDataRequest,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        todo!()
    }

    fn query_host_consensus_state(
        &self,
        _request: QueryHostConsensusStateRequest,
    ) -> Result<Self::ConsensusState, Error> {
        todo!()
    }

    fn build_client_state(
        &self,
        _height: Height,
        _settings: ClientSettings,
    ) -> Result<Self::ClientState, Error> {
        todo!()
    }

    fn build_consensus_state(
        &self,
        _light_block: Self::LightBlock,
    ) -> Result<Self::ConsensusState, Error> {
        todo!()
    }

    fn build_header(
        &mut self,
        _trusted_height: Height,
        _target_height: Height,
        _client_state: &AnyClientState,
    ) -> Result<(Self::Header, Vec<Self::Header>), Error> {
        todo!()
    }

    fn maybe_register_counterparty_payee(
        &mut self,
        _channel_id: &ChannelId,
        _port_id: &PortId,
        _counterparty_payee: &Signer,
    ) -> Result<(), Error> {
        todo!()
    }

    fn subscribe(&mut self) -> Result<super::handle::Subscription, Error> {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use ckb_jsonrpc_types::{
        BlockNumber, BlockView, ChainInfo, HeaderView, JsonBytes, OutPoint, Transaction,
        TransactionWithStatusResponse,
    };
    use ckb_sdk::rpc::ckb_light_client::{Cell, Pagination, SearchKey};
    use futures::FutureExt;
    use ibc_relayer_types::core::ics24_host::identifier::ChainId;
    use tendermint_rpc::Url;
    use tokio::runtime::Runtime;

    use super::rpc_client::Rpc;
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::str::FromStr;

    struct MockRpcClient {}

    impl CkbRpcClient for MockRpcClient {
        fn new(_ckb_uri: &Url, _indexer_uri: &Url) -> Self {
            MockRpcClient {}
        }

        fn get_blockchain_info(&self) -> Rpc<ChainInfo> {
            let chain_info = ChainInfo {
                chain: String::from("test"),
                median_time: 0x0.into(),
                epoch: 0x11555.into(),
                difficulty: Default::default(),
                is_initial_block_download: true,
                alerts: vec![],
            };
            async { Ok(chain_info) }.boxed()
        }

        fn get_block_by_number(&self, _number: BlockNumber) -> Rpc<BlockView> {
            todo!()
        }

        fn get_block(&self, _hash: &ckb_types::H256) -> Rpc<BlockView> {
            todo!()
        }

        fn get_tip_header(&self) -> Rpc<HeaderView> {
            todo!()
        }

        fn get_transaction(
            &self,
            _hash: &ckb_types::H256,
        ) -> Rpc<Option<TransactionWithStatusResponse>> {
            todo!()
        }

        fn get_live_cell(
            &self,
            _out_point: &OutPoint,
            _with_data: bool,
        ) -> Rpc<ckb_jsonrpc_types::CellWithStatus> {
            todo!()
        }

        fn send_transaction(
            &self,
            _tx: &Transaction,
            _outputs_validator: Option<OutputsValidator>,
        ) -> Rpc<ckb_types::H256> {
            todo!()
        }

        fn get_txs_by_hashes(
            &self,
            _hashes: Vec<ckb_types::H256>,
        ) -> Rpc<Vec<Option<TransactionWithStatusResponse>>> {
            todo!()
        }

        fn fetch_live_cells(
            &self,
            _search_key: SearchKey,
            _limit: u32,
            _cursor: Option<JsonBytes>,
        ) -> Rpc<Pagination<Cell>> {
            todo!()
        }
    }

    fn get_ckb_chain() -> CkbChain<MockRpcClient> {
        let data_dir = Path::new("test_storage");
        if data_dir.is_dir() {
            fs::remove_dir_all(data_dir).unwrap();
        }
        let dummy_addr = "http://127.0.0.1";
        let config = CkbChainConfig {
            id: ChainId::new(String::from("ckb"), 1),
            ckb_rpc: Url::from_str(dummy_addr).unwrap(),
            ckb_indexer_rpc: Url::from_str(dummy_addr).unwrap(),
            lightclient_contract_typeargs: Default::default(),
            key_name: Default::default(),
            data_dir: data_dir.into(),
        };
        let chain: CkbChain<MockRpcClient> =
            CkbChain::bootstrap(ChainConfig::Ckb(config), Arc::new(Runtime::new().unwrap()))
                .unwrap();
        chain
    }

    #[test]
    fn get_verified_packed_client_and_proof_update() {
        let _chain = get_ckb_chain();
    }
}
