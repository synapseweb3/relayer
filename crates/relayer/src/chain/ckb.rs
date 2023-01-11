use ckb_jsonrpc_types::OutputsValidator;
use ckb_sdk::NetworkType;
use eth2_types::MainnetEthSpec;
use ibc_relayer_storage::Storage;
use ibc_relayer_types::clients::ics07_ckb::{
    client_state::ClientState as CkbClientState,
    consensus_state::ConsensusState as CkbConsensusState, header::Header as CkbHeader,
    light_block::LightBlock as CkbLightBlock,
};
use ibc_relayer_types::clients::ics07_eth::{
    client_state::ClientState as EthClient, types::Update as EthUpdate,
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
mod utils;
use assembler::TxAssembler;
use rpc_client::RpcClient;

pub struct CkbChain {
    pub rt: Arc<TokioRuntime>,
    pub rpc_client: Arc<RpcClient>,
    pub config: CkbChainConfig,
    pub keybase: KeyRing<Secp256k1KeyPair>,
    pub tx_assembler: TxAssembler,
    // TODO the spec of Ethereum should be selectable.
    pub storage: Storage<MainnetEthSpec>,
}

impl CkbChain {
    fn create_eth_client(&mut self) -> Result<Vec<IbcEventWithHeight>, Error> {
        Ok(vec![])
    }

    fn update_eth_client(
        &mut self,
        header_updates: Vec<EthUpdate>,
    ) -> Result<Vec<IbcEventWithHeight>, Error> {
        let chain_id = self.id().to_string();
        let onchain_packed_client = self.rt.block_on(
            self.tx_assembler
                .fetch_packed_client(&self.config.lightclient_contract_typeargs, &chain_id),
        )?;
        let (packed_client, packed_proof_update) =
            utils::get_verified_packed_client_and_proof_update(
                &chain_id,
                header_updates,
                &self.storage,
                onchain_packed_client,
            )?;

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
}

impl ChainEndpoint for CkbChain {
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
        let rpc_client = Arc::new(RpcClient::new(&config.ckb_rpc, &config.ckb_indexer_rpc));
        let keybase =
            KeyRing::new(Default::default(), "ckb", &config.id).map_err(Error::key_base)?;
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
