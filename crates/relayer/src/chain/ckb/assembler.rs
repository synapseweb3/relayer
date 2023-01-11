#![allow(dead_code)]

use ckb_sdk::constants::TYPE_ID_CODE_HASH;
use ckb_sdk::traits::PrimaryScriptType;
use ckb_sdk::{Address, AddressPayload, NetworkType};
use ckb_types::core::{Capacity, DepType, ScriptHashType, TransactionView};
use ckb_types::{packed, prelude::*, H256};
use eth_light_client_in_ckb_verification::types::packed::{
    Client as PackedClient, ClientReader as PackedClientReader, ProofUpdate as PackedProofUpdate,
};
use secp256k1::PublicKey;
use std::sync::Arc;

use super::helper::{CellSearcher, TxCompleter};
use super::rpc_client::CkbRpcClient;
use crate::error::Error;

pub struct TxAssembler<C: CkbRpcClient> {
    ckb_rpc: Arc<C>,
    address: Address,
}

impl<C: CkbRpcClient> TxAssembler<C> {
    pub fn new(ckb_rpc: Arc<C>, pubkey: &PublicKey, network: NetworkType) -> Self {
        let address_payload = AddressPayload::from_pubkey(pubkey);
        let address = Address::new(network, address_payload, true);
        Self { ckb_rpc, address }
    }

    pub async fn fetch_packed_client(
        &self,
        contract_typeid_args: &H256,
        client_id: &String,
    ) -> Result<Option<PackedClient>, Error> {
        let contract_typescript = packed::Script::new_builder()
            .code_hash(TYPE_ID_CODE_HASH.0.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(contract_typeid_args.as_bytes().to_vec().pack())
            .build();
        let type_hash = contract_typescript.calc_script_hash();
        let lightclient_cell_opt = CellSearcher::new(self.ckb_rpc.as_ref())
            .search_cell_by_typescript(&type_hash, &client_id.as_bytes().to_vec())
            .await?;
        match lightclient_cell_opt {
            Some(cell) => {
                if let Err(err) = PackedClientReader::verify(&cell.output_data, false) {
                    Err(Error::rpc_response(format!("client format error: {}", err)))
                } else {
                    Ok(Some(PackedClient::new_unchecked(cell.output_data)))
                }
            }
            None => Ok(None),
        }
    }

    pub async fn assemble_updates_into_transaction(
        &self,
        packed_client: PackedClient,
        packed_proof_update: PackedProofUpdate,
        contract_typeid_args: &H256,
        client_id: &String,
    ) -> Result<(TransactionView, Vec<packed::CellOutput>), Error> {
        let contract_typescript = packed::Script::new_builder()
            .code_hash(TYPE_ID_CODE_HASH.0.pack())
            .hash_type(ScriptHashType::Type.into())
            .args(contract_typeid_args.as_bytes().to_vec().pack())
            .build();
        let searcher = CellSearcher::new(self.ckb_rpc.as_ref());
        let contract_cell = {
            let contract = searcher
                .search_cell(&contract_typescript, PrimaryScriptType::Type)
                .await?;
            match contract {
                Some(cell) => cell,
                None => {
                    return Err(Error::rpc_response(format!(
                        "contract not found: {}",
                        hex::encode(contract_typeid_args)
                    )));
                }
            }
        };
        let contract_cell_dep = packed::CellDep::new_builder()
            .out_point(contract_cell.out_point)
            .dep_type(DepType::Code.into())
            .build();

        let type_hash = contract_typescript.calc_script_hash();
        let lightclient_cell_opt = searcher
            .search_cell_by_typescript(&type_hash, &client_id.as_bytes().to_vec())
            .await?;

        let output_data = packed_client.as_slice().pack();
        let output_cell = packed::CellOutput::new_builder()
            // TODO set the mock lock script for client cell
            //.lock(lock)
            .type_(Some(contract_typescript).pack())
            .build_exact_capacity(Capacity::bytes(output_data.len()).unwrap())
            .expect("build ibc contract output");
        let mut inputs_cell_as_output = vec![];
        let mut inputs_cell = vec![];
        let mut inputs_capacity: u64 = 0;
        if let Some(lightclient_cell) = lightclient_cell_opt {
            inputs_cell.push(packed::CellInput::new(lightclient_cell.out_point, 0));
            inputs_capacity += Unpack::<u64>::unpack(&lightclient_cell.output.capacity());
            inputs_cell_as_output.push(lightclient_cell.output);
        }

        let witness = {
            let input_type_args = packed::BytesOpt::new_builder()
                .set(Some(packed_proof_update.as_slice().pack()))
                .build();
            let witness_args = packed::WitnessArgs::new_builder()
                .input_type(input_type_args)
                .build();
            witness_args.as_bytes()
        };
        let tx = TransactionView::new_advanced_builder()
            .inputs(inputs_cell)
            .output(output_cell)
            .output_data(output_data)
            .witness(witness.pack())
            .cell_dep(contract_cell_dep)
            .build();
        let fee_rate = 1000;
        let (tx, mut new_inputs) = TxCompleter::new(&searcher)
            .complete_tx_with_secp256k1_change(tx, &self.address, inputs_capacity, fee_rate)
            .await?;

        inputs_cell_as_output.append(&mut new_inputs);
        Ok((tx, inputs_cell_as_output))
    }
}
