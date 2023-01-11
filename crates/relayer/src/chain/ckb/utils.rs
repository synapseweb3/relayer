use eth2_types::EthSpec;
use eth_light_client_in_ckb_verification::types::{
    core::{Client as EthLcClient, Header as EthLcHeader},
    packed::{self, Client as PackedClient, ProofUpdate as PackedProofUpdate},
    prelude::*,
};
use ibc_relayer_storage::{
    error::Error as StorageError,
    prelude::{StorageAsMMRStore, StorageReader, StorageWriter},
};
use ibc_relayer_types::clients::ics07_eth::types::{Header as EthHeader, Update as EthUpdate};
use tendermint_light_client::errors::Error as LightClientError;

use crate::error::Error;

pub fn get_verified_packed_client_and_proof_update<S, E>(
    chain_id: &String,
    header_updates: Vec<EthUpdate>,
    storage: &S,
    onchain_packed_client: Option<PackedClient>,
) -> Result<(PackedClient, PackedProofUpdate), Error>
where
    S: StorageReader<E> + StorageWriter<E> + StorageAsMMRStore<E>,
    E: EthSpec,
{
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
    if let Some(stored_tip_slot) = storage.get_tip_beacon_header_slot()? {
        if start_slot != stored_tip_slot + 1 {
            let height = (stored_tip_slot + 1).try_into().expect("slot too big");
            return Err(Error::light_client_verification(
                chain_id.clone(),
                LightClientError::missing_last_block_id(height),
            ));
        }
        is_creation = false;
    }
    if let Some(client) = onchain_packed_client {
        let onchain_tip_slot: u64 = client.maximal_slot().unpack();
        if start_slot != onchain_tip_slot + 1 {
            let height = (onchain_tip_slot + 1).try_into().expect("slot too big");
            return Err(Error::light_client_verification(
                chain_id.clone(),
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

    let minimal_slot = storage.get_base_beacon_header_slot()?.unwrap_or(start_slot);
    let last_finalized_header = &finalized_headers[finalized_headers.len() - 1];
    let maximal_slot = last_finalized_header.inner.slot;
    let tip_header_root = last_finalized_header.root;

    // Saves all header digests into storage for MMR.
    {
        let mut finalized_headers_iter = finalized_headers.iter();

        let mut last_slot = if storage.is_initialized()? {
            start_slot - 1
        } else {
            let first = finalized_headers_iter.next().expect("checked");
            storage.initialize_with(first.inner.slot, first.digest())?;
            storage.put_tip_beacon_header_slot(first.inner.slot)?;
            first.inner.slot
        };

        let mut mmr = storage.chain_root_mmr(last_slot)?;

        for header in finalized_headers_iter {
            last_slot = header.inner.slot;
            mmr.push(header.digest()).map_err(StorageError::from)?;
        }
        mmr.commit().map_err(StorageError::from)?;

        storage.put_tip_beacon_header_slot(last_slot)?;
    };

    // Gets the new root and a proof for all new headers.
    let (packed_headers_mmr_root, packed_headers_mmr_proof) = {
        let positions = (start_slot..=maximal_slot)
            .into_iter()
            .map(|slot| slot - minimal_slot)
            .collect::<Vec<_>>();

        let mmr = storage.chain_root_mmr(maximal_slot)?;

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
