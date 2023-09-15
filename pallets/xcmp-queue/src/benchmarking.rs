// Copyright (C) 2021 Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Benchmarking setup for cumulus-pallet-xcmp-queue

use crate::*;

use frame_benchmarking::{benchmarks, impl_benchmark_test_suite};
use frame_system::RawOrigin;

/// The maximum number of instructions we expect in an XCM for the purpose of benchmarking.
/// This is hardcoded because 100 is the default maximum instructions and that is not accessible
const MAX_INSTRUCTIONS: usize = 100;

/// Maximum number of items we expect in a single `MultiAssets` value. Note this is not (yet)
/// enforced, and just serves to provide a sensible upper bound for benchmarking.
/// This value is copied from xcm/src/v3/multiasset.rs
const MAX_ITEMS_IN_MULTIASSETS: u32 = 20;

fn construct_xcm<RuntimeCall>() -> VersionedXcm<RuntimeCall> {
	let assets = (0..MAX_ITEMS_IN_MULTIASSETS)
		.map(|i| (MultiLocation::from(Parachain(i)), 100).into())
		.collect::<Vec<_>>();
	let multi_assets = MultiAssets::from_sorted_and_deduplicated(assets).unwrap();

	let instructions =
		vec![Instruction::<RuntimeCall>::ReserveAssetDeposited(multi_assets); MAX_INSTRUCTIONS];

	VersionedXcm::from(Xcm::<RuntimeCall>(instructions))
}

benchmarks! {
	set_config_with_u32 {}: update_resume_threshold(RawOrigin::Root, 100)
	set_config_with_weight {}: update_weight_restrict_decay(RawOrigin::Root, Weight::from_parts(3_000_000, 0))
	service_deferred {
		let para_id = ParaId::from(999);

		let xcm = construct_xcm::<T::RuntimeCall>();

		let max_messages = T::MaxDeferredMessages::get() as usize;
		let relay_block = T::RelayChainBlockNumberProvider::current_block_number();
		// We set `deferred_to` to the current relay block number to make sure that the messages are serviced.
		let deferred_message = DeferredMessage { sent_at: relay_block, deferred_to: relay_block, sender: para_id, xcm };
		let deferred_xcm_messages = vec![deferred_message.clone(); max_messages];
		crate::Pallet::<T>::inject_deferred_messages(para_id, relay_block, deferred_xcm_messages.try_into().unwrap());
		let max_buckets = T::MaxDeferredBuckets::get();
		let indices: Vec<DeferredIndex> = (1..(max_buckets)).map(|i| (relay_block, i as u16)).collect();
		crate::Pallet::<T>::inject_bare_deferred_indices(para_id, indices);
		assert_eq!(crate::Pallet::<T>::messages_deferred_to(para_id, (relay_block, 0)).len(), max_messages);
		assert_eq!(crate::Pallet::<T>::deferred_indices(para_id).len(), max_buckets as usize);
		// TODO: figure out how to get the weight of the xcm in a production runtime (Weigher not available)
		let weight = Weight::from_parts(1_000_000 - 1_000, 1024);
		assert!(crate::Pallet::<T>::update_xcmp_max_individual_weight(RawOrigin::Root.into(), weight).is_ok());
	} :_(RawOrigin::Root, weight.saturating_add(T::DbWeight::get().reads_writes(max_messages as u64 + 2, 2)), para_id)
	verify
	{
		assert_eq!(crate::Pallet::<T>::messages_deferred_to(para_id, (relay_block, 0)).len(), 0);
		assert_eq!(crate::Pallet::<T>::deferred_indices(para_id).len(), max_buckets as usize - 1);
		// worst case is placing the message in overweight, so check that they end up there
		assert!(Overweight::<T>::contains_key(0));
		assert!(Overweight::<T>::contains_key((max_messages - 1) as u64));
	}
	discard_deferred_bucket {
		let para_id = ParaId::from(999);

		let xcm = construct_xcm::<T::RuntimeCall>();
		let hash = xcm.using_encoded(sp_io::hashing::blake2_256);

		let sent_at = 1;
		let deferred_to = 6;
		let max_messages = T::MaxDeferredMessages::get() as usize;
		let deferred_message = DeferredMessage { sent_at, deferred_to, sender: para_id, xcm };
		let deferred_xcm_messages = vec![deferred_message.clone(); max_messages];
		crate::Pallet::<T>::inject_deferred_messages(para_id, deferred_to, deferred_xcm_messages.try_into().unwrap());
		assert_eq!(crate::Pallet::<T>::messages_deferred_to(para_id, (deferred_to, 0)).len(), max_messages);
	} :discard_deferred(RawOrigin::Root, para_id, (deferred_to, 0), None)
	verify
	{
		assert_eq!(crate::Pallet::<T>::messages_deferred_to(para_id, (deferred_to, 0)).len(), 0);
	}
	discard_deferred_individual {
		let para_id = ParaId::from(999);

		let xcm = construct_xcm::<T::RuntimeCall>();
		let hash = xcm.using_encoded(sp_io::hashing::blake2_256);

		let sent_at = 1;
		let deferred_to = 6;
		let max_messages = T::MaxDeferredMessages::get() as usize;
		let deferred_message = DeferredMessage { sent_at, deferred_to, sender: para_id, xcm };
		let deferred_xcm_messages = vec![deferred_message.clone(); max_messages];
		crate::Pallet::<T>::inject_deferred_messages(para_id, deferred_to, deferred_xcm_messages.try_into().unwrap());
		assert_eq!(crate::Pallet::<T>::messages_deferred_to(para_id, (deferred_to, 0)).len(), max_messages);
	} :discard_deferred(RawOrigin::Root, para_id, (deferred_to, 0), Some(max_messages as u32 - 1))
	verify
	{
		let messages = crate::Pallet::<T>::messages_deferred_to(para_id, (deferred_to, 0));
		assert_eq!(messages.len(), max_messages);
		assert_eq!(messages[max_messages - 1], None);
	}
}

impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
