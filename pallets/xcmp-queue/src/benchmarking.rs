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
		let deferred_message = DeferredMessage { sent_at: 1, deferred_to: 6, sender: para_id, xcm };
		let deferred_xcm_messages = vec![deferred_message.clone(); max_messages];
		crate::Pallet::<T>::inject_deferred_messages(para_id, deferred_xcm_messages.try_into().unwrap());
		assert_eq!(crate::Pallet::<T>::deferred_messages(para_id).len(), max_messages);
	} :_(RawOrigin::Root, Weight::MAX, para_id)
	verify
	{
		assert_eq!(crate::Pallet::<T>::deferred_messages(para_id).len(), 0);
	}
	discard_deferred {
		let para_id = ParaId::from(999);

		let xcm = construct_xcm::<T::RuntimeCall>();
		let hash = xcm.using_encoded(sp_io::hashing::blake2_256);

		let sent_at = 1;
		let deferred_to = 6;
		let max_messages = T::MaxDeferredMessages::get() as usize;
		let deferred_message = DeferredMessage { sent_at, deferred_to, sender: para_id, xcm };
		let deferred_xcm_messages = vec![deferred_message.clone(); max_messages];
		crate::Pallet::<T>::inject_deferred_messages(para_id, deferred_xcm_messages.try_into().unwrap());
		assert_eq!(crate::Pallet::<T>::deferred_messages(para_id).len(), max_messages);
	} :_(RawOrigin::Root, para_id, sent_at, Some(deferred_to), Some(hash))
	verify
	{
		assert_eq!(crate::Pallet::<T>::deferred_messages(para_id).len(), 0);
	}
}

impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
