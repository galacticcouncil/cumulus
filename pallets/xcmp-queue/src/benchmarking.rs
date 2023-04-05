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

benchmarks! {
	set_config_with_u32 {}: update_resume_threshold(RawOrigin::Root, 100)
	set_config_with_weight {}: update_weight_restrict_decay(RawOrigin::Root, Weight::from_parts(3_000_000, 0))
	discard_deferred {
		let para_id = ParaId::from(999);
		let xcm_message = 	VersionedXcm::from(Xcm::<T::RuntimeCall>(vec![Instruction::<T::RuntimeCall>::ReserveAssetDeposited(
			MultiAssets::new(),
		)]));
		let deferred_message = DeferredMessage {
			sent_at: 1,
			deferred_to: 6,
			sender: para_id,
			xcm:xcm_message
		};

		let deferred_xcm_messages = vec![deferred_message];
		let deferred_xcm_messages = deferred_xcm_messages.try_into().unwrap();
		crate::Pallet::<T>::inject_deferred_messages(para_id,deferred_xcm_messages);
		//TODO: continue from here to set up a worst case scenario
	} :_(RawOrigin::Root, para_id, 1, None, None)
	verify
	{
		assert_eq!(crate::Pallet::<T>::deferred_messages(para_id).len(), 0);
	}
}

impl_benchmark_test_suite!(Pallet, crate::mock::new_test_ext(), crate::mock::Test);
