// Copyright 2021 Parity Technologies (UK) Ltd.
// This file is part of Cumulus.

// Cumulus is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Cumulus is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Cumulus.  If not, see <http://www.gnu.org/licenses/>.

//! Autogenerated weights for `cumulus_pallet_xcmp_queue`
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 4.0.0-dev
//! DATE: 2023-02-27, STEPS: `50`, REPEAT: `20`, LOW RANGE: `[]`, HIGH RANGE: `[]`
//! WORST CASE MAP SIZE: `1000000`
//! HOSTNAME: `runner-9fxy16xz-project-238-concurrent-0`, CPU: `Intel(R) Xeon(R) CPU @ 2.60GHz`
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("statemine-dev"), DB CACHE: 1024

// Executed Command:
// ./artifacts/polkadot-parachain
// benchmark
// pallet
// --chain=statemine-dev
// --execution=wasm
// --wasm-execution=compiled
// --pallet=cumulus_pallet_xcmp_queue
// --extrinsic=*
// --steps=50
// --repeat=20
// --json
// --header=./file_header.txt
// --output=./parachains/runtimes/assets/statemine/src/weights/cumulus_pallet_xcmp_queue.rs

#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::Weight};
use sp_std::marker::PhantomData;

/// Weight functions for `cumulus_pallet_xcmp_queue`.
pub struct WeightInfo<T>(PhantomData<T>);
impl<T: frame_system::Config> cumulus_pallet_xcmp_queue::WeightInfo for WeightInfo<T> {
	/// Storage: XcmpQueue QueueConfig (r:1 w:1)
	/// Proof Skipped: XcmpQueue QueueConfig (max_values: Some(1), max_size: None, mode: Measured)
	fn set_config_with_u32() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `76`
		//  Estimated: `571`
		// Minimum execution time: 4_840 nanoseconds.
		Weight::from_parts(5_169_000, 571)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	/// Storage: XcmpQueue QueueConfig (r:1 w:1)
	/// Proof Skipped: XcmpQueue QueueConfig (max_values: Some(1), max_size: None, mode: Measured)
	fn set_config_with_weight() -> Weight {
		// Proof Size summary in bytes:
		//  Measured:  `76`
		//  Estimated: `571`
		// Minimum execution time: 4_743 nanoseconds.
		Weight::from_parts(5_184_000, 571)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
	// Storage: XcmpQueue QueueConfig (r:1 w:0)
	// Proof Skipped: XcmpQueue QueueConfig (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: XcmpQueue DeferredXcmMessages (r:1 w:1)
	// Proof Skipped: XcmpQueue DeferredXcmMessages (max_values: None, max_size: None, mode: Measured)
	// Storage: XcmpQueue CounterForOverweight (r:1 w:1)
	// Proof: XcmpQueue CounterForOverweight (max_values: Some(1), max_size: Some(4), added: 499, mode: MaxEncodedLen)
	// Storage: XcmpQueue OverweightCount (r:1 w:1)
	// Proof Skipped: XcmpQueue OverweightCount (max_values: Some(1), max_size: None, mode: Measured)
	// Storage: XcmpQueue Overweight (r:100 w:100)
	// Proof Skipped: XcmpQueue Overweight (max_values: None, max_size: None, mode: Measured)
	fn service_deferred() -> Weight {
		// Minimum execution time: 90_934_683 nanoseconds.
		Weight::from_ref_time(91_491_151_000)
			.saturating_add(T::DbWeight::get().reads(104))
			.saturating_add(T::DbWeight::get().writes(103))
	}
	// Storage: XcmpQueue DeferredXcmMessages (r:1 w:1)
	// Proof Skipped: XcmpQueue DeferredXcmMessages (max_values: None, max_size: None, mode: Measured)
	fn discard_deferred() -> Weight {
		// Minimum execution time: 62_131_073 nanoseconds.
		Weight::from_ref_time(63_092_826_000)
			.saturating_add(T::DbWeight::get().reads(1))
			.saturating_add(T::DbWeight::get().writes(1))
	}
}
