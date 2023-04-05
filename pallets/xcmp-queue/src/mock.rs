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

use super::*;
use crate as xcmp_queue;
use core::marker::PhantomData;
use cumulus_pallet_parachain_system::AnyRelayNumber;
use cumulus_primitives_core::{IsSystem, ParaId};
use frame_support::{
	parameter_types,
	traits::{Everything, Nothing, OriginTrait},
};
use frame_system::EnsureRoot;
use sp_core::{ConstU32, H256};
use sp_runtime::traits::BlockNumberProvider;
use sp_runtime::{
	testing::Header,
	traits::{BlakeTwo256, IdentityLookup},
};
use xcm::prelude::*;
use xcm_builder::{CurrencyAdapter, FixedWeightBounds, IsConcrete, NativeAsset, ParentIsPreset};
use xcm_executor::traits::{ConvertOrigin, ShouldExecute};

type UncheckedExtrinsic = frame_system::mocking::MockUncheckedExtrinsic<Test>;
type Block = frame_system::mocking::MockBlock<Test>;

// Configure a mock runtime to test the pallet.
frame_support::construct_runtime!(
	pub enum Test where
		Block = Block,
		NodeBlock = Block,
		UncheckedExtrinsic = UncheckedExtrinsic,
	{
		System: frame_system::{Pallet, Call, Config, Storage, Event<T>},
		Balances: pallet_balances::{Pallet, Call, Storage, Config<T>, Event<T>},
		ParachainSystem: cumulus_pallet_parachain_system::{
			Pallet, Call, Config, Storage, Inherent, Event<T>, ValidateUnsigned,
		},
		XcmpQueue: xcmp_queue::{Pallet, Call, Storage, Event<T>},
	}
);

parameter_types! {
	pub const BlockHashCount: u64 = 250;
	pub const SS58Prefix: u8 = 42;
}

type AccountId = u64;

impl frame_system::Config for Test {
	type BaseCallFilter = Everything;
	type BlockWeights = ();
	type BlockLength = ();
	type DbWeight = ();
	type RuntimeOrigin = RuntimeOrigin;
	type RuntimeCall = RuntimeCall;
	type Index = u64;
	type BlockNumber = u64;
	type Hash = H256;
	type Hashing = BlakeTwo256;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
	type Header = Header;
	type RuntimeEvent = RuntimeEvent;
	type BlockHashCount = BlockHashCount;
	type Version = ();
	type PalletInfo = PalletInfo;
	type AccountData = pallet_balances::AccountData<u64>;
	type OnNewAccount = ();
	type OnKilledAccount = ();
	type SystemWeightInfo = ();
	type SS58Prefix = SS58Prefix;
	type OnSetCode = cumulus_pallet_parachain_system::ParachainSetCode<Test>;
	type MaxConsumers = frame_support::traits::ConstU32<16>;
}

parameter_types! {
	pub const ExistentialDeposit: u64 = 5;
	pub const MaxReserves: u32 = 50;
}

impl pallet_balances::Config for Test {
	type Balance = u64;
	type RuntimeEvent = RuntimeEvent;
	type DustRemoval = ();
	type ExistentialDeposit = ExistentialDeposit;
	type AccountStore = System;
	type WeightInfo = ();
	type MaxLocks = ();
	type MaxReserves = MaxReserves;
	type ReserveIdentifier = [u8; 8];
}

impl cumulus_pallet_parachain_system::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type OnSystemEvent = ();
	type SelfParaId = ();
	type OutboundXcmpMessageSource = XcmpQueue;
	type DmpMessageHandler = ();
	type ReservedDmpWeight = ();
	type XcmpMessageHandler = XcmpQueue;
	type ReservedXcmpWeight = ();
	type CheckAssociatedRelayNumber = AnyRelayNumber;
}

parameter_types! {
	pub const RelayChain: MultiLocation = MultiLocation::parent();
	pub UniversalLocation: InteriorMultiLocation = X1(Parachain(1u32.into())).into();
	pub UnitWeightCost: Weight = Weight::from_parts(1_000_000, 1024);
	pub const MaxInstructions: u32 = 100;
	pub const MaxAssetsIntoHolding: u32 = 64;
}

/// Means for transacting assets on this chain.
pub type LocalAssetTransactor = CurrencyAdapter<
	// Use this currency:
	Balances,
	// Use this currency when it is a fungible asset matching the given location or name:
	IsConcrete<RelayChain>,
	// Do a simple punn to convert an AccountId32 MultiLocation into a native chain account ID:
	LocationToAccountId,
	// Our chain's account ID type (we can't get away without mentioning it explicitly):
	AccountId,
	// We don't track any teleports.
	(),
>;

pub type LocationToAccountId = (ParentIsPreset<AccountId>,);

pub struct BarrierMock {}

impl ShouldExecute for BarrierMock {
	fn should_execute<RuntimeCall>(
		_origin: &MultiLocation,
		_instructions: &mut [Instruction<RuntimeCall>],
		_max_weight: Weight,
		_weight_credit: &mut Weight,
	) -> Result<(), ()> {
		Ok(())
	}
}

pub type FixedWeigher = FixedWeightBounds<UnitWeightCost, RuntimeCall, MaxInstructions>;

pub struct XcmConfig;
impl xcm_executor::Config for XcmConfig {
	type RuntimeCall = RuntimeCall;
	type XcmSender = XcmRouter;
	// How to withdraw and deposit an asset.
	type AssetTransactor = LocalAssetTransactor;
	type OriginConverter = ();
	type IsReserve = NativeAsset;
	type IsTeleporter = NativeAsset;
	type UniversalLocation = UniversalLocation;
	type Barrier = BarrierMock;
	type Weigher = FixedWeigher;
	type Trader = ();
	type ResponseHandler = ();
	type AssetTrap = ();
	type AssetClaims = ();
	type SubscriptionService = ();
	type PalletInstancesInfo = AllPalletsWithSystem;
	type MaxAssetsIntoHolding = MaxAssetsIntoHolding;
	type AssetLocker = ();
	type AssetExchanger = ();
	type FeeManager = ();
	type MessageExporter = ();
	type UniversalAliases = Nothing;
	type CallDispatcher = RuntimeCall;
	type SafeCallFilter = Everything;
}

pub type XcmRouter = (
	// XCMP to communicate with the sibling chains.
	XcmpQueue,
);

pub struct SystemParachainAsSuperuser<RuntimeOrigin>(PhantomData<RuntimeOrigin>);
impl<RuntimeOrigin: OriginTrait> ConvertOrigin<RuntimeOrigin>
	for SystemParachainAsSuperuser<RuntimeOrigin>
{
	fn convert_origin(
		origin: impl Into<MultiLocation>,
		kind: OriginKind,
	) -> Result<RuntimeOrigin, MultiLocation> {
		let origin = origin.into();
		if kind == OriginKind::Superuser
			&& matches!(
				origin,
				MultiLocation {
					parents: 1,
					interior: X1(Parachain(id)),
				} if ParaId::from(id).is_system(),
			) {
			Ok(RuntimeOrigin::root())
		} else {
			Err(origin)
		}
	}
}

pub struct XcmDeferFilterMock;

impl XcmDeferFilter<RuntimeCall> for XcmDeferFilterMock {
	fn deferred_by(
		_para: ParaId,
		_sent_at: RelayBlockNumber,
		xcm: &VersionedXcm<RuntimeCall>,
	) -> Option<RelayBlockNumber> {
		let xcm = Xcm::<RuntimeCall>::try_from(xcm.clone()).unwrap();
		let first = xcm.first().unwrap();
		match first {
			ClearOrigin => Some(5),
			ReserveAssetDeposited(_) => Some(5),
			RefundSurplus => Some(42),
			_ => Some(1_000_000),
		}
	}
}

impl Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type XcmExecutor = xcm_executor::XcmExecutor<XcmConfig>;
	type ChannelInfo = ParachainSystem;
	type VersionWrapper = ();
	type ExecuteOverweightOrigin = EnsureRoot<AccountId>;
	type ExecuteDeferredOrigin = EnsureRoot<AccountId>;
	type ControllerOrigin = EnsureRoot<AccountId>;
	type ControllerOriginConverter = SystemParachainAsSuperuser<RuntimeOrigin>;
	type WeightInfo = ();
	type PriceForSiblingDelivery = ();
	type XcmDeferFilter = XcmDeferFilterMock;
	type MaxDeferredMessages = ConstU32<20>;
	type RelayChainBlockNumberProvider = RelayBlockNumberProviderMock;
}

pub struct RelayBlockNumberProviderMock;

impl BlockNumberProvider for RelayBlockNumberProviderMock {
	type BlockNumber = RelayBlockNumber;

	fn current_block_number() -> RelayBlockNumber {
		7
	}
}

pub fn new_test_ext() -> sp_io::TestExternalities {
	let t = frame_system::GenesisConfig::default().build_storage::<Test>().unwrap();

	let mut r: sp_io::TestExternalities = t.into();

	r.execute_with(|| System::set_block_number(1));

	r
}

pub fn create_versioned_reserve_asset_deposited() -> VersionedXcm<RuntimeCall> {
	VersionedXcm::from(Xcm::<RuntimeCall>(vec![Instruction::<RuntimeCall>::ReserveAssetDeposited(
		MultiAssets::new(),
	)]))
}

pub fn format_message(msg: &mut Vec<u8>, encoded_xcm: Vec<u8>) -> &[u8] {
	msg.extend(XcmpMessageFormat::ConcatenatedVersionedXcm.encode());
	msg.extend(encoded_xcm.clone());
	msg
}

pub fn create_bounded_vec(
	deferred_xcm_messages: Vec<DeferredMessage<RuntimeCall>>,
) -> BoundedVec<DeferredMessage<RuntimeCall>, ConstU32<20>> {
	deferred_xcm_messages.try_into().unwrap()
}
