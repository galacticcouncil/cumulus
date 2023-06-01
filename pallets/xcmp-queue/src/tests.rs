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

use crate::mock::*;

use super::*;
use cumulus_primitives_core::XcmpMessageHandler;
use frame_support::traits::OnIdle;
use frame_support::weights::RuntimeDbWeight;
use frame_support::{assert_noop, assert_ok};
use frame_system::EventRecord;
use mock::{new_test_ext, RuntimeCall, RuntimeOrigin, Test, XcmpQueue};
use sp_runtime::traits::BadOrigin;

use pretty_assertions::assert_eq;

#[test]
fn one_message_does_not_panic() {
	new_test_ext().execute_with(|| {
		let message_format = XcmpMessageFormat::ConcatenatedVersionedXcm.encode();
		let messages = vec![(Default::default(), 1u32.into(), message_format.as_slice())];

		// This shouldn't cause a panic
		XcmpQueue::handle_xcmp_messages(messages.into_iter(), Weight::MAX);
	})
}

#[test]
#[should_panic = "Invalid incoming blob message data"]
#[cfg(debug_assertions)]
fn bad_message_is_handled() {
	new_test_ext().execute_with(|| {
		let bad_data = vec![
			1, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 64, 239, 139, 0,
			0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 37, 0,
			0, 0, 0, 0, 0, 0, 16, 0, 127, 147,
		];
		InboundXcmpMessages::<Test>::insert(ParaId::from(1000), 1, bad_data);
		let format = XcmpMessageFormat::ConcatenatedEncodedBlob;
		// This should exit with an error.
		XcmpQueue::process_xcmp_message(
			1000.into(),
			(1, format),
			&mut 0,
			Weight::from_ref_time(10_000_000_000),
			Weight::from_ref_time(10_000_000_000),
		);
	});
}

/// Tests that a blob message is handled. Currently this isn't implemented and panics when debug assertions
/// are enabled. When this feature is enabled, this test should be rewritten properly.
#[test]
#[should_panic = "Blob messages not handled."]
#[cfg(debug_assertions)]
fn handle_blob_message() {
	new_test_ext().execute_with(|| {
		let bad_data = vec![
			1, 1, 1, 1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 64, 239,
			139, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0,
			37, 0, 0, 0, 0, 0, 0, 0, 16, 0, 127, 147,
		];
		InboundXcmpMessages::<Test>::insert(ParaId::from(1000), 1, bad_data);
		let format = XcmpMessageFormat::ConcatenatedEncodedBlob;
		XcmpQueue::process_xcmp_message(
			1000.into(),
			(1, format),
			&mut 0,
			Weight::from_ref_time(10_000_000_000),
			Weight::from_ref_time(10_000_000_000),
		);
	});
}

#[test]
#[should_panic = "Invalid incoming XCMP message data"]
#[cfg(debug_assertions)]
fn handle_invalid_data() {
	new_test_ext().execute_with(|| {
		let data = Xcm::<Test>(vec![]).encode();
		InboundXcmpMessages::<Test>::insert(ParaId::from(1000), 1, data);
		let format = XcmpMessageFormat::ConcatenatedVersionedXcm;
		XcmpQueue::process_xcmp_message(
			1000.into(),
			(1, format),
			&mut 0,
			Weight::from_ref_time(10_000_000_000),
			Weight::from_ref_time(10_000_000_000),
		);
	});
}

#[test]
fn service_overweight_unknown() {
	new_test_ext().execute_with(|| {
		assert_noop!(
			XcmpQueue::service_overweight(RuntimeOrigin::root(), 0, Weight::from_parts(1000, 1000)),
			Error::<Test>::BadOverweightIndex,
		);
	});
}

#[test]
fn service_overweight_bad_xcm_format() {
	new_test_ext().execute_with(|| {
		let bad_xcm = vec![255];
		Overweight::<Test>::insert(0, (ParaId::from(1000), 0, bad_xcm));

		assert_noop!(
			XcmpQueue::service_overweight(RuntimeOrigin::root(), 0, Weight::from_parts(1000, 1000)),
			Error::<Test>::BadXcm
		);
	});
}

#[test]
fn suspend_xcm_execution_works() {
	new_test_ext().execute_with(|| {
		QueueSuspended::<Test>::put(true);

		let xcm =
			VersionedXcm::from(Xcm::<RuntimeCall>(vec![Instruction::<RuntimeCall>::ClearOrigin]))
				.encode();
		let mut message_format = XcmpMessageFormat::ConcatenatedVersionedXcm.encode();
		message_format.extend(xcm.clone());
		let messages = vec![(ParaId::from(999), 1u32.into(), message_format.as_slice())];

		// This should have executed the incoming XCM, because it came from a system parachain
		XcmpQueue::handle_xcmp_messages(messages.into_iter(), Weight::MAX);

		let queued_xcm = InboundXcmpMessages::<Test>::get(ParaId::from(999), 1u32);
		assert!(queued_xcm.is_empty());

		let messages = vec![(ParaId::from(2000), 1u32.into(), message_format.as_slice())];

		// This shouldn't have executed the incoming XCM
		XcmpQueue::handle_xcmp_messages(messages.into_iter(), Weight::MAX);

		let queued_xcm = InboundXcmpMessages::<Test>::get(ParaId::from(2000), 1u32);
		assert_eq!(queued_xcm, xcm);
	});
}

#[test]
fn defer_xcm_execution_works() {
	new_test_ext().execute_with(|| {
		let versioned_xcm = create_versioned_reserve_asset_deposited();
		let hash = versioned_xcm.using_encoded(sp_io::hashing::blake2_256);
		let para_id = ParaId::from(999);
		let mut xcmp_message = Vec::new();
		let messages =
			vec![(para_id, 1u32.into(), format_message(&mut xcmp_message, versioned_xcm.encode()))];

		RelayBlockNumberProviderMock::set(1);
		XcmpQueue::handle_xcmp_messages(messages.into_iter(), Weight::MAX);

		let deferred_message = DeferredMessage {
			sent_at: 1u32.into(),
			sender: para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 6,
		};

		assert_eq!(
			create_bounded_vec(vec![deferred_message]),
			DeferredXcmMessages::<Test>::get(para_id),
		);

		assert_last_event::<Test>(
			Event::XcmDeferred {
				sender: para_id,
				sent_at: 1u32.into(),
				deferred_to: 6u32.into(),
				message_hash: Some(hash),
			}
			.into(),
		);
	});
}

#[test]
fn handle_xcmp_messages_should_be_able_to_store_multiple_messages_at_same_block() {
	new_test_ext().execute_with(|| {
		let versioned_xcm = create_versioned_reserve_asset_deposited();
		let hash = versioned_xcm.using_encoded(sp_io::hashing::blake2_256);
		let para_id = ParaId::from(999);
		let mut xcmp_message = Vec::new();
		let messages =
			vec![(para_id, 1u32.into(), format_message(&mut xcmp_message, versioned_xcm.encode()))];

		RelayBlockNumberProviderMock::set(1);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);
		XcmpQueue::handle_xcmp_messages(messages.into_iter(), Weight::MAX);

		let deferred_message = DeferredMessage {
			sent_at: 1u32.into(),
			sender: para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 6,
		};

		assert_eq!(
			create_bounded_vec(vec![deferred_message.clone(), deferred_message]),
			DeferredXcmMessages::<Test>::get(para_id),
		);

		assert_last_event::<Test>(
			Event::XcmDeferred {
				sender: para_id,
				sent_at: 1u32.into(),
				deferred_to: 6u32.into(),
				message_hash: Some(hash),
			}
			.into(),
		);
	});
}

#[test]
fn handle_xcmp_messages_should_execute_deferred_message_and_remove_from_deferred_storage() {
	new_test_ext().execute_with(|| {
		let versioned_xcm = create_versioned_reserve_asset_deposited();
		let para_id = ParaId::from(999);
		let mut xcmp_message = Vec::new();
		let messages =
			vec![(para_id, 1u32.into(), format_message(&mut xcmp_message, versioned_xcm.encode()))];

		RelayBlockNumberProviderMock::set(1);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);

		let deferred_message = DeferredMessage {
			sent_at: 1u32.into(),
			sender: para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 6,
		};

		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![deferred_message.clone(), deferred_message])
		);

		let QueueConfigData { xcmp_max_individual_weight, .. } = <QueueConfig<Test>>::get();

		XcmpQueue::service_deferred_queues(Weight::MAX, 7, xcmp_max_individual_weight);

		assert_eq!(DeferredXcmMessages::<Test>::get(para_id), create_bounded_vec(vec![]));
	});
}

#[test]
fn on_idle_should_service_deferred_message() {
	new_test_ext().execute_with(|| {
		//Arrange
		let versioned_xcm = create_versioned_reserve_asset_deposited();
		let para_id = ParaId::from(999);
		let mut xcmp_message = Vec::new();
		let messages =
			vec![(para_id, 1u32.into(), format_message(&mut xcmp_message, versioned_xcm.encode()))];

		RelayBlockNumberProviderMock::set(1);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);

		let deferred_message = DeferredMessage {
			sent_at: 1u32.into(),
			sender: para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 6,
		};

		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![deferred_message])
		);
		RelayBlockNumberProviderMock::set(7);

		//Act
		XcmpQueue::on_idle(1, Weight::MAX);

		//Assert
		assert_eq!(DeferredXcmMessages::<Test>::get(para_id), create_bounded_vec(vec![]));
	});
}

#[test]
fn service_deferred_should_execute_deferred_messages() {
	new_test_ext().execute_with(|| {
		//Arrange
		let versioned_xcm = create_versioned_reserve_asset_deposited();
		let hash = versioned_xcm.using_encoded(sp_io::hashing::blake2_256);
		let para_id = ParaId::from(999);
		let para_id2 = ParaId::from(1000);
		let mut xcmp_message = Vec::new();
		let mut xcmp_message2 = Vec::new();
		let messages = vec![
			(para_id, 1u32.into(), format_message(&mut xcmp_message, versioned_xcm.encode())),
			(para_id2, 2u32.into(), format_message(&mut xcmp_message2, versioned_xcm.encode())),
		];

		RelayBlockNumberProviderMock::set(2);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);

		let deferred_message = DeferredMessage {
			sent_at: 1u32.into(),
			sender: para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 7,
		};

		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![deferred_message])
		);
		RelayBlockNumberProviderMock::set(7);

		//Act
		assert_ok!(XcmpQueue::service_deferred(RuntimeOrigin::root(), Weight::MAX, para_id));

		//Assert
		assert_eq!(DeferredXcmMessages::<Test>::get(para_id), create_bounded_vec(vec![]));
		let deferred_message = DeferredMessage {
			sent_at: 2u32.into(),
			sender: para_id2,
			xcm: versioned_xcm.clone(),
			deferred_to: 7,
		};

		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id2),
			create_bounded_vec(vec![deferred_message])
		);
		assert_last_event::<Test>(
			Event::Success { message_hash: Some(hash), weight: Weight::from_parts(1000000, 1024) }
				.into(),
		);
	});
}

#[test]
fn service_deferred_should_fail_when_called_with_wrong_origin() {
	new_test_ext().execute_with(|| {
		//Arrange
		let versioned_xcm = create_versioned_reserve_asset_deposited();
		let para_id = ParaId::from(999);
		let mut xcmp_message = Vec::new();
		let messages =
			vec![(para_id, 1u32.into(), format_message(&mut xcmp_message, versioned_xcm.encode()))];

		RelayBlockNumberProviderMock::set(1);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);

		let deferred_message = DeferredMessage {
			sent_at: 1u32.into(),
			sender: para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 6,
		};

		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![deferred_message])
		);

		//Act and assert
		assert_noop!(
			XcmpQueue::service_deferred(RuntimeOrigin::signed(100), Weight::MAX, para_id),
			BadOrigin
		);
	});
}

#[test]
fn service_deferred_queues_should_pass_overweight_messages_to_overweight_queue() {
	new_test_ext().execute_with(|| {
		//Arrange
		use xcm_executor::traits::WeightBounds;
		let mut xcm = Xcm::<RuntimeCall>(vec![Instruction::<RuntimeCall>::ReserveAssetDeposited(
			MultiAssets::new(),
		)]);
		// We just set a very low max_inidividual_weight to trigger the overweight logic
		let low_max_weight = Weight::from_parts(100, 1);
		assert!(FixedWeigher::weight(&mut xcm).unwrap().any_gt(low_max_weight));
		let versioned_xcm = VersionedXcm::from(xcm);
		let para_id = ParaId::from(999);
		let mut xcmp_message = Vec::new();
		let encoded_xcm = versioned_xcm.encode();
		let messages =
			vec![(para_id, 1u32.into(), format_message(&mut xcmp_message, encoded_xcm.clone()))];

		RelayBlockNumberProviderMock::set(1);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);

		let deferred_message = DeferredMessage {
			sent_at: 1u32.into(),
			sender: para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 6,
		};
		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![deferred_message])
		);
		assert_eq!(Overweight::<Test>::count(), 0);

		//Act
		XcmpQueue::service_deferred_queues(low_max_weight, 7, low_max_weight);

		//Assert
		assert_eq!(DeferredXcmMessages::<Test>::get(para_id), create_bounded_vec(vec![]));
		assert_eq!(Overweight::<Test>::get(0), Some((ParaId::from(999), 1, encoded_xcm)));
		assert_eq!(Overweight::<Test>::count(), 1);
	});
}

#[test]
fn service_deferred_queues_should_stop_processing_when_weight_limit_is_reached_for_different_queues(
) {
	new_test_ext().execute_with(|| {
		//Arrange
		use xcm_executor::traits::WeightBounds;
		let mut xcm = Xcm::<RuntimeCall>(vec![Instruction::<RuntimeCall>::ReserveAssetDeposited(
			MultiAssets::new(),
		)]);
		// We just set a very low max weight to stop processing deferred messages early
		let db_weights: RuntimeDbWeight = <Test as frame_system::Config>::DbWeight::get();
		let low_max_weight = FixedWeigher::weight(&mut xcm)
			.unwrap()
			.saturating_add(db_weights.reads_writes(1, 1));
		let versioned_xcm = VersionedXcm::from(xcm);
		let para_id = ParaId::from(999);
		let second_para_id = ParaId::from(1000);
		let mut xcmp_message = Vec::new();
		let formatted_msg = format_message(&mut xcmp_message, versioned_xcm.encode());
		let messages = vec![
			(para_id, 1u32.into(), formatted_msg),
			(second_para_id, 1u32.into(), formatted_msg),
		];

		RelayBlockNumberProviderMock::set(1);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);

		let deferred_message = DeferredMessage {
			sent_at: 1u32.into(),
			sender: para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 6,
		};
		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![deferred_message])
		);
		let second_deferred_message = DeferredMessage {
			sent_at: 1u32.into(),
			sender: second_para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 6,
		};
		assert_eq!(
			DeferredXcmMessages::<Test>::get(second_para_id),
			create_bounded_vec(vec![second_deferred_message.clone()])
		);

		let QueueConfigData { xcmp_max_individual_weight, .. } = <QueueConfig<Test>>::get();
		//Act
		XcmpQueue::service_deferred_queues(low_max_weight, 7, xcmp_max_individual_weight);

		//Assert
		assert_eq!(DeferredXcmMessages::<Test>::get(para_id), create_bounded_vec(vec![]));
		assert_eq!(
			DeferredXcmMessages::<Test>::get(second_para_id),
			create_bounded_vec(vec![second_deferred_message])
		);
	});
}

#[test]
fn service_deferred_queues_should_stop_processing_when_weight_limit_is_reached_for_the_same_queue()
{
	new_test_ext().execute_with(|| {
		//Arrange
		use xcm_executor::traits::WeightBounds;
		let mut xcm = Xcm::<RuntimeCall>(vec![Instruction::<RuntimeCall>::ReserveAssetDeposited(
			MultiAssets::new(),
		)]);
		// We just set a very low max weight to stop processing deferred messages early
		let db_weights: RuntimeDbWeight = <Test as frame_system::Config>::DbWeight::get();
		let low_max_weight = FixedWeigher::weight(&mut xcm)
			.unwrap()
			.saturating_add(db_weights.reads_writes(1, 1));
		let versioned_xcm = VersionedXcm::from(xcm);
		let para_id = ParaId::from(999);
		let mut xcmp_message = Vec::new();
		let mut xcms = Vec::new();
		xcms.extend(versioned_xcm.encode());
		// We put the same message again, so that we can stop after the first one.
		xcms.extend(versioned_xcm.encode());
		let messages = vec![(para_id, 1u32.into(), format_message(&mut xcmp_message, xcms))];

		RelayBlockNumberProviderMock::set(1);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);

		let deferred_message = DeferredMessage {
			sent_at: 1u32.into(),
			sender: para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 6,
		};
		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![deferred_message.clone(), deferred_message.clone()])
		);

		let QueueConfigData { xcmp_max_individual_weight, .. } = <QueueConfig<Test>>::get();
		//Act
		XcmpQueue::service_deferred_queues(low_max_weight, 7, xcmp_max_individual_weight);

		//Assert
		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![deferred_message])
		);
	});
}

#[test]
fn discard_deferred_should_remove_message_from_storage() {
	new_test_ext().execute_with(|| {
		//Arrange
		let versioned_xcm = create_versioned_reserve_asset_deposited();
		let second_versioned_xcm =
			VersionedXcm::from(Xcm::<RuntimeCall>(vec![Instruction::<RuntimeCall>::ClearOrigin]));
		let para_id = ParaId::from(999);
		let mut xcms = Vec::new();
		xcms.extend(versioned_xcm.encode());
		// We put the same message that we will remove to test whether messages with the same hash but different block get removed
		xcms.extend(second_versioned_xcm.encode());
		let mut xcmp_message = Vec::new();
		let messages = vec![(para_id, 1u32.into(), format_message(&mut xcmp_message, xcms))];

		RelayBlockNumberProviderMock::set(1);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);

		let second_hash = second_versioned_xcm.using_encoded(sp_io::hashing::blake2_256);
		let mut second_xcms = Vec::new();
		// We put the same message twice to test removal of identical messages
		second_xcms.extend(second_versioned_xcm.encode());
		second_xcms.extend(second_versioned_xcm.encode());
		let mut second_xcmp_message = Vec::new();
		let second_messages =
			vec![(para_id, 2u32.into(), format_message(&mut second_xcmp_message, second_xcms))];
		RelayBlockNumberProviderMock::set(2);
		XcmpQueue::handle_xcmp_messages(second_messages.clone().into_iter(), Weight::MAX);

		let deferred_message = DeferredMessage {
			sent_at: 1,
			sender: para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 6,
		};
		let second_deferred_message = DeferredMessage {
			sent_at: 1,
			sender: para_id,
			xcm: second_versioned_xcm.clone(),
			deferred_to: 6,
		};
		let message_to_remove = DeferredMessage {
			sent_at: 2,
			sender: para_id,
			xcm: second_versioned_xcm.clone(),
			deferred_to: 7,
		};

		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![
				deferred_message.clone(),
				second_deferred_message.clone(),
				message_to_remove.clone(),
				message_to_remove
			])
		);

		//Act
		assert_ok!(XcmpQueue::discard_deferred(
			RuntimeOrigin::root(),
			para_id,
			2,
			Some(7),
			Some(second_hash)
		));

		//Assert
		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![deferred_message, second_deferred_message])
		);
	});
}

#[test]
fn discard_deferred_should_remove_messages_when_only_required_params_specified() {
	new_test_ext().execute_with(|| {
		//Arrange
		let versioned_xcm = create_versioned_reserve_asset_deposited();
		let second_versioned_xcm =
			VersionedXcm::from(Xcm::<RuntimeCall>(vec![Instruction::<RuntimeCall>::ClearOrigin]));
		let para_id = ParaId::from(999);
		let mut xcms = Vec::new();
		xcms.extend(versioned_xcm.encode());
		// We put the same message that we will remove to test whether messages with the same hash but different block get removed
		xcms.extend(second_versioned_xcm.encode());
		let mut xcmp_message = Vec::new();
		let messages = vec![(para_id, 1u32.into(), format_message(&mut xcmp_message, xcms))];

		RelayBlockNumberProviderMock::set(1);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);

		let mut second_xcmp_message = Vec::new();
		let second_messages = vec![(
			para_id,
			2u32.into(),
			format_message(&mut second_xcmp_message, second_versioned_xcm.encode()),
		)];
		RelayBlockNumberProviderMock::set(2);
		XcmpQueue::handle_xcmp_messages(second_messages.clone().into_iter(), Weight::MAX);

		let deferred_message = DeferredMessage {
			sent_at: 1,
			sender: para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 6,
		};
		let second_deferred_message = DeferredMessage {
			sent_at: 1,
			sender: para_id,
			xcm: second_versioned_xcm.clone(),
			deferred_to: 6,
		};
		let third_message = DeferredMessage {
			sent_at: 2,
			sender: para_id,
			xcm: second_versioned_xcm.clone(),
			deferred_to: 7,
		};

		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![
				deferred_message.clone(),
				second_deferred_message.clone(),
				third_message.clone()
			])
		);

		//Act
		assert_ok!(XcmpQueue::discard_deferred(RuntimeOrigin::root(), para_id, 1, None, None));

		//Assert
		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![third_message])
		);
	});
}

#[test]
fn discard_deferred_should_remove_correct_messages_when_only_required_params_and_deferred_to_are_specified(
) {
	new_test_ext().execute_with(|| {
		//Arrange
		let versioned_xcm = create_versioned_reserve_asset_deposited();
		// we defined a custom deferral period for RefundSurplus in the mocks
		let second_versioned_xcm =
			VersionedXcm::from(Xcm::<RuntimeCall>(vec![Instruction::<RuntimeCall>::RefundSurplus]));
		let para_id = ParaId::from(999);
		let mut xcms = Vec::new();
		xcms.extend(versioned_xcm.encode());
		// We put the same message that we will remove to test whether messages with the same hash but different block get removed
		xcms.extend(second_versioned_xcm.encode());
		let mut xcmp_message = Vec::new();
		let messages = vec![(para_id, 1u32.into(), format_message(&mut xcmp_message, xcms))];

		RelayBlockNumberProviderMock::set(1);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);

		let mut second_xcmp_message = Vec::new();
		let second_messages = vec![(
			para_id,
			2u32.into(),
			format_message(&mut second_xcmp_message, second_versioned_xcm.encode()),
		)];
		RelayBlockNumberProviderMock::set(2);
		XcmpQueue::handle_xcmp_messages(second_messages.clone().into_iter(), Weight::MAX);

		let deferred_message = DeferredMessage {
			sent_at: 1,
			sender: para_id,
			xcm: versioned_xcm.clone(),
			deferred_to: 6,
		};
		let second_deferred_message = DeferredMessage {
			sent_at: 1,
			sender: para_id,
			xcm: second_versioned_xcm.clone(),
			deferred_to: 43,
		};
		let third_message = DeferredMessage {
			sent_at: 2,
			sender: para_id,
			xcm: second_versioned_xcm.clone(),
			deferred_to: 44,
		};

		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![
				deferred_message.clone(),
				second_deferred_message.clone(),
				third_message.clone()
			])
		);

		//Act
		assert_ok!(XcmpQueue::discard_deferred(RuntimeOrigin::root(), para_id, 1, Some(43), None));

		//Assert
		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![deferred_message, third_message])
		);
	});
}

#[test]
fn handle_xcmp_messages_should_execute_deferred_message_from_different_blocks() {
	new_test_ext().execute_with(|| {
		//Arrange
		let versioned_xcm = create_versioned_reserve_asset_deposited();

		let para_id = ParaId::from(999);
		let para_id_2 = ParaId::from(1000);

		let mut xcmp_message = Vec::new();
		let formatted_msg = format_message(&mut xcmp_message, versioned_xcm.encode());
		let messages = vec![(para_id, 1u32.into(), formatted_msg)];
		let messages2 = vec![(para_id_2, 2u32.into(), formatted_msg)];

		RelayBlockNumberProviderMock::set(1);
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);
		RelayBlockNumberProviderMock::set(2);
		XcmpQueue::handle_xcmp_messages(messages2.clone().into_iter(), Weight::MAX);

		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id),
			create_bounded_vec(vec![DeferredMessage {
				sent_at: 1u32.into(),
				sender: para_id,
				xcm: versioned_xcm.clone(),
				deferred_to: 6
			}])
		);
		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id_2),
			create_bounded_vec(vec![DeferredMessage {
				sent_at: 2u32.into(),
				sender: para_id_2,
				xcm: versioned_xcm.clone(),
				deferred_to: 7
			}])
		);

		let QueueConfigData { xcmp_max_individual_weight, .. } = <QueueConfig<Test>>::get();

		//Act
		XcmpQueue::service_deferred_queues(Weight::MAX, 6, xcmp_max_individual_weight);

		//Assert
		assert_eq!(DeferredXcmMessages::<Test>::get(para_id), create_bounded_vec(vec![]));
		assert_eq!(
			DeferredXcmMessages::<Test>::get(para_id_2),
			create_bounded_vec(vec![DeferredMessage {
				sent_at: 2u32.into(),
				sender: para_id_2,
				xcm: versioned_xcm.clone(),
				deferred_to: 7
			}])
		);
	});
}

#[test]
fn deferred_xcm_should_be_executed_and_removed_from_storage() {
	new_test_ext().execute_with(|| {
		//Arrange
		let versioned_xcm = create_versioned_reserve_asset_deposited();
		let xcm = versioned_xcm.encode();
		let para_id = ParaId::from(999);
		let mut xcmp_message = Vec::new();
		let formatted_msg = format_message(&mut xcmp_message, xcm.clone());
		let messages = vec![(para_id, 1u32.into(), formatted_msg)];
		RelayBlockNumberProviderMock::set(1);

		//Act
		XcmpQueue::handle_xcmp_messages(messages.clone().into_iter(), Weight::MAX);
		let messages = vec![(para_id, 6u32.into(), formatted_msg)];
		RelayBlockNumberProviderMock::set(6);
		XcmpQueue::handle_xcmp_messages(messages.into_iter(), Weight::MAX);

		//Assert
		let expected_msg =
			DeferredMessage { sent_at: 6, deferred_to: 11, xcm: versioned_xcm, sender: para_id };

		assert_eq!(
			create_bounded_vec(vec![expected_msg]),
			DeferredXcmMessages::<Test>::get(para_id)
		);
	});
}

#[test]
fn handle_xcmp_messages_should_both_defer_and_execute_xcm_message() {
	new_test_ext().execute_with(|| {
		//Arrange
		let assets = MultiAssets::new();
		let versioned_xcm = VersionedXcm::from(Xcm::<RuntimeCall>(vec![
			Instruction::<RuntimeCall>::ReserveAssetDeposited(assets),
		]));
		let xcm = versioned_xcm.encode();
		let mut message_format = XcmpMessageFormat::ConcatenatedVersionedXcm.encode();
		message_format.extend(xcm.clone());
		let messages = vec![(ParaId::from(999), 1u32.into(), message_format.as_slice())];
		let messages2 = vec![(ParaId::from(1000), 7u32.into(), message_format.as_slice())];
		RelayBlockNumberProviderMock::set(1);

		//Act
		XcmpQueue::handle_xcmp_messages(messages.into_iter(), Weight::MAX);
		let expected_msg = DeferredMessage {
			sent_at: 1,
			deferred_to: 6,
			xcm: versioned_xcm.clone(),
			sender: ParaId::from(999),
		};
		assert_eq!(
			DeferredXcmMessages::<Test>::get(ParaId::from(999)),
			create_bounded_vec(vec![expected_msg])
		);
		RelayBlockNumberProviderMock::set(7);
		XcmpQueue::handle_xcmp_messages(messages2.into_iter(), Weight::MAX);

		assert_eq!(DeferredXcmMessages::<Test>::get(ParaId::from(999)), create_bounded_vec(vec![]));

		let expected_msg = DeferredMessage {
			sent_at: 7,
			deferred_to: 12,
			xcm: versioned_xcm,
			sender: ParaId::from(1000),
		};
		assert_eq!(
			DeferredXcmMessages::<Test>::get(ParaId::from(1000)),
			create_bounded_vec(vec![expected_msg])
		);
	});
}

#[test]
fn update_suspend_threshold_works() {
	new_test_ext().execute_with(|| {
		let data: QueueConfigData = <QueueConfig<Test>>::get();
		assert_eq!(data.suspend_threshold, 2);
		assert_ok!(XcmpQueue::update_suspend_threshold(RuntimeOrigin::root(), 3));
		assert_noop!(XcmpQueue::update_suspend_threshold(RuntimeOrigin::signed(2), 5), BadOrigin);
		let data: QueueConfigData = <QueueConfig<Test>>::get();

		assert_eq!(data.suspend_threshold, 3);
	});
}

#[test]
fn update_drop_threshold_works() {
	new_test_ext().execute_with(|| {
		let data: QueueConfigData = <QueueConfig<Test>>::get();
		assert_eq!(data.drop_threshold, 5);
		assert_ok!(XcmpQueue::update_drop_threshold(RuntimeOrigin::root(), 6));
		assert_noop!(XcmpQueue::update_drop_threshold(RuntimeOrigin::signed(2), 7), BadOrigin);
		let data: QueueConfigData = <QueueConfig<Test>>::get();

		assert_eq!(data.drop_threshold, 6);
	});
}

#[test]
fn update_resume_threshold_works() {
	new_test_ext().execute_with(|| {
		let data: QueueConfigData = <QueueConfig<Test>>::get();
		assert_eq!(data.resume_threshold, 1);
		assert_ok!(XcmpQueue::update_resume_threshold(RuntimeOrigin::root(), 2));
		assert_noop!(XcmpQueue::update_resume_threshold(RuntimeOrigin::signed(7), 3), BadOrigin);
		let data: QueueConfigData = <QueueConfig<Test>>::get();

		assert_eq!(data.resume_threshold, 2);
	});
}

#[test]
fn update_threshold_weight_works() {
	new_test_ext().execute_with(|| {
		let data: QueueConfigData = <QueueConfig<Test>>::get();
		assert_eq!(data.threshold_weight, Weight::from_ref_time(100_000));
		assert_ok!(XcmpQueue::update_threshold_weight(
			RuntimeOrigin::root(),
			Weight::from_ref_time(10_000)
		));
		assert_noop!(
			XcmpQueue::update_threshold_weight(
				RuntimeOrigin::signed(5),
				Weight::from_ref_time(10_000_000),
			),
			BadOrigin
		);
		let data: QueueConfigData = <QueueConfig<Test>>::get();

		assert_eq!(data.threshold_weight, Weight::from_ref_time(10_000));
	});
}

#[test]
fn update_weight_restrict_decay_works() {
	new_test_ext().execute_with(|| {
		let data: QueueConfigData = <QueueConfig<Test>>::get();
		assert_eq!(data.weight_restrict_decay, Weight::from_ref_time(2));
		assert_ok!(XcmpQueue::update_weight_restrict_decay(
			RuntimeOrigin::root(),
			Weight::from_ref_time(5)
		));
		assert_noop!(
			XcmpQueue::update_weight_restrict_decay(
				RuntimeOrigin::signed(6),
				Weight::from_ref_time(4),
			),
			BadOrigin
		);
		let data: QueueConfigData = <QueueConfig<Test>>::get();

		assert_eq!(data.weight_restrict_decay, Weight::from_ref_time(5));
	});
}

#[test]
fn update_xcmp_max_individual_weight() {
	new_test_ext().execute_with(|| {
		let data: QueueConfigData = <QueueConfig<Test>>::get();
		assert_eq!(
			data.xcmp_max_individual_weight,
			Weight::from_parts(20u64 * WEIGHT_REF_TIME_PER_MILLIS, DEFAULT_POV_SIZE),
		);
		assert_ok!(XcmpQueue::update_xcmp_max_individual_weight(
			RuntimeOrigin::root(),
			Weight::from_ref_time(30u64 * WEIGHT_REF_TIME_PER_MILLIS)
		));
		assert_noop!(
			XcmpQueue::update_xcmp_max_individual_weight(
				RuntimeOrigin::signed(3),
				Weight::from_ref_time(10u64 * WEIGHT_REF_TIME_PER_MILLIS)
			),
			BadOrigin
		);
		let data: QueueConfigData = <QueueConfig<Test>>::get();

		assert_eq!(
			data.xcmp_max_individual_weight,
			Weight::from_ref_time(30u64 * WEIGHT_REF_TIME_PER_MILLIS)
		);
	});
}

/// Validates [`validate`] for required Some(destination) and Some(message)
struct OkFixedXcmHashWithAssertingRequiredInputsSender;
impl OkFixedXcmHashWithAssertingRequiredInputsSender {
	const FIXED_XCM_HASH: [u8; 32] = [9; 32];

	fn fixed_delivery_asset() -> MultiAssets {
		MultiAssets::new()
	}

	fn expected_delivery_result() -> Result<(XcmHash, MultiAssets), SendError> {
		Ok((Self::FIXED_XCM_HASH, Self::fixed_delivery_asset()))
	}
}
impl SendXcm for OkFixedXcmHashWithAssertingRequiredInputsSender {
	type Ticket = ();

	fn validate(
		destination: &mut Option<MultiLocation>,
		message: &mut Option<Xcm<()>>,
	) -> SendResult<Self::Ticket> {
		assert!(destination.is_some());
		assert!(message.is_some());
		Ok(((), OkFixedXcmHashWithAssertingRequiredInputsSender::fixed_delivery_asset()))
	}

	fn deliver(_: Self::Ticket) -> Result<XcmHash, SendError> {
		Ok(Self::FIXED_XCM_HASH)
	}
}

#[test]
fn xcmp_queue_does_not_consume_dest_or_msg_on_not_applicable() {
	// dummy message
	let message = Xcm(vec![Trap(5)]);

	// XcmpQueue - check dest is really not applicable
	let dest = (Parent, Parent, Parent);
	let mut dest_wrapper = Some(dest.clone().into());
	let mut msg_wrapper = Some(message.clone());
	assert_eq!(
		Err(SendError::NotApplicable),
		<XcmpQueue as SendXcm>::validate(&mut dest_wrapper, &mut msg_wrapper)
	);

	// check wrapper were not consumed
	assert_eq!(Some(dest.clone().into()), dest_wrapper.take());
	assert_eq!(Some(message.clone()), msg_wrapper.take());

	// another try with router chain with asserting sender
	assert_eq!(
		OkFixedXcmHashWithAssertingRequiredInputsSender::expected_delivery_result(),
		send_xcm::<(XcmpQueue, OkFixedXcmHashWithAssertingRequiredInputsSender)>(
			dest.into(),
			message
		)
	);
}

#[test]
fn xcmp_queue_consumes_dest_and_msg_on_ok_validate() {
	// dummy message
	let message = Xcm(vec![Trap(5)]);

	// XcmpQueue - check dest/msg is valid
	let dest = (Parent, X1(Parachain(5555)));
	let mut dest_wrapper = Some(dest.clone().into());
	let mut msg_wrapper = Some(message.clone());
	assert!(<XcmpQueue as SendXcm>::validate(&mut dest_wrapper, &mut msg_wrapper).is_ok());

	// check wrapper were consumed
	assert_eq!(None, dest_wrapper.take());
	assert_eq!(None, msg_wrapper.take());

	new_test_ext().execute_with(|| {
		// another try with router chain with asserting sender
		assert_eq!(
			Err(SendError::Transport("NoChannel")),
			send_xcm::<(XcmpQueue, OkFixedXcmHashWithAssertingRequiredInputsSender)>(
				dest.into(),
				message
			)
		);
	});
}

fn assert_last_event<T: Config>(generic_event: <T as Config>::RuntimeEvent) {
	let events = frame_system::Pallet::<T>::events();
	let system_event: <T as frame_system::Config>::RuntimeEvent = generic_event.into();
	// compare to the last event record
	let EventRecord { event, .. } = &events[events.len() - 1];
	assert_eq!(event, &system_event);
}
