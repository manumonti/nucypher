import os
import random

import pytest
import pytest_twisted
from eth_utils import keccak
from nucypher_core import SessionStaticSecret
from twisted.internet import reactor
from twisted.internet.task import deferLater

from nucypher.blockchain.eth.agents import CoordinatorAgent
from nucypher.blockchain.eth.constants import NULL_ADDRESS
from nucypher.blockchain.eth.models import Coordinator
from nucypher.crypto.powers import TransactingPower
from tests.utils.dkg import generate_fake_ritual_transcript, threshold_from_shares


@pytest.fixture(scope='module')
def agent(coordinator_agent) -> CoordinatorAgent:
    return coordinator_agent


@pytest.mark.usefixtures("ursulas")
@pytest.fixture(scope="module")
def cohort(staking_providers):
    # "ursulas" fixture is needed to set provider public key
    deployer, cohort_provider_1, cohort_provider_2, *everybody_else = staking_providers
    cohort_providers = [cohort_provider_1, cohort_provider_2]
    cohort_providers.sort()  # providers must be sorted
    return cohort_providers


@pytest.fixture(scope='module')
def cohort_ursulas(cohort, taco_application_agent):
    ursulas_for_cohort = []
    for provider in cohort:
        operator = taco_application_agent.get_operator_from_staking_provider(provider)
        ursulas_for_cohort.append(operator)

    return ursulas_for_cohort


@pytest.fixture(scope="module")
def transacting_powers(accounts, cohort_ursulas):
    return [
        TransactingPower(account=ursula, signer=accounts.get_account_signer(ursula))
        for ursula in cohort_ursulas
    ]


@pytest.fixture(scope="module")
def incoming_validator(staking_providers, cohort):
    return staking_providers[
        len(cohort) + 1
    ]  # deployer + cohort ursulas already assigned


@pytest.fixture(scope="module")
def departing_validator(cohort):
    # randomize departing validator from the cohort
    return cohort[random.randint(0, len(cohort) - 1)]


def test_coordinator_properties(agent):
    assert len(agent.contract_address) == 42
    assert agent.contract.address == agent.contract_address
    assert agent.contract_name == CoordinatorAgent.contract_name


@pytest.mark.usefixtures("ursulas")
def test_initiate_ritual(
    accounts,
    agent,
    cohort,
    get_random_checksum_address,
    fee_model,
    global_allow_list,
    transacting_powers,
    ritual_token,
    testerchain,
    initiator,
):
    number_of_rituals = agent.number_of_rituals()
    assert number_of_rituals == 0

    duration = 60 * 60 * 24
    amount = fee_model.getRitualCost(len(cohort), duration)

    # Approve the ritual token for the coordinator agent to spend
    ritual_token.approve(
        fee_model.address,
        amount,
        sender=accounts[initiator.transacting_power.account],
    )

    authority = get_random_checksum_address()
    receipt = agent.initiate_ritual(
        fee_model=fee_model.address,
        providers=cohort,
        authority=authority,
        duration=duration,
        access_controller=global_allow_list.address,
        transacting_power=initiator.transacting_power,
    )
    assert receipt['status'] == 1
    start_ritual_event = agent.contract.events.StartRitual().process_receipt(receipt)
    assert start_ritual_event[0]["args"]["participants"] == cohort

    number_of_rituals = agent.number_of_rituals()
    assert number_of_rituals == 1
    ritual_id = number_of_rituals - 1

    ritual = agent.get_ritual(ritual_id)
    assert ritual.authority == authority

    ritual = agent.get_ritual(ritual_id)
    assert [p.provider for p in ritual.participants] == cohort

    assert (
        agent.get_ritual_status(ritual_id=ritual_id)
        == Coordinator.RitualStatus.DKG_AWAITING_TRANSCRIPTS
    )

    ritual_dkg_key = agent.get_ritual_public_key(ritual_id=ritual_id)
    assert ritual_dkg_key is None  # no dkg key available until ritual is completed


@pytest_twisted.inlineCallbacks
def test_post_transcript(
    agent, transacting_powers, testerchain, clock, mock_async_hooks
):
    ritual_id = agent.number_of_rituals() - 1
    dkg_size = len(transacting_powers)
    threshold = threshold_from_shares(dkg_size)

    txs = []
    transcripts = []
    for transacting_power in transacting_powers:
        transcript = generate_fake_ritual_transcript(dkg_size, threshold)
        transcripts.append(transcript)
        async_tx = agent.post_transcript(
            ritual_id=ritual_id,
            transcript=transcript,
            transacting_power=transacting_power,
            async_tx_hooks=mock_async_hooks,
        )
        txs.append(async_tx)

    testerchain.tx_machine.start()
    while not all([tx.final for tx in txs]):
        yield clock.advance(testerchain.tx_machine._task.interval)
    testerchain.tx_machine.stop()

    for i, async_tx in enumerate(txs):
        post_transcript_events = (
            agent.contract.events.TranscriptPosted().process_receipt(async_tx.receipt)
        )
        # assert len(post_transcript_events) == 1
        event = post_transcript_events[0]
        assert event["args"]["ritualId"] == ritual_id
        assert event["args"]["transcriptDigest"] == keccak(transcripts[i])

    # ensure relevant hooks are called (once for each tx) OR not called (failure ones)
    yield deferLater(reactor, 0.2, lambda: None)
    assert mock_async_hooks.on_broadcast.call_count == len(txs)
    assert mock_async_hooks.on_finalized.call_count == len(txs)
    for async_tx in txs:
        assert async_tx.successful is True

    # failure hooks not called
    assert mock_async_hooks.on_broadcast_failure.call_count == 0
    assert mock_async_hooks.on_fault.call_count == 0
    assert mock_async_hooks.on_insufficient_funds.call_count == 0

    ritual = agent.get_ritual(ritual_id, transcripts=True)
    assert [p.transcript for p in ritual.participants] == transcripts

    assert (
        agent.get_ritual_status(ritual_id=ritual_id)
        == Coordinator.RitualStatus.DKG_AWAITING_AGGREGATIONS
    )

    ritual_dkg_key = agent.get_ritual_public_key(ritual_id=ritual_id)
    assert ritual_dkg_key is None  # no dkg key available until ritual is completed


@pytest_twisted.inlineCallbacks
def test_post_aggregation(
    agent,
    dkg_public_key,
    transacting_powers,
    cohort,
    testerchain,
    clock,
    mock_async_hooks,
):
    testerchain.tx_machine.start()
    ritual_id = agent.number_of_rituals() - 1
    participant_public_keys = {}
    txs = []
    participant_public_key = SessionStaticSecret.random().public_key()

    dkg_size = len(transacting_powers)
    threshold = threshold_from_shares(dkg_size)
    aggregated_transcript = generate_fake_ritual_transcript(dkg_size, threshold)

    for transacting_power in transacting_powers:
        async_tx = agent.post_aggregation(
            ritual_id=ritual_id,
            aggregated_transcript=aggregated_transcript,
            public_key=dkg_public_key,
            participant_public_key=participant_public_key,
            transacting_power=transacting_power,
            async_tx_hooks=mock_async_hooks,
        )
        txs.append(async_tx)

    testerchain.tx_machine.start()
    while not all([tx.final for tx in txs]):
        yield clock.advance(testerchain.tx_machine._task.interval)
    testerchain.tx_machine.stop()

    for i, async_tx in enumerate(txs):
        participant_public_keys[cohort[i]] = participant_public_key
        post_aggregation_events = (
            agent.contract.events.AggregationPosted().process_receipt(async_tx.receipt)
        )
        assert len(post_aggregation_events) == 1
        event = post_aggregation_events[0]
        assert event["args"]["ritualId"] == ritual_id
        assert event["args"]["aggregatedTranscriptDigest"] == keccak(
            bytes(aggregated_transcript)
        )

    participants = agent.get_ritual(ritual_id).participants
    for p in participants:
        assert p.aggregated
        assert p.decryption_request_static_key == bytes(
            participant_public_keys[p.provider]
        )

    # ensure relevant hooks are called (once for each tx) OR not called (failure ones)
    yield deferLater(reactor, 0.2, lambda: None)
    assert mock_async_hooks.on_broadcast.call_count == len(txs)
    assert mock_async_hooks.on_finalized.call_count == len(txs)
    for async_tx in txs:
        assert async_tx.successful is True

    # failure hooks not called
    assert mock_async_hooks.on_broadcast_failure.call_count == 0
    assert mock_async_hooks.on_fault.call_count == 0
    assert mock_async_hooks.on_insufficient_funds.call_count == 0

    ritual = agent.get_ritual(ritual_id)
    assert ritual.participant_public_keys == participant_public_keys

    assert (
        agent.get_ritual_status(ritual_id=ritual_id) == Coordinator.RitualStatus.ACTIVE
    )

    ritual_dkg_key = agent.get_ritual_public_key(ritual_id=ritual_id)
    assert bytes(ritual_dkg_key) == bytes(dkg_public_key)


@pytest.mark.usefixtures("ursulas")
def test_request_handover(
    accounts,
    agent,
    testerchain,
    incoming_validator,
    departing_validator,
    supervisor_transacting_power,
):
    ritual_id = agent.number_of_rituals() - 1

    handover_status = agent.get_handover_status(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    assert handover_status == Coordinator.HandoverStatus.NON_INITIATED

    receipt = agent.request_handover(
        ritual_id=ritual_id,
        departing_validator=departing_validator,
        incoming_validator=incoming_validator,
        transacting_power=supervisor_transacting_power,
    )

    assert receipt["status"] == 1
    handover_events = agent.contract.events.HandoverRequest().process_receipt(receipt)
    handover_event = handover_events[0]
    assert handover_event["args"]["ritualId"] == ritual_id
    assert handover_event["args"]["incomingParticipant"] == incoming_validator
    assert handover_event["args"]["departingParticipant"] == departing_validator

    handover_status = agent.get_handover_status(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    assert handover_status == Coordinator.HandoverStatus.HANDOVER_AWAITING_TRANSCRIPT

    handover = agent.get_handover(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    assert handover.departing_validator == departing_validator
    assert handover.incoming_validator == incoming_validator
    assert handover.transcript == b""  # no transcript available yet
    assert (
        handover.decryption_request_pubkey == b""
    )  # no decryption request pubkey available yet
    assert handover.blinded_share == b""  # no blinded share available yet
    assert handover.key == agent.get_handover_key(
        ritual_id=ritual_id, departing_validator=departing_validator
    )


@pytest_twisted.inlineCallbacks
def test_post_handover_transcript(
    agent,
    accounts,
    transacting_powers,
    testerchain,
    clock,
    mock_async_hooks,
    departing_validator,
    incoming_validator,
    taco_application_agent,
):
    ritual_id = agent.number_of_rituals() - 1

    transcript = os.urandom(32)  # Randomly generated transcript for testing
    participant_public_key = SessionStaticSecret.random().public_key()

    operator = taco_application_agent.get_operator_from_staking_provider(
        incoming_validator
    )
    incoming_operator_transacting_power = TransactingPower(
        account=operator,
        signer=accounts.get_account_signer(operator),
    )

    handover_status = agent.get_handover_status(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    assert handover_status == Coordinator.HandoverStatus.HANDOVER_AWAITING_TRANSCRIPT

    async_tx = agent.post_handover_transcript(
        ritual_id=ritual_id,
        departing_validator=departing_validator,
        handover_transcript=transcript,
        participant_public_key=participant_public_key,
        transacting_power=incoming_operator_transacting_power,
        async_tx_hooks=mock_async_hooks,
    )

    testerchain.tx_machine.start()
    while not async_tx.final:
        yield clock.advance(testerchain.tx_machine._task.interval)
    testerchain.tx_machine.stop()

    post_transcript_events = (
        agent.contract.events.HandoverTranscriptPosted().process_receipt(
            async_tx.receipt
        )
    )
    handover_event = post_transcript_events[0]
    assert handover_event["args"]["ritualId"] == ritual_id
    assert handover_event["args"]["incomingParticipant"] == incoming_validator
    assert handover_event["args"]["departingParticipant"] == departing_validator

    handover_status = agent.get_handover_status(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    assert handover_status == Coordinator.HandoverStatus.HANDOVER_AWAITING_BLINDED_SHARE

    # ensure relevant hooks are called (once for each tx) OR not called (failure ones)
    yield deferLater(reactor, 0.2, lambda: None)
    assert mock_async_hooks.on_broadcast.call_count == 1
    assert mock_async_hooks.on_finalized.call_count == 1
    assert async_tx.successful is True

    # failure hooks not called
    assert mock_async_hooks.on_broadcast_failure.call_count == 0
    assert mock_async_hooks.on_fault.call_count == 0
    assert mock_async_hooks.on_insufficient_funds.call_count == 0

    # check proper state
    handover = agent.get_handover(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    assert handover.departing_validator == departing_validator
    assert handover.incoming_validator == incoming_validator
    assert handover.transcript == transcript
    assert handover.decryption_request_pubkey == bytes(participant_public_key)
    assert handover.blinded_share == b""  # no blinded share available yet
    assert handover.key == agent.get_handover_key(
        ritual_id=ritual_id, departing_validator=departing_validator
    )


@pytest_twisted.inlineCallbacks
def test_post_blinded_share(
    agent,
    accounts,
    transacting_powers,
    testerchain,
    clock,
    mock_async_hooks,
    departing_validator,
    incoming_validator,
    taco_application_agent,
):
    ritual_id = agent.number_of_rituals() - 1

    blinded_share = os.urandom(96)  # Randomly generated bytes for testing

    operator = taco_application_agent.get_operator_from_staking_provider(
        departing_validator
    )
    departing_operator_transacting_power = TransactingPower(
        account=operator,
        signer=accounts.get_account_signer(operator),
    )

    handover_status = agent.get_handover_status(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    assert handover_status == Coordinator.HandoverStatus.HANDOVER_AWAITING_BLINDED_SHARE

    async_tx = agent.post_blinded_share_for_handover(
        ritual_id=ritual_id,
        blinded_share=blinded_share,
        transacting_power=departing_operator_transacting_power,
        async_tx_hooks=mock_async_hooks,
    )

    testerchain.tx_machine.start()
    while not async_tx.final:
        yield clock.advance(testerchain.tx_machine._task.interval)
    testerchain.tx_machine.stop()

    events = agent.contract.events.BlindedSharePosted().process_receipt(
        async_tx.receipt
    )
    handover_event = events[0]
    assert handover_event["args"]["ritualId"] == ritual_id
    assert handover_event["args"]["departingParticipant"] == departing_validator

    handover_status = agent.get_handover_status(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    assert handover_status == Coordinator.HandoverStatus.HANDOVER_AWAITING_FINALIZATION

    # ensure relevant hooks are called (once for each tx) OR not called (failure ones)
    yield deferLater(reactor, 0.2, lambda: None)
    assert mock_async_hooks.on_broadcast.call_count == 1
    assert mock_async_hooks.on_finalized.call_count == 1
    assert async_tx.successful is True

    # failure hooks not called
    assert mock_async_hooks.on_broadcast_failure.call_count == 0
    assert mock_async_hooks.on_fault.call_count == 0
    assert mock_async_hooks.on_insufficient_funds.call_count == 0

    # check proper state
    handover = agent.get_handover(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    assert handover.departing_validator == departing_validator
    assert handover.incoming_validator == incoming_validator
    assert handover.blinded_share == blinded_share


@pytest.mark.usefixtures("ursulas")
def test_finalize_handover(
    accounts,
    agent,
    testerchain,
    incoming_validator,
    departing_validator,
    supervisor_transacting_power,
    cohort,
):
    ritual_id = agent.number_of_rituals() - 1
    ritual = agent.get_ritual(ritual_id)
    old_aggregated_transcript = ritual.aggregated_transcript
    blinded_share = agent.get_handover(
        ritual_id=ritual_id, departing_validator=departing_validator
    ).blinded_share

    handover_status = agent.get_handover_status(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    assert handover_status == Coordinator.HandoverStatus.HANDOVER_AWAITING_FINALIZATION

    receipt = agent.finalize_handover(
        ritual_id=ritual_id,
        departing_validator=departing_validator,
        transacting_power=supervisor_transacting_power,
    )

    assert receipt["status"] == 1
    handover_events = agent.contract.events.HandoverFinalized().process_receipt(receipt)
    handover_event = handover_events[0]
    assert handover_event["args"]["ritualId"] == ritual_id
    assert handover_event["args"]["incomingParticipant"] == incoming_validator
    assert handover_event["args"]["departingParticipant"] == departing_validator

    handover_status = agent.get_handover_status(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    assert handover_status == Coordinator.HandoverStatus.NON_INITIATED

    handover = agent.get_handover(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    # The handover model still contains key data
    assert handover.key == agent.get_handover_key(
        ritual_id=ritual_id, departing_validator=departing_validator
    )
    assert handover.departing_validator == departing_validator
    # Remaining data should be empty, though
    assert handover.incoming_validator == NULL_ADDRESS
    assert handover.transcript == b""
    assert handover.decryption_request_pubkey == b""
    assert handover.blinded_share == b""

    # Now let's check that agggregate transcript has been updated
    ritual = agent.get_ritual(ritual_id)
    new_aggregated_transcript = ritual.aggregated_transcript
    assert new_aggregated_transcript != old_aggregated_transcript

    index = cohort.index(departing_validator)
    threshold = 2
    blind_share_position = 32 + index * 96 + threshold * 48

    old_aggregate_with_blinded_share = (
        old_aggregated_transcript[:blind_share_position]
        + blinded_share
        + old_aggregated_transcript[blind_share_position + 96 :]
    )
    assert old_aggregate_with_blinded_share == new_aggregated_transcript
