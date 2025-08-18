import pytest
from nucypher_core.ferveo import (
    AggregatedTranscript,
    Dkg,
    Keypair,
    Validator,
    ValidatorMessage,
    combine_decryption_shares_simple,
    decrypt_with_shared_secret,
    encrypt,
)

SHARES_NUM = 4


# This test is a mirror of the handover python test in ferveo
@pytest.mark.parametrize("handover_slot_index", list(range(SHARES_NUM)))
def test_handover_with_encrypt_and_decrypt(
    get_random_checksum_address, handover_slot_index
):
    tau = 1
    security_threshold = 3
    shares_num = SHARES_NUM
    validators_num = shares_num + 2

    validator_keypairs = [Keypair.random() for _ in range(validators_num)]

    # validators and associated keypairs must be in the same order
    validators = [
        Validator(get_random_checksum_address(), keypair.public_key(), i)
        for i, keypair in enumerate(validator_keypairs)
    ]

    # Each validator holds their own DKG instance and generates a transcript every
    # validator, including themselves
    messages = []
    for sender in validators:
        dkg = Dkg(
            tau=tau,
            shares_num=shares_num,
            security_threshold=security_threshold,
            validators=validators,
            me=sender,
        )
        messages.append(ValidatorMessage(sender, dkg.generate_transcript()))

    # Now that every validator holds a dkg instance and a transcript for every other validator,
    # every validator can aggregate the transcripts
    me = validators[0]
    dkg = Dkg(
        tau=tau,
        shares_num=shares_num,
        security_threshold=security_threshold,
        validators=validators,
        me=me,
    )

    # Server can aggregate the transcripts
    server_aggregate = dkg.aggregate_transcripts(messages)
    assert server_aggregate.verify(validators_num, messages)

    # And the client can also aggregate and verify the transcripts
    client_aggregate = AggregatedTranscript(messages)
    assert client_aggregate.verify(validators_num, messages)

    # In the meantime, the client creates a ciphertext and decryption request
    msg = "abc".encode()
    aad = "my-aad".encode()
    ciphertext = encrypt(msg, aad, client_aggregate.public_key)

    # The client can serialize/deserialize ciphertext for transport
    _ciphertext_serialized = bytes(ciphertext)

    # Let's simulate a handover
    incoming_validator_keypair = Keypair.random()
    incoming_validator = Validator(
        get_random_checksum_address(),
        incoming_validator_keypair.public_key(),
        handover_slot_index,
    )
    departing_keypair = validator_keypairs[handover_slot_index]

    handover_transcript = dkg.generate_handover_transcript(
        server_aggregate,
        handover_slot_index,
        incoming_validator_keypair,
    )

    new_aggregate = server_aggregate.finalize_handover(
        handover_transcript, departing_keypair
    )

    validator_keypairs[handover_slot_index] = incoming_validator_keypair
    validators[handover_slot_index] = incoming_validator

    # Having aggregated the transcripts, the validators can now create decryption shares
    decryption_shares = []
    for validator, validator_keypair in zip(validators, validator_keypairs):
        dkg = Dkg(
            tau=tau,
            shares_num=shares_num,
            security_threshold=security_threshold,
            validators=validators,
            me=validator,
        )
        # Create a decryption share for the ciphertext
        decryption_share = new_aggregate.create_decryption_share_simple(
            dkg, ciphertext.header, aad, validator_keypair
        )
        decryption_shares.append(decryption_share)

    # We only need `threshold` decryption shares in simple variant
    decryption_shares = decryption_shares[:security_threshold]

    # Now, the decryption share can be used to decrypt the ciphertext
    # This part is in the client API

    shared_secret = combine_decryption_shares_simple(decryption_shares)

    # The client should have access to the public parameters of the DKG

    plaintext = decrypt_with_shared_secret(ciphertext, aad, shared_secret)
    assert bytes(plaintext) == msg
