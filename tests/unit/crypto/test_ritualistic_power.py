import os

from nucypher_core.ferveo import FerveoPublicKey
from nucypher_core.ferveo import Keypair as FerveoKeypair

from nucypher.crypto.keypairs import RitualisticKeypair
from nucypher.crypto.powers import RitualisticPower


def test_derive_ritualistic_power(tmpdir):
    size = FerveoKeypair.secure_randomness_size()
    blob = os.urandom(size)
    keypair = RitualisticKeypair.from_secure_randomness(blob)
    power = RitualisticPower(keypair=keypair)

    assert isinstance(power, RitualisticPower)
    assert isinstance(power.keypair, RitualisticKeypair)

    public_key = power.public_key()
    assert isinstance(public_key, FerveoPublicKey)

    # Generate keypair with different randomness
    keypair2 = RitualisticKeypair.from_secure_randomness(os.urandom(size))
    power2 = RitualisticPower(keypair=keypair2)
    assert power.public_key() != power2.public_key()

    # Generate keypair with same randomness
    keypair3 = RitualisticKeypair.from_secure_randomness(blob)
    power3 = RitualisticPower(keypair=keypair3)
    assert power.public_key() == power3.public_key()
