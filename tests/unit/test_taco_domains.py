import pytest

from nucypher.blockchain.eth.domains import (
    EthChain,
    PolygonChain,
    TACoDomain,
)


@pytest.fixture(scope="module")
def test_registry(module_mocker):
    # override fixture which mocks SUPPORTED_DOMAIN_NAMES
    yield


@pytest.fixture(scope="module", autouse=True)
def mock_condition_blockchains(module_mocker):
    # override fixture which mocks get_domain_info
    yield


@pytest.mark.parametrize(
    "eth_chain_test",
    (
        (EthChain.MAINNET, "mainnet", 1),
        (EthChain.GOERLI, "goerli", 5),
        (EthChain.SEPOLIA, "sepolia", 11155111),
    ),
)
def test_eth_chains(eth_chain_test):
    eth_chain, expected_name, expected_id = eth_chain_test
    assert eth_chain.name == expected_name
    assert eth_chain.id == expected_id


@pytest.mark.parametrize(
    "poly_chain_test",
    (
        (PolygonChain.MAINNET, "polygon", 137),
        (PolygonChain.MUMBAI, "mumbai", 80001),
    ),
)
def test_polygon_chains(poly_chain_test):
    eth_chain, expected_name, expected_id = poly_chain_test
    assert eth_chain.name == expected_name
    assert eth_chain.id == expected_id


@pytest.mark.parametrize(
    "taco_domain_test",
    (
        (TACoDomain.MAINNET, "mainnet", EthChain.MAINNET, PolygonChain.MAINNET),
        (TACoDomain.LYNX, "lynx", EthChain.GOERLI, PolygonChain.MUMBAI),
        (TACoDomain.TAPIR, "tapir", EthChain.SEPOLIA, PolygonChain.MUMBAI),
    ),
)
def test_taco_domain_info(taco_domain_test):
    (
        domain_info,
        expected_name,
        expected_eth_chain,
        expected_polygon_chain,
    ) = taco_domain_test
    assert domain_info.name == expected_name
    assert domain_info.eth_chain == expected_eth_chain
    assert domain_info.polygon_chain == expected_polygon_chain

    assert domain_info.is_testnet == (expected_name != "mainnet")


@pytest.mark.parametrize(
    "domain_name_test",
    (
        ("mainnet", TACoDomain.MAINNET),
        ("lynx", TACoDomain.LYNX),
        ("tapir", TACoDomain.TAPIR),
    ),
)
def test_get_domain_info(domain_name_test):
    domain_name, expected_domain_info = domain_name_test
    assert TACoDomain.get_domain_info(domain_name) == expected_domain_info


def test_get_domain_info_unrecognized_domain_name():
    with pytest.raises(TACoDomain.Unrecognized):
        TACoDomain.get_domain_info(domain="5am_In_Toronto")
