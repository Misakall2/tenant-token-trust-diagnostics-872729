"""多租户诊断测试共享常量与夹具。"""

import sys
from pathlib import Path

import pytest

_EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "multitenant"
if str(_EXAMPLES) not in sys.path:
    sys.path.insert(0, str(_EXAMPLES))

from tenant_auth.clock import ControlledClock  # noqa: E402
from tenant_auth.keystore import FakeKeySource  # noqa: E402
from tenant_auth.model import TenantPolicy  # noqa: E402
from tenant_auth.tokens import TokenFactory  # noqa: E402
from tenant_auth.verifier import MultiTenantVerifier  # noqa: E402

BASE_TIME = 1_800_000_000
TENANT_A = "tenant-a"
TENANT_B = "tenant-b"
ISSUER_A = "https://issuer-a.example"
ISSUER_B = "https://issuer-b.example"
AUDIENCE = "api-gateway"
LEEWAY = 30


@pytest.fixture
def clock() -> ControlledClock:
    return ControlledClock(BASE_TIME)


@pytest.fixture
def factory(clock: ControlledClock) -> TokenFactory:
    return TokenFactory(clock)


@pytest.fixture
def source() -> FakeKeySource:
    return FakeKeySource()


@pytest.fixture
def world(factory: TokenFactory, source: FakeKeySource, clock: ControlledClock) -> dict:
    """两个租户、同号 kid=k1 的标准世界。"""
    mat_a = factory.new_rsa_material(TENANT_A, "k1")
    mat_b = factory.new_rsa_material(TENANT_B, "k1", alg="RS256")
    source.set_script(TENANT_A, [{"keys": [mat_a.public_jwk()]}])
    source.set_script(TENANT_B, [{"keys": [mat_b.public_jwk()]}])
    policies = {
        TENANT_A: TenantPolicy(
            TENANT_A, ISSUER_A, AUDIENCE, frozenset({"RS256"}), key_set_ttl=300, leeway=LEEWAY
        ),
        TENANT_B: TenantPolicy(
            TENANT_B, ISSUER_B, AUDIENCE, frozenset({"RS256"}), key_set_ttl=300, leeway=LEEWAY
        ),
    }
    verifier = MultiTenantVerifier.build(policies, source, clock)
    return {
        "clock": clock,
        "factory": factory,
        "source": source,
        "verifier": verifier,
        "mat_a": mat_a,
        "mat_b": mat_b,
        "policies": policies,
    }


@pytest.fixture
def verifier(world: dict) -> MultiTenantVerifier:
    return world["verifier"]
