"""租户选择与固定信任配置测试。

覆盖：
- 租户只能由可信上下文选择，未知租户拒绝；
- 令牌自带 iss/alg 不能改变信任配置；
- 算法白名单固定，alg=none 与越权算法在密码学操作前被拒；
- 同 kid 跨租户不串用。
"""

import pytest

from tests.tenant.constants import AUDIENCE, ISSUER_A, ISSUER_B, TENANT_A, TENANT_B
from tenant_auth.errors import Stage, TenantSelectionError
from tenant_auth.model import TenantPolicy
from tenant_auth.tokens import TokenFactory


def test_happy_path_returns_verified_claims(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    token = factory.issue(world["mat_a"], factory.standard_claims(ISSUER_A, AUDIENCE))
    result = verifier.verify(token, TENANT_A)
    assert result.tenant_id == TENANT_A
    assert result.kid == "k1"
    assert result.alg == "RS256"
    assert result.claims["iss"] == ISSUER_A


def test_unknown_tenant_rejected_at_first_stage(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    token = factory.issue(world["mat_a"], factory.standard_claims(ISSUER_A, AUDIENCE))
    diagnosis = verifier.diagnose(token, "not-a-real-tenant")
    assert not diagnosis.accepted
    assert diagnosis.failure_stage is Stage.TENANT_SELECTION
    assert diagnosis.reason == "unknown_tenant"
    assert diagnosis.stages == [Stage.TENANT_SELECTION]
    with pytest.raises(TenantSelectionError):
        verifier.verify(token, "not-a-real-tenant")


def test_tenant_id_never_taken_from_token(world: dict) -> None:
    """令牌里即便伪造 iss，也无法影响租户选择或信任锚。"""
    verifier = world["verifier"]
    factory = world["factory"]
    # 用 B 的钥匙签发，但 iss 伪装成 A
    token = factory.issue(world["mat_b"], factory.standard_claims(ISSUER_A, AUDIENCE))
    diagnosis = verifier.diagnose(token, TENANT_A)
    assert not diagnosis.accepted
    # A 用自己的 k1 公钥验签 -> 签名失败，而不是被令牌 iss 引导到 B 的配置
    assert diagnosis.failure_stage is Stage.SIGNATURE
    assert diagnosis.reason == "bad_signature"
    # 没有为 A 触发额外刷新（kid=k1 命中 A 的缓存）
    assert world["source"].call_count(TENANT_A) == 1


def test_same_kid_does_not_cross_tenants(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    token_b = factory.issue(world["mat_b"], factory.standard_claims(ISSUER_B, AUDIENCE))
    assert verifier.diagnose(token_b, TENANT_B).accepted
    cross = verifier.diagnose(token_b, TENANT_A)
    assert not cross.accepted and cross.reason == "bad_signature"


def test_algorithm_whitelist_is_fixed_per_tenant(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    ec_mat = factory.new_ec_material(TENANT_A, "k-ec")
    token = factory.issue(ec_mat, factory.standard_claims(ISSUER_A, AUDIENCE), alg="ES256")
    diagnosis = verifier.diagnose(token, TENANT_A)
    assert not diagnosis.accepted
    assert diagnosis.failure_stage is Stage.SIGNATURE
    assert diagnosis.reason == "algorithm_not_allowed"
    # 拒绝发生在选钥匙之前，密钥源完全不被调用（白名单先于密钥阶段生效）
    assert world["source"].call_count(TENANT_A) == 0


def test_alg_none_always_rejected_even_with_valid_kid(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    # 先让 A 的缓存加载，再用带合法 kid 的 none 令牌
    good = factory.issue(world["mat_a"], factory.standard_claims(ISSUER_A, AUDIENCE))
    assert verifier.diagnose(good, TENANT_A).accepted
    none_token = TokenFactory.unsigned_none_token(
        {"iss": ISSUER_A, "aud": AUDIENCE, "exp": world["clock"].now() + 300}, kid="k1"
    )
    diagnosis = verifier.diagnose(none_token, TENANT_A)
    assert not diagnosis.accepted
    assert diagnosis.reason == "algorithm_not_allowed"


def test_policy_cannot_whitelist_none() -> None:
    with pytest.raises(ValueError, match="none"):
        TenantPolicy("t", "iss", "aud", frozenset({"none"}))


def test_token_jku_header_never_drives_trust(world: dict) -> None:
    """令牌头里的 jku 只是被忽略的数据，验证器从不读取它。"""
    verifier = world["verifier"]
    factory = world["factory"]
    token = factory.issue(
        world["mat_a"],
        factory.standard_claims(ISSUER_A, AUDIENCE),
        extra_headers={"jku": "https://attacker.example/evil-jwks.json"},
    )
    diagnosis = verifier.diagnose(token, TENANT_A)
    assert diagnosis.accepted  # 固定配置照常验通，jku 被无视
