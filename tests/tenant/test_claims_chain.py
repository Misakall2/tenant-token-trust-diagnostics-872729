"""声明检查链测试：iss/aud 精确匹配、时间字段、必填声明与无旁路保证。"""

import pytest

from tests.tenant.constants import AUDIENCE, ISSUER_A, LEEWAY, TENANT_A
from tenant_auth.errors import ClaimsValidationError, Stage
from tenant_auth.tokens import TokenFactory


def _issue(factory: TokenFactory, mat, **claims_kw) -> str:
    return factory.issue(mat, factory.standard_claims(ISSUER_A, AUDIENCE, **claims_kw))


def test_issuer_exact_match_required(world: dict) -> None:
    verifier = world["verifier"]
    token = _issue(world["factory"], world["mat_a"], extra={"iss": "https://issuer-a.example.evil"})
    d = verifier.diagnose(token, TENANT_A)
    assert not d.accepted and d.failure_stage is Stage.CLAIMS and d.reason == "invalid_claim"


def test_audience_string_and_array(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    ok_array = _issue(factory, world["mat_a"], extra={"aud": ["other", AUDIENCE]})
    assert verifier.diagnose(ok_array, TENANT_A).accepted
    bad_array = _issue(factory, world["mat_a"], extra={"aud": ["x", "y"]})
    d = verifier.diagnose(bad_array, TENANT_A)
    assert not d.accepted and d.reason == "invalid_claim"
    bad_string = _issue(factory, world["mat_a"], extra={"aud": "someone-else"})
    assert not verifier.diagnose(bad_string, TENANT_A).accepted


def test_exp_boundary_strict(world: dict) -> None:
    from tenant_auth.model import TenantPolicy
    from tenant_auth.verifier import MultiTenantVerifier

    verifier = world["verifier"]
    factory = world["factory"]
    # 零偏差验证器：呈现 RFC 原始边界，exp == now 即过期
    strict = MultiTenantVerifier.build(
        {TENANT_A: TenantPolicy(
            TENANT_A, ISSUER_A, AUDIENCE, frozenset({"RS256"}), key_set_ttl=300, leeway=0)},
        world["source"], world["clock"],
    )
    exact = _issue(factory, world["mat_a"], ttl=0)
    assert strict.diagnose(exact, TENANT_A).reason == "expired_token"

    # 默认 leeway=30：过期 29 秒落在偏差内接受，恰为 30 秒边界仍拒绝
    within = _issue(factory, world["mat_a"], ttl=-(LEEWAY - 1))
    assert verifier.diagnose(within, TENANT_A).accepted
    boundary = _issue(factory, world["mat_a"], ttl=-LEEWAY)
    assert verifier.diagnose(boundary, TENANT_A).reason == "expired_token"


def test_nbf_and_iat(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    future_nbf = _issue(factory, world["mat_a"], nbf=world["clock"].now() + 120)
    assert verifier.diagnose(future_nbf, TENANT_A).reason == "invalid_claim"
    # nbf 恰落在偏差边界：nbf 用严格大于，接受
    nbf_boundary = _issue(factory, world["mat_a"], nbf=world["clock"].now() + LEEWAY)
    assert verifier.diagnose(nbf_boundary, TENANT_A).accepted
    future_iat = _issue(factory, world["mat_a"], iat=world["clock"].now() + 120)
    assert verifier.diagnose(future_iat, TENANT_A).reason == "invalid_claim"


def test_boolean_time_claims_rejected(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    for field_name in ("exp", "nbf", "iat"):
        claims = factory.standard_claims(ISSUER_A, AUDIENCE)
        claims[field_name] = True  # bool 是 int 子类，必须显式拒绝
        token = factory.issue(world["mat_a"], claims)
        d = verifier.diagnose(token, TENANT_A)
        assert not d.accepted and d.reason == "invalid_claim", field_name


def test_missing_required_claims_rejected(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    no_exp = factory.issue(
        world["mat_a"], {"iss": ISSUER_A, "aud": AUDIENCE, "iat": world["clock"].now()}
    )
    d = verifier.diagnose(no_exp, TENANT_A)
    assert not d.accepted and d.reason == "missing_claim"


def test_extra_required_claim_from_policy(world: dict) -> None:
    from tenant_auth.model import TenantPolicy
    from tenant_auth.verifier import MultiTenantVerifier

    policy = TenantPolicy(
        TENANT_A, ISSUER_A, AUDIENCE, frozenset({"RS256"}),
        key_set_ttl=300, leeway=LEEWAY, required_claims=frozenset({"jti"}),
    )
    verifier = MultiTenantVerifier.build({TENANT_A: policy}, world["source"], world["clock"])
    factory = world["factory"]
    without_jti = _issue(factory, world["mat_a"])
    assert verifier.diagnose(without_jti, TENANT_A).reason == "missing_claim"
    with_jti = _issue(factory, world["mat_a"], extra={"jti": "token-123"})
    assert verifier.diagnose(with_jti, TENANT_A).accepted


def test_no_bypass_verified_claims_only_after_full_chain(world: dict) -> None:
    """验签成功但声明失败时，verify 抛错且不返回任何声明对象。"""
    verifier = world["verifier"]
    factory = world["factory"]
    expired = _issue(factory, world["mat_a"], ttl=-600)
    with pytest.raises(ClaimsValidationError) as exc:
        verifier.verify(expired, TENANT_A)
    assert exc.value.claim == "exp"
    # 诊断同样显示走完签名、停在声明阶段
    d = verifier.diagnose(expired, TENANT_A)
    assert d.stages[-1] is Stage.CLAIMS and not d.accepted


def test_every_accepted_request_traverses_all_five_stages(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    token = _issue(factory, world["mat_a"])
    d = verifier.diagnose(token, TENANT_A)
    assert d.accepted
    assert d.stages == [
        Stage.TENANT_SELECTION,
        Stage.KEY_REFRESH,
        Stage.KEY_SELECTION,
        Stage.SIGNATURE,
        Stage.CLAIMS,
    ]
    # 缓存命中请求的阶段链完全一致（只是 cache_used 标记不同）
    d2 = verifier.diagnose(token, TENANT_A)
    assert d2.accepted and d2.stages == d.stages and d2.cache_used
