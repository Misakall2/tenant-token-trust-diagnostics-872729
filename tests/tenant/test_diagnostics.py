"""诊断脱敏、轮换端到端与库职责边界测试。"""

from tests.tenant.constants import AUDIENCE, ISSUER_A, TENANT_A
from tenant_auth.errors import Stage
from tenant_auth.model import redact_fingerprint
from tenant_auth.tokens import TokenFactory


def test_fingerprint_is_short_and_irreversible() -> None:
    fp = redact_fingerprint("a-sensitive-token")
    assert len(fp) == 12
    assert "a-sensitive-token" not in fp
    assert redact_fingerprint("a-sensitive-token") == fp  # 可关联
    assert redact_fingerprint("other") != fp


def test_diagnosis_never_contains_token_or_claims(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    token = factory.issue(
        world["mat_a"], factory.standard_claims(ISSUER_A, AUDIENCE, extra={"secret": "shh"})
    )
    d = verifier.diagnose(token, TENANT_A)
    rendered = str(d.__dict__) + d.summary_line()
    assert token not in rendered
    assert "shh" not in rendered
    assert d.token_fingerprint in rendered
    # 私钥材料也不出现在诊断里
    assert world["mat_a"].signing_key.as_dict(private=True).get("d") not in rendered


def test_full_rotation_end_to_end(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    source = world["source"]
    store = verifier.key_store

    old_token = factory.issue(world["mat_a"], factory.standard_claims(ISSUER_A, AUDIENCE))
    assert verifier.diagnose(old_token, TENANT_A).accepted

    # 密钥轮换：新钥匙 k2，重新编排 A 的密钥源脚本
    new_mat = factory.new_rsa_material(TENANT_A, "k2")
    source.set_script(TENANT_A, [
        {"keys": [world["mat_a"].public_jwk()]},
        {"keys": [new_mat.public_jwk()]},
    ])
    # 重置计数视角：直接观察后续调用次数
    new_token = factory.issue(new_mat, factory.standard_claims(ISSUER_A, AUDIENCE))
    d_rotated = verifier.diagnose(new_token, TENANT_A)
    assert d_rotated.accepted and not d_rotated.cache_used
    assert store.refresh_completed(TENANT_A) == 2

    # 旧令牌在新快照后被拒，且不逐个试钥匙
    d_old = verifier.diagnose(old_token, TENANT_A)
    assert not d_old.accepted and d_old.reason == "unknown_key_id"


def test_library_responsibility_decode_does_not_check_claims(world: dict) -> None:
    """根因证据：joserfc.jwt.decode 对过期令牌照样返回 Token，声明检查是接入方职责。"""
    from joserfc import jwt
    from joserfc.jwk import RSAKey

    factory = world["factory"]
    expired = factory.issue(world["mat_a"], factory.standard_claims(ISSUER_A, AUDIENCE, ttl=-600))
    public = RSAKey.import_key(world["mat_a"].public_jwk())
    # 库只验签：过期不影响 decode 成功
    decoded = jwt.decode(expired, public, algorithms=["RS256"])
    assert decoded.claims["exp"] < world["clock"].now()
    # 接入层则必须在声明阶段拒绝
    d = world["verifier"].diagnose(expired, TENANT_A)
    assert not d.accepted and d.failure_stage is Stage.CLAIMS


def test_library_none_is_neutral_capability_not_vuln(world: dict) -> None:
    """alg=none 是 RFC 7515 的中性能力；风险只来自接入方把它放进白名单。"""
    # 库在显式启用 none 的注册表里可以解析（能力存在）
    assert TokenFactory.can_library_accept_none() is True
    # 但本接入方案的固定白名单永远拒绝它
    none_token = TokenFactory.unsigned_none_token(
        {"iss": ISSUER_A, "aud": AUDIENCE, "exp": world["clock"].now() + 60}, kid="k1"
    )
    d = world["verifier"].diagnose(none_token, TENANT_A)
    assert not d.accepted and d.reason == "algorithm_not_allowed"


def test_tampered_token_rejected_at_signature_stage(world: dict) -> None:
    verifier = world["verifier"]
    factory = world["factory"]
    good = factory.issue(world["mat_a"], factory.standard_claims(ISSUER_A, AUDIENCE))
    for variant in (TokenFactory.tamper_signature(good), TokenFactory.tamper_payload(good)):
        d = verifier.diagnose(variant, TENANT_A)
        assert not d.accepted
        assert d.failure_stage is Stage.SIGNATURE
        assert d.reason == "bad_signature"


def test_concurrent_waiters_run_same_chain_as_leader(world: dict) -> None:
    """缓存命中、刷新完成、并发等待者三类请求的阶段链完全一致。"""
    import threading

    verifier = world["verifier"]
    factory = world["factory"]
    token = factory.issue(world["mat_a"], factory.standard_claims(ISSUER_A, AUDIENCE))

    # 先打一次建立缓存
    first = verifier.diagnose(token, TENANT_A)
    cached = verifier.diagnose(token, TENANT_A)

    # 并发等待者：用阻塞源构造一次真实的单飞刷新（新租户上下文）
    from tenant_auth.clock import ControlledClock
    from tenant_auth.keystore import BlockingKeySource
    from tenant_auth.model import TenantPolicy
    from tenant_auth.verifier import MultiTenantVerifier

    clock2 = ControlledClock(1_800_000_000)
    factory2 = TokenFactory(clock2)
    mat = factory2.new_rsa_material("tenant-c", "k1")
    blocking = BlockingKeySource({"keys": [mat.public_jwk()]})
    policy = TenantPolicy("tenant-c", ISSUER_A, AUDIENCE, frozenset({"RS256"}), key_set_ttl=300)
    v2 = MultiTenantVerifier.build({"tenant-c": policy}, blocking, clock2)
    t2 = factory2.issue(mat, factory2.standard_claims(ISSUER_A, AUDIENCE))

    outcomes: list = []
    barrier = threading.Barrier(5)

    def worker() -> None:
        barrier.wait()
        outcomes.append(v2.diagnose(t2, "tenant-c"))

    threads = [threading.Thread(target=worker) for _ in range(5)]
    for t in threads:
        t.start()
    assert blocking.entered.wait(5)
    blocking.release()
    for t in threads:
        t.join()

    expected_chain = first.stages
    assert cached.stages == expected_chain
    assert len(outcomes) == 5
    assert all(o.stages == expected_chain and o.accepted for o in outcomes)
    assert blocking.calls == 1
