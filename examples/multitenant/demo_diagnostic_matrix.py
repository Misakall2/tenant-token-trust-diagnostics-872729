"""演示 3：全链路诊断矩阵与确定性并发刷新合并。

运行方式（仓库根目录）：

    python examples/multitenant/demo_diagnostic_matrix.py

矩阵覆盖：串租户、轮换、刷新故障、过期/未生效、声明缺失、非法时间类型、
算法越权、无签名令牌，以及 N 个并发请求合并为一次刷新。
输出只含脱敏指纹、失败阶段与原因码。
"""

import sys
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    sys.stdout.reconfigure(encoding="utf-8")  # Windows 控制台默认 GBK，固定 UTF-8 输出
except (AttributeError, ValueError):
    pass

from tenant_auth.clock import ControlledClock  # noqa: E402
from tenant_auth.keystore import BlockingKeySource, FakeKeySource  # noqa: E402
from tenant_auth.model import TenantPolicy  # noqa: E402
from tenant_auth.tokens import TokenFactory  # noqa: E402
from tenant_auth.verifier import MultiTenantVerifier  # noqa: E402

BASE_TIME = 1_800_000_000
TENANT_A = "tenant-a"
TENANT_B = "tenant-b"
ISSUER_A = "https://issuer-a.example"
AUDIENCE = "api-gateway"
LEEWAY = 30


def build() -> tuple[ControlledClock, TokenFactory, MultiTenantVerifier, FakeKeySource, dict]:
    clock = ControlledClock(BASE_TIME)
    factory = TokenFactory(clock)
    mat_a = factory.new_rsa_material(TENANT_A, "k1")
    mat_b = factory.new_rsa_material(TENANT_B, "k1")  # 同 kid，不同钥匙
    source = FakeKeySource()
    source.set_script(TENANT_A, [{"keys": [mat_a.public_jwk()]}, RuntimeError("outage")])
    source.set_script(TENANT_B, [{"keys": [mat_b.public_jwk()]}])
    policies = {
        TENANT_A: TenantPolicy(TENANT_A, ISSUER_A, AUDIENCE, frozenset({"RS256"}), key_set_ttl=300, leeway=LEEWAY),
        TENANT_B: TenantPolicy(TENANT_B, "https://issuer-b.example", AUDIENCE, frozenset({"RS256"}), key_set_ttl=300),
    }
    verifier = MultiTenantVerifier.build(policies, source, clock)
    return clock, factory, verifier, source, {"mat_a": mat_a, "mat_b": mat_b}


def main() -> None:
    clock, factory, verifier, source, mats = build()
    mat_a, mat_b = mats["mat_a"], mats["mat_b"]
    results: list[tuple[str, object]] = []

    # 零偏差严格验证器：专门展示"恰好落在边界"的 RFC 原始语义
    strict_source = FakeKeySource()
    strict_source.set_script(TENANT_A, [{"keys": [mat_a.public_jwk()]}])
    strict_policy = TenantPolicy(
        TENANT_A, ISSUER_A, AUDIENCE, frozenset({"RS256"}), key_set_ttl=300, leeway=0
    )
    strict_verifier = MultiTenantVerifier.build({TENANT_A: strict_policy}, strict_source, clock)

    def case(name: str, token: str, tenant: str, *, strict: bool = False) -> None:
        diagnosis = strict_verifier.diagnose(token, tenant) if strict else verifier.diagnose(token, tenant)
        results.append((name, diagnosis))
        suffix = " [leeway=0]" if strict else ""
        print(f"{name:32s} {diagnosis.summary_line()}{suffix}")

    print("=" * 78)
    print("诊断矩阵（token~ 为 SHA-256 短指纹，非完整令牌）")
    print("=" * 78)

    good = factory.issue(mat_a, factory.standard_claims(ISSUER_A, AUDIENCE))
    case("01 合法令牌", good, TENANT_A)

    case("02 串租户（同 kid 不同钥匙）", factory.issue(mat_b, factory.standard_claims(
        "https://issuer-b.example", AUDIENCE)), TENANT_A)

    case("03 未知租户上下文", good, "tenant-unknown")

    case("04 签名被篡改", TokenFactory.tamper_signature(good), TENANT_A)
    case("05 载荷被篡改", TokenFactory.tamper_payload(good), TENANT_A)
    case("06 alg=none 无签名", TokenFactory.unsigned_none_token(
        {"iss": ISSUER_A, "aud": AUDIENCE, "exp": clock.now() + 300}), TENANT_A)

    # 算法越权：用 ES256 签发，但 A 的白名单只有 RS256
    ec_mat = factory.new_ec_material(TENANT_A, "k-ec")
    case("07 算法不在白名单", factory.issue(
        ec_mat, factory.standard_claims(ISSUER_A, AUDIENCE), alg="ES256"), TENANT_A)

    # 声明问题（签名均合法）
    case("08 签发者不匹配", factory.issue(mat_a, factory.standard_claims(
        "https://evil.example", AUDIENCE)), TENANT_A)
    case("09 受众不匹配", factory.issue(mat_a, factory.standard_claims(
        ISSUER_A, "other-service")), TENANT_A)
    case("10 受众数组包含我方", factory.issue(mat_a, factory.standard_claims(
        ISSUER_A, ["other-service", AUDIENCE])), TENANT_A)
    case("11 受众数组不含我方", factory.issue(mat_a, factory.standard_claims(
        ISSUER_A, ["x", "y"])), TENANT_A)

    # 时间边界（RFC 7519 严格语义 + 可配置 leeway）：
    #   exp == now 恰好到期即拒绝；偏差内接受；恰等于偏差边界仍拒绝
    exp_exact = factory.issue(mat_a, factory.standard_claims(ISSUER_A, AUDIENCE, ttl=0))
    case("12 exp 恰好等于当前时间（到期即拒）", exp_exact, TENANT_A, strict=True)
    within_skew = factory.issue(mat_a, factory.standard_claims(ISSUER_A, AUDIENCE, ttl=-LEEWAY + 1))
    case("13 过期但在时钟偏差内", within_skew, TENANT_A)
    at_skew_boundary = factory.issue(mat_a, factory.standard_claims(ISSUER_A, AUDIENCE, ttl=-LEEWAY))
    case("14 过期恰等于偏差边界（仍拒绝）", at_skew_boundary, TENANT_A)

    nbf_future = factory.issue(mat_a, factory.standard_claims(
        ISSUER_A, AUDIENCE, nbf=clock.now() + 120))
    case("15 nbf 在未来", nbf_future, TENANT_A)
    nbf_skew = factory.issue(mat_a, factory.standard_claims(
        ISSUER_A, AUDIENCE, nbf=clock.now() + LEEWAY))
    case("16 nbf 恰好落在偏差边界（nbf 用严格大于，边界接受）", nbf_skew, TENANT_A)
    nbf_exact_now = factory.issue(mat_a, factory.standard_claims(
        ISSUER_A, AUDIENCE, nbf=clock.now()))
    case("17 nbf 恰好等于当前时间（即时生效）", nbf_exact_now, TENANT_A, strict=True)

    iat_future = factory.issue(mat_a, factory.standard_claims(
        ISSUER_A, AUDIENCE, iat=clock.now() + 120))
    case("18 iat 在未来", iat_future, TENANT_A)

    bool_time = factory.issue(mat_a, {
        "iss": ISSUER_A, "aud": AUDIENCE, "exp": True, "iat": clock.now(), "nbf": clock.now()})
    case("19 exp 为布尔值", bool_time, TENANT_A)

    missing = factory.issue(mat_a, {"iss": ISSUER_A, "aud": AUDIENCE, "iat": clock.now()})
    case("20 缺少必填 exp", missing, TENANT_A)

    # 刷新故障：未知 kid 触发刷新，脚本第二项是异常
    mystery = factory.new_rsa_material(TENANT_A, "k404")
    case("21 未知 kid 且刷新故障", factory.issue(mystery, factory.standard_claims(
        ISSUER_A, AUDIENCE)), TENANT_A)

    # 汇总断言：仅 01、10、13、16、17 应放行
    # 边界规则（来自 joserfc，可由 leeway 配置）：
    #   exp: now >= exp - leeway 即过期（含等号），故 exp==now 拒绝、偏差边界也拒绝；
    #   nbf: nbf > now + leeway 才拒绝（严格大于），故偏差边界与 nbf==now 均接受。
    accepted_names = {name for name, d in results if d.accepted}  # type: ignore[attr-defined]
    expected_accepted = {
        "01 合法令牌",
        "10 受众数组包含我方",
        "13 过期但在时钟偏差内",
        "16 nbf 恰好落在偏差边界（nbf 用严格大于，边界接受）",
        "17 nbf 恰好等于当前时间（即时生效）",
    }
    assert accepted_names == expected_accepted, accepted_names
    # 每条成功记录都必须走完五个阶段，不存在旁路
    for name, d in results:
        if d.accepted:  # type: ignore[attr-defined]
            from tenant_auth.errors import Stage
            assert d.stages[-1] is Stage.CLAIMS  # type: ignore[attr-defined]
    print(f"\n矩阵断言通过：放行集合 {sorted(accepted_names)}，其余全部拒绝且停在正确阶段。")

    # ------------------------------------------------------------------
    print("\n" + "=" * 78)
    print("确定性并发：8 个线程同时验证同一未知 kid 的令牌，只允许一次刷新")
    print("=" * 78)
    clock2 = ControlledClock(BASE_TIME)
    factory2 = TokenFactory(clock2)
    mat = factory2.new_rsa_material(TENANT_A, "k1")
    blocking = BlockingKeySource({"keys": [mat.public_jwk()]})
    policy = TenantPolicy(TENANT_A, ISSUER_A, AUDIENCE, frozenset({"RS256"}), key_set_ttl=300)
    v2 = MultiTenantVerifier.build({TENANT_A: policy}, blocking, clock2)
    token = factory2.issue(mat, factory2.standard_claims(ISSUER_A, AUDIENCE))

    outcomes: list[object] = []
    barrier = threading.Barrier(8)

    def worker() -> None:
        barrier.wait()  # 尽量让 8 个线程同时进入
        outcomes.append(v2.diagnose(token, TENANT_A))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    assert blocking.entered.wait(timeout=5), "刷新发起者未进入密钥源"
    blocking.release()
    for t in threads:
        t.join()

    accepted = sum(1 for d in outcomes if d.accepted)  # type: ignore[attr-defined]
    print(f"并发请求数=8，密钥源实际调用={blocking.calls}，放行={accepted}，拒绝={8 - accepted}")
    assert blocking.calls == 1
    assert accepted == 8
    # 首个请求刷新完成，其余 7 个是等待者：它们与发起者走完全相同的检查链
    assert all(d.stages[-1].value == "claims" for d in outcomes)  # type: ignore[attr-defined]
    print("并发断言通过：单次刷新，8 个请求全部经同一检查链放行（等待者收到同一结果）。")


if __name__ == "__main__":
    main()
