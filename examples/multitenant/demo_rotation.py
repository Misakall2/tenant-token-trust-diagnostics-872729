"""演示 2：可回放的租户密钥轮换（含刷新故障、TTL 到期、同 kid 跨租户）。

运行方式（仓库根目录）：

    python examples/multitenant/demo_rotation.py

全程使用 FakeKeySource 脚本驱动，无网络；每一步都打印实际放行结果与刷新次数。
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    sys.stdout.reconfigure(encoding="utf-8")  # Windows 控制台默认 GBK，固定 UTF-8 输出
except (AttributeError, ValueError):
    pass

from tenant_auth.clock import ControlledClock  # noqa: E402
from tenant_auth.keystore import FakeKeySource, TenantKeyStore  # noqa: E402
from tenant_auth.model import TenantPolicy  # noqa: E402
from tenant_auth.tokens import TokenFactory  # noqa: E402
from tenant_auth.verifier import MultiTenantVerifier  # noqa: E402

BASE_TIME = 1_800_000_000
TENANT_A = "tenant-a"
TENANT_B = "tenant-b"
ISSUER_A = "https://issuer-a.example"
ISSUER_B = "https://issuer-b.example"
AUDIENCE = "api"


def section(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def main() -> None:
    clock = ControlledClock(BASE_TIME)
    factory = TokenFactory(clock)

    # 两代密钥：k1（旧）与 k2（新）；另一个租户也使用编号 k1，验证互不串用
    old_key = factory.new_rsa_material(TENANT_A, "k1")
    new_key = factory.new_rsa_material(TENANT_A, "k2")
    tenant_b_key = factory.new_rsa_material(TENANT_B, "k1", alg="RS256")

    source = FakeKeySource()
    # 刷新脚本（按调用顺序消费，末项重复返回）：
    #   1) 旧快照 k1  2) 轮换后新快照 k2  3) 再给一次新快照（让未知 kid 的刷新成功）
    #   4) 起模拟端点故障
    source.set_script(
        TENANT_A,
        [
            {"keys": [old_key.public_jwk()]},
            {"keys": [new_key.public_jwk()]},
            {"keys": [new_key.public_jwk()]},
            RuntimeError("simulated JWKS endpoint outage"),
        ],
    )
    source.set_script(TENANT_B, [{"keys": [tenant_b_key.public_jwk()]}])

    policies = {
        TENANT_A: TenantPolicy(TENANT_A, ISSUER_A, AUDIENCE, frozenset({"RS256"}), key_set_ttl=300),
        TENANT_B: TenantPolicy(TENANT_B, ISSUER_B, AUDIENCE, frozenset({"RS256"}), key_set_ttl=300),
    }
    verifier = MultiTenantVerifier.build(policies, source, clock)
    store: TenantKeyStore = verifier.key_store

    section("1) 初始令牌由 k1 签发：首次验证触发一次刷新，随后命中缓存")
    token_k1 = factory.issue(old_key, factory.standard_claims(ISSUER_A, AUDIENCE))
    d1 = verifier.diagnose(token_k1, TENANT_A)
    print(d1.summary_line(), f"| 缓存命中={d1.cache_used} 刷新尝试={d1.refresh_attempted}")
    d1b = verifier.diagnose(token_k1, TENANT_A)
    print(d1b.summary_line(), f"| 缓存命中={d1b.cache_used} 刷新尝试={d1b.refresh_attempted}")
    count_after_init = source.call_count(TENANT_A)
    print(f"密钥源实际调用次数：{count_after_init}（期望 1）")
    assert d1.accepted and not d1.cache_used and d1.refresh_attempted
    assert d1b.accepted and d1b.cache_used and not d1b.refresh_attempted
    assert count_after_init == 1

    section("2) 相同 kid 跨租户不串用：两租户都有 k1，查找只在本租户快照内进行")
    token_b = factory.issue(tenant_b_key, factory.standard_claims(ISSUER_B, AUDIENCE))
    d_b_ok = verifier.diagnose(token_b, TENANT_B)
    print("B 上下文验证 B 的令牌：", d_b_ok.summary_line())
    cross = verifier.diagnose(token_b, TENANT_A)
    print("A 上下文验证 B 的令牌：", cross.summary_line(), "（选中 A 自己的 k1 公钥，验签失败）")
    print(f"两租户密钥源调用次数：A={source.call_count(TENANT_A)} B={source.call_count(TENANT_B)}（无跨租户刷新）")
    assert d_b_ok.accepted and not cross.accepted and cross.reason == "bad_signature"
    assert source.call_count(TENANT_A) == count_after_init  # 跨租户不触发 A 的刷新
    assert source.call_count(TENANT_B) == 1

    section("3) 轮换：密钥源切到 k2，未知 kid 触发该租户一次刷新")
    token_k2 = factory.issue(new_key, factory.standard_claims(ISSUER_A, AUDIENCE))
    d2 = verifier.diagnose(token_k2, TENANT_A)
    print(d2.summary_line(), f"| 缓存命中={d2.cache_used}")
    count_after_rotation = source.call_count(TENANT_A)
    print(f"密钥源实际调用次数：{count_after_rotation}（期望 2），成功刷新计数：{store.refresh_completed(TENANT_A)}")
    assert d2.accepted and count_after_rotation == 2

    section("4) 轮换后旧钥匙令牌被拒：刷新确认 k1 已不存在；负缓存保证同世代只刷新一次")
    d3 = verifier.diagnose(token_k1, TENANT_A)
    print(d3.summary_line())
    count_after_old_reject = source.call_count(TENANT_A)
    print(f"密钥源实际调用次数：{count_after_old_reject}（期望 3，为确认 k1 不在新快照刷新一次）")
    d3b = verifier.diagnose(token_k1, TENANT_A)
    print("同一未知 kid 再次请求：", d3b.summary_line())
    print(f"密钥源实际调用次数：{source.call_count(TENANT_A)}（仍为 {count_after_old_reject}，负缓存命中）")
    assert not d3.accepted and d3.reason == "unknown_key_id" and count_after_old_reject == 3
    assert not d3b.accepted and d3b.reason == "unknown_key_id"
    assert source.call_count(TENANT_A) == count_after_old_reject  # 无新增刷新、不逐个试钥匙

    section("5) 刷新故障：失败不覆盖当前快照，已知 kid 继续服务，失败可重试")
    mystery = factory.new_rsa_material(TENANT_A, "k9")
    token_mystery = factory.issue(mystery, factory.standard_claims(ISSUER_A, AUDIENCE))
    d4 = verifier.diagnose(token_mystery, TENANT_A)
    print(d4.summary_line())
    print(f"最近刷新故障原因：{store.last_refresh_error(TENANT_A)}；快照仍存在：{store.has_snapshot(TENANT_A)}")
    d4b = verifier.diagnose(token_k2, TENANT_A)
    print("故障后已知 kid 的令牌：", d4b.summary_line(), f"| 缓存命中={d4b.cache_used}")
    d4c = verifier.diagnose(token_mystery, TENANT_A)
    print("故障后同一未知 kid 重试：", d4c.summary_line(), "（失败不记负缓存，允许再次尝试）")
    print(f"密钥源实际调用次数：{source.call_count(TENANT_A)}（两次故障重试各计一次）")
    assert not d4.accepted and d4.reason == "source_unavailable"
    assert d4b.accepted and d4b.cache_used
    assert not d4c.accepted and d4c.reason == "source_unavailable"

    section("6) TTL 到期后不能无限用旧钥匙：到期 + 刷新故障 => 拒绝而非放行")
    clock.advance(301)
    d5 = verifier.diagnose(token_k2, TENANT_A)
    print(d5.summary_line())
    print(f"快照年龄 {store.snapshot_age(TENANT_A)}s > TTL 300s，刷新仍故障，拒绝放行")
    assert not d5.accepted and d5.reason == "source_unavailable"
    print("\n断言全部通过：轮换、负缓存、故障保留与可重试、TTL 失效、跨租户隔离均符合预期。")


if __name__ == "__main__":
    main()
