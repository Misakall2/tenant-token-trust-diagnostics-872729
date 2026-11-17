"""演示 1："签名通过就放行"等错误接法与正确接法的差异（完全离线）。

运行方式（仓库根目录）：

    python examples/multitenant/demo_wrong_vs_correct.py

所有密钥在进程内临时生成，脚本结束即销毁；不发起任何网络请求，
输出中只有令牌短指纹，没有完整令牌、私钥或声明正文。
"""

import sys
from pathlib import Path

# 让脚本在仓库根目录或 examples/multitenant 下都能直接运行
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    sys.stdout.reconfigure(encoding="utf-8")  # Windows 控制台默认 GBK，固定 UTF-8 输出
except (AttributeError, ValueError):
    pass

from joserfc import jwt  # noqa: E402
from joserfc.errors import ClaimError  # noqa: E402
from joserfc.jwk import RSAKey  # noqa: E402
from joserfc.jws import JWSRegistry  # noqa: E402
from joserfc.jwt import JWTClaimsRegistry  # noqa: E402

from tenant_auth.clock import ControlledClock  # noqa: E402
from tenant_auth.keystore import FakeKeySource  # noqa: E402
from tenant_auth.model import TenantPolicy  # noqa: E402
from tenant_auth.tokens import TokenFactory  # noqa: E402
from tenant_auth.verifier import MultiTenantVerifier  # noqa: E402

TENANT = "tenant-a"
ISSUER = "https://issuer-a.example"
AUDIENCE = "api-gateway"
BASE_TIME = 1_800_000_000


def build_world() -> tuple[ControlledClock, TokenFactory, MultiTenantVerifier, dict]:
    clock = ControlledClock(BASE_TIME)
    factory = TokenFactory(clock)
    material = factory.new_rsa_material(TENANT, "k1")
    source = FakeKeySource()
    source.set_script(TENANT, [{"keys": [material.public_jwk()]}])
    policy = TenantPolicy(TENANT, ISSUER, AUDIENCE, frozenset({"RS256"}), key_set_ttl=300, leeway=30)
    verifier = MultiTenantVerifier.build({TENANT: policy}, source, clock)
    return clock, factory, verifier, {"material": material, "source": source, "policy": policy}


def section(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def main() -> None:
    clock, factory, verifier, world = build_world()
    material = world["material"]
    public_key = RSAKey.import_key(material.public_jwk())

    section("基线：合法令牌，正确接法放行")
    good_token = factory.issue(material, factory.standard_claims(ISSUER, AUDIENCE))
    print(verifier.diagnose(good_token, TENANT).summary_line())

    # ------------------------------------------------------------------
    section("错误接法 A：jwt.decode 成功就把声明交给业务（跳过声明检查）")
    # 伪造者无法伪造签名，但可以拿到一枚*自己租户*合法签发、却已过期/越权的令牌；
    # 只验签的代码会照单全收。
    expired_claims = factory.standard_claims(ISSUER, AUDIENCE, ttl=-600)
    expired_token = factory.issue(material, expired_claims)
    token_obj = jwt.decode(expired_token, public_key, algorithms=["RS256"])  # 库：只验签
    wrong_release = token_obj.claims  # 错误接入：这里直接放行
    print(f"[错误接法] 过期令牌被放行，业务读到 exp={wrong_release['exp']}（当前时间 {clock.now()}）")

    diagnosis = verifier.diagnose(expired_token, TENANT)
    print("[正确接法]", diagnosis.summary_line())

    # ------------------------------------------------------------------
    section("错误接法 B：信任令牌自带的 iss 来选择信任配置（配置被令牌反向驱动）")
    # 攻击者在自己控制的签发者下拿到一枚真实签名的令牌，iss 写成受害者域名。
    # 若接入方按 token.claims['iss'] 找配置，就会用错误签发者的钥匙校验并放行。
    attacker_material = factory.new_rsa_material("attacker", "attacker-k1")
    spoofed = factory.issue(
        attacker_material,
        factory.standard_claims(ISSUER, AUDIENCE),  # iss 伪装成受害者
    )
    attacker_key = RSAKey.import_key(attacker_material.public_jwk())

    def wrong_tenant_driven_verify(token: str) -> str:
        obj = jwt.decode(token, attacker_key, algorithms=["RS256"])  # 钥匙跟着不可信来源走
        issuer = obj.claims["iss"]  # 用令牌自带 iss 当信任锚
        requests = JWTClaimsRegistry(now=clock.now(), iss={"essential": True, "value": issuer})
        try:
            requests.validate(obj.claims)
        except ClaimError:
            return "REJECT"
        return "ACCEPT"

    print(f"[错误接法] 伪装 iss 的外部令牌结果：{wrong_tenant_driven_verify(spoofed)}")
    print("[正确接法]", verifier.diagnose(spoofed, TENANT).summary_line(), "（租户钥匙验签失败）")

    # ------------------------------------------------------------------
    section("错误接法 C：算法白名单含 none / 不做白名单限制")
    none_token = TokenFactory.unsigned_none_token(
        {"iss": ISSUER, "aud": AUDIENCE, "exp": clock.now() + 300}
    )
    permissive_registry = JWSRegistry(algorithms=["none", "RS256"])  # 危险配置
    obj = jwt.decode(none_token, None, registry=permissive_registry)
    print(f"[错误接法] alg=none 被宽松注册表解析，声明直接可得：iss={obj.claims['iss']}")
    print("[正确接法]", verifier.diagnose(none_token, TENANT).summary_line())

    # ------------------------------------------------------------------
    section("错误接法 D：篡改载荷/签名后仍以为 decode 会兜底所有安全问题")
    tampered = TokenFactory.tamper_payload(good_token)
    try:
        jwt.decode(tampered, public_key, algorithms=["RS256"])
    except Exception as exc:  # noqa: BLE001 - 演示用，仅打印错误类型
        print(f"[库职责] 验签阶段抛出 {type(exc).__name__}: {exc.error}")
    print("[正确接法]", verifier.diagnose(tampered, TENANT).summary_line())

    # ------------------------------------------------------------------
    section("结论：库职责 vs 接入错误")
    print(
        "joserfc 的职责：按给定钥匙与算法注册表验证 JWS 签名、提供声明校验原语。\n"
        "  * jwt.decode 文档明确说明它只验证签名与载荷格式，不校验业务声明；\n"
        "  * alg=none 是 RFC 7515 的中性能力，库不会替接入方决定信任策略。\n"
        "接入方职责（本样例的正确接法）：\n"
        "  1) 租户只由可信上下文选择，iss/jku/jwk/alg 不能反向改变信任配置；\n"
        "  2) 固定签发者、受众与算法白名单（永远不含 none）；\n"
        "  3) 验签成功后必须再过声明检查，VerifiedClaims 只在全链通过后产生。"
    )

    # 总断言：上述全部恶意/非法令牌，正确接法一律拒绝
    for bad in (expired_token, spoofed, none_token, tampered):
        d = verifier.diagnose(bad, TENANT)
        assert not d.accepted, d.summary_line()
    assert verifier.diagnose(good_token, TENANT).accepted
    print("\n断言通过：4 类错误令牌全部 REJECT，合法令牌 ACCEPT。")


if __name__ == "__main__":
    main()
