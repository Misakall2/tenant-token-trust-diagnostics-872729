"""信任模型：租户策略、诊断结果与脱敏工具。

信任配置（签发者、受众、算法白名单、密钥源）全部按租户固定，
令牌自身携带的 iss / jku / jwk / alg 不能反向修改这里的任何字段。
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any

from .errors import Stage


def redact_fingerprint(value: str | bytes) -> str:
    """对敏感原文计算不可逆短指纹，用于日志关联而不泄露内容。

    只返回 SHA-256 的前 12 个十六进制字符；完整令牌、私钥、声明正文
    都不允许进入诊断结果。
    """
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()[:12]


@dataclass(frozen=True)
class TenantPolicy:
    """单个租户的固定信任配置，由可信配置面下发，不接受令牌覆盖。

    :param issuer: 期望的精确 iss 值
    :param audience: 期望的 aud（字符串，或字符串数组中的任一元素）
    :param allowed_algorithms: 该租户允许的 JWS 算法白名单
    :param key_set_ttl: 密钥快照有效期（秒）
    :param leeway: 时钟偏差容忍（秒），对 exp/nbf/iat 同时生效
    :param required_claims: 除 iss/aud/exp 外额外要求存在的声明名
    """

    tenant_id: str
    issuer: str
    audience: str
    allowed_algorithms: frozenset[str]
    key_set_ttl: int = 300
    leeway: int = 30
    required_claims: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        if not self.tenant_id:
            raise ValueError("tenant_id must be a non-empty string")
        if not self.issuer:
            raise ValueError("issuer must be a non-empty string")
        if not self.audience:
            raise ValueError("audience must be a non-empty string")
        if not self.allowed_algorithms:
            raise ValueError("allowed_algorithms must not be empty")
        if "none" in self.allowed_algorithms:
            raise ValueError("the 'none' algorithm must never be whitelisted")
        if self.key_set_ttl <= 0:
            raise ValueError("key_set_ttl must be positive")
        if self.leeway < 0:
            raise ValueError("leeway must not be negative")


@dataclass(frozen=True)
class VerifiedClaims:
    """只有走完签名验证与声明检查之后才会构造的业务对象。

    不存在"先返回已解析声明、再让业务自己检查"的旁路。
    """

    tenant_id: str
    claims: dict[str, Any]
    kid: str
    alg: str


@dataclass
class Diagnosis:
    """一次验证的可回放诊断记录（脱敏）。

    ``stages`` 记录实际走过的阶段链；任何成功请求都必须走到 CLAIMS，
    失败请求停在第一个失败阶段，便于在日志中定位根因而不泄露令牌内容。
    """

    accepted: bool
    tenant_id: str | None
    stages: list[Stage]
    failure_stage: Stage | None
    reason: str | None
    token_fingerprint: str
    kid: str | None = None
    alg: str | None = None
    refresh_attempted: bool = False
    cache_used: bool = False
    #: verify() 透传的原始接入错误（含 claim 等细粒度字段），不参与序列化展示
    cause: object | None = None

    def summary_line(self) -> str:
        chain = " -> ".join(stage.value for stage in self.stages)
        if self.accepted:
            return f"ACCEPT  tenant={self.tenant_id} chain=[{chain}] kid={self.kid} alg={self.alg}"
        return (
            f"REJECT  tenant={self.tenant_id} chain=[{chain}] "
            f"failed_at={self.failure_stage.value if self.failure_stage else '-'} "
            f"reason={self.reason} token~={self.token_fingerprint}"
        )
