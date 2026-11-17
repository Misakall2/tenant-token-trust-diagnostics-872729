"""多租户验证器：把 joserfc 的密码学原语组织成完整信任链。

检查链（任何请求都按此顺序，失败即停在对应阶段）：

    TENANT_SELECTION -> KEY_REFRESH -> KEY_SELECTION -> SIGNATURE -> CLAIMS

关键边界：

* 租户 ID 只来自调用方显式传入的可信上下文，令牌里没有任何字段能选择租户；
* iss/aud/算法白名单来自该租户的固定策略，令牌头里的 jku/jwk/alg 只能
  被检查、不能改变信任配置；
* ``jwt.decode`` 只负责验签（joserfc 文档明确声明它不校验声明），
  声明检查由本模块强制完成，且 :class:`VerifiedClaims` 只在全部通过后产生；
* 本类没有任何"只解析不校验就返回声明"的方法，业务侧拿不到旁路对象。
"""

import base64
import json
from collections.abc import Mapping
from typing import Any

from joserfc import jwt
from joserfc.errors import (
    BadSignatureError,
    ClaimError,
    DecodeError,
    JoseError,
    UnsupportedAlgorithmError,
)
from joserfc.jws import JWSRegistry
from joserfc.jwt import JWTClaimsRegistry

from .clock import Clock, SystemClock
from .errors import (
    ClaimsValidationError,
    DiagnosticError,
    KeySelectionError,
    SignatureVerificationError,
    Stage,
    TenantSelectionError,
)
from .keystore import TenantKeyStore
from .model import Diagnosis, TenantPolicy, VerifiedClaims, redact_fingerprint


def _peek_header(token: str) -> dict[str, Any]:
    """只解码头部用于读取 kid/alg，不做任何信任判断。

    头部是公开元数据；信任与否完全由后续固定策略决定。
    """
    try:
        header_segment = token.split(".", 1)[0]
        padding = "=" * (-len(header_segment) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_segment + padding))
    except (ValueError, TypeError, json.JSONDecodeError) as exc:
        raise SignatureVerificationError("malformed_token", detail="header is not decodable") from exc
    if not isinstance(header, dict):
        raise SignatureVerificationError("malformed_token", detail="header is not a JSON object")
    return header


class MultiTenantVerifier:
    """策略固定、密钥租户隔离、验签与声明检查一体的验证器。"""

    def __init__(
        self,
        policies: Mapping[str, TenantPolicy],
        key_store: TenantKeyStore,
        clock: Clock | None = None,
    ) -> None:
        self._policies = dict(policies)
        self._store = key_store
        self._clock = clock or SystemClock()

    @classmethod
    def build(
        cls,
        policies: Mapping[str, TenantPolicy],
        key_source: Any,
        clock: Clock | None = None,
    ) -> "MultiTenantVerifier":
        """便捷构造：按各租户策略里的 TTL 建立密钥缓存。"""
        clock = clock or SystemClock()
        store = TenantKeyStore(
            key_source,
            {tenant_id: policy.key_set_ttl for tenant_id, policy in policies.items()},
            clock=clock,
        )
        return cls(policies, store, clock)

    @property
    def key_store(self) -> TenantKeyStore:
        return self._store

    # ----- 对外两个入口，共用同一条检查链 -----

    def verify(self, token: str, trusted_tenant_id: str) -> VerifiedClaims:
        """验证通过才返回 :class:`VerifiedClaims`，失败抛出 :class:`DiagnosticError`。"""
        result, claims = self._run_chain(token, trusted_tenant_id)
        if not result.accepted:
            assert isinstance(result.failure_stage, Stage)
            if isinstance(result.cause, DiagnosticError):
                # 透传原始错误，保留 claim 等细粒度字段
                raise result.cause
            raise self._error_for(result)
        assert claims is not None
        return claims

    def diagnose(self, token: str, trusted_tenant_id: str) -> Diagnosis:
        """返回脱敏诊断记录（含阶段链与失败原因），不抛验证类异常。"""
        result, _ = self._run_chain(token, trusted_tenant_id)
        return result

    def _error_for(self, result: Diagnosis) -> DiagnosticError:
        assert result.failure_stage is not None
        if result.failure_stage is Stage.CLAIMS:
            return ClaimsValidationError(result.reason or "claim_rejected", result.tenant_id)
        if result.failure_stage is Stage.SIGNATURE:
            return SignatureVerificationError(result.reason or "signature_rejected", result.tenant_id)
        if result.failure_stage is Stage.KEY_SELECTION:
            return KeySelectionError(result.reason or "key_rejected", result.tenant_id)
        if result.failure_stage is Stage.TENANT_SELECTION:
            return TenantSelectionError(result.reason or "tenant_rejected", result.tenant_id)
        return DiagnosticError(result.failure_stage, result.reason or "rejected", result.tenant_id)

    # ----- 检查链 -----

    def _run_chain(
        self, token: str, trusted_tenant_id: str
    ) -> tuple[Diagnosis, VerifiedClaims | None]:
        fingerprint = redact_fingerprint(token)
        stages: list[Stage] = []
        policy: TenantPolicy | None = None
        kid: str | None = None
        alg: str | None = None
        refresh_attempted = False
        cache_used = False

        # 阶段 1：租户选择。只信任显式上下文，不读取令牌中的任何租户线索。
        stages.append(Stage.TENANT_SELECTION)
        policy = self._policies.get(trusted_tenant_id)
        if policy is None:
            return self._reject(
                trusted_tenant_id, stages, Stage.TENANT_SELECTION, "unknown_tenant", fingerprint, kid, alg
            ), None

        # 预解析头部仅用于取 kid/alg；其中 jku/jwk 永远不被读取。
        try:
            header = _peek_header(token)
        except SignatureVerificationError as exc:
            stages.append(Stage.SIGNATURE)
            return self._reject(
                trusted_tenant_id,
                stages,
                Stage.SIGNATURE,
                exc.reason,
                fingerprint,
                kid,
                alg,
            ), None
        kid = header.get("kid")
        alg = header.get("alg")
        if not isinstance(kid, str):
            stages.append(Stage.KEY_SELECTION)
            return self._reject(
                trusted_tenant_id, stages, Stage.KEY_SELECTION, "missing_key_id", fingerprint, kid, alg
            ), None
        if not isinstance(alg, str):
            stages.append(Stage.SIGNATURE)
            return self._reject(
                trusted_tenant_id, stages, Stage.SIGNATURE, "missing_algorithm", fingerprint, kid, alg
            ), None

        # 固定算法白名单先于任何密码学操作生效；令牌无法用自身 alg 扩大白名单。
        if alg not in policy.allowed_algorithms:
            stages.append(Stage.SIGNATURE)
            return self._reject(
                trusted_tenant_id,
                stages,
                Stage.SIGNATURE,
                "algorithm_not_allowed",
                fingerprint,
                kid,
                alg,
            ), None

        # 阶段 2+3：租户隔离的密钥刷新与选择（单飞在 key store 内部完成）。
        stages.append(Stage.KEY_REFRESH)
        stages.append(Stage.KEY_SELECTION)
        try:
            key, cache_used, refresh_attempted = self._store.get_verification_key(trusted_tenant_id, kid, alg)
        except DiagnosticError as exc:
            # 密钥阶段的异常已携带 KEY_REFRESH / KEY_SELECTION 的精确阶段；
            # 负缓存/用途不符这类缓存内拒绝不产生刷新，其余路径均伴随一次刷新尝试
            cached_reject = exc.reason in ("unknown_key_id", "key_use_mismatch")
            diagnosis = self._reject(
                trusted_tenant_id,
                stages,
                exc.stage,
                exc.reason,
                fingerprint,
                kid,
                alg,
                refresh_attempted=not cached_reject,
            )
            diagnosis.cause = exc
            return diagnosis, None

        # 阶段 4：签名验证。注册表再次钉死白名单，双重保险。
        stages.append(Stage.SIGNATURE)
        registry = JWSRegistry(algorithms=sorted(policy.allowed_algorithms))
        try:
            decoded = jwt.decode(token, key, algorithms=sorted(policy.allowed_algorithms), registry=registry)
        except UnsupportedAlgorithmError:
            return self._reject(
                trusted_tenant_id,
                stages,
                Stage.SIGNATURE,
                "algorithm_not_allowed",
                fingerprint,
                kid,
                alg,
                cache_used=cache_used,
            ), None
        except BadSignatureError:
            return self._reject(
                trusted_tenant_id,
                stages,
                Stage.SIGNATURE,
                "bad_signature",
                fingerprint,
                kid,
                alg,
                cache_used=cache_used,
            ), None
        except DecodeError:
            return self._reject(
                trusted_tenant_id,
                stages,
                Stage.SIGNATURE,
                "malformed_token",
                fingerprint,
                kid,
                alg,
                cache_used=cache_used,
            ), None
        except JoseError as exc:
            return self._reject(
                trusted_tenant_id,
                stages,
                Stage.SIGNATURE,
                exc.error or "jose_rejected",
                fingerprint,
                kid,
                alg,
                cache_used=cache_used,
            ), None

        # 阶段 5：声明检查。验签成功不等于放行，必须全部通过才有返回值。
        stages.append(Stage.CLAIMS)
        try:
            self._check_claims(policy, decoded.claims)
        except ClaimsValidationError as exc:
            diagnosis = self._reject(
                trusted_tenant_id,
                stages,
                Stage.CLAIMS,
                exc.reason,
                fingerprint,
                kid,
                alg,
                cache_used=cache_used,
            )
            diagnosis.cause = exc
            return diagnosis, None

        return (
            Diagnosis(
                accepted=True,
                tenant_id=trusted_tenant_id,
                stages=list(stages),
                failure_stage=None,
                reason=None,
                token_fingerprint=fingerprint,
                kid=kid,
                alg=alg,
                refresh_attempted=refresh_attempted,
                cache_used=cache_used,
            ),
            VerifiedClaims(
                tenant_id=trusted_tenant_id,
                claims=decoded.claims,
                kid=kid,
                alg=alg,
            ),
        )

    def _check_claims(self, policy: TenantPolicy, claims: dict[str, Any]) -> None:
        """构造租户固定的声明注册表并执行校验。

        joserfc 已实现：iss 精确匹配、aud 字符串/数组兼容、exp/nbf/iat
        数值与时间检查（布尔值被 NumericDate 判定拒绝）、必填声明缺失拒绝。
        额外必填声明在这里补齐，时间时钟与偏差全部来自注入配置。
        """
        options: dict[str, Any] = {
            "iss": {"essential": True, "value": policy.issuer},
            "aud": {"essential": True, "value": policy.audience},
            "exp": {"essential": True},
        }
        for name in policy.required_claims:
            options.setdefault(name, {"essential": True})

        registry = JWTClaimsRegistry(now=self._clock.now, leeway=policy.leeway, **options)
        try:
            registry.validate(claims)
        except ClaimError as exc:
            # error: missing_claim / invalid_claim / expired_token；claim 记录具体声明名
            raise ClaimsValidationError(
                exc.error,
                policy.tenant_id,
                claim=getattr(exc, "claim", None),
            ) from exc

    @staticmethod
    def _reject(
        tenant_id: str | None,
        stages: list[Stage],
        failure_stage: Stage,
        reason: str,
        fingerprint: str,
        kid: str | None,
        alg: str | None,
        *,
        refresh_attempted: bool = False,
        cache_used: bool = False,
    ) -> Diagnosis:
        return Diagnosis(
            accepted=False,
            tenant_id=tenant_id,
            stages=list(stages),
            failure_stage=failure_stage,
            reason=reason,
            token_fingerprint=fingerprint,
            kid=kid,
            alg=alg,
            refresh_attempted=refresh_attempted,
            cache_used=cache_used,
        )
