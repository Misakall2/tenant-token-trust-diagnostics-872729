"""离线令牌工厂：用临时生成的真实密钥签发测试令牌。

所有密钥只存在于进程内存中，测试结束即销毁，不落盘、不连网。
工厂同时提供"错误接法"演示需要的伪造变体（篡改、none、算法混淆、
串租户令牌），这些变体全部由真实材料构造，可离线回放。
"""

import base64
import json
from dataclasses import dataclass
from typing import Any

from joserfc import jwt
from joserfc.jwk import ECKey, Key, RSAKey
from joserfc.jws import JWSRegistry

from .clock import Clock


@dataclass
class TenantKeyMaterial:
    """一个租户的签名私钥与对外公开 JWKS 视图。"""

    tenant_id: str
    signing_key: Key
    alg: str
    kid: str
    use: str = "sig"

    def public_jwk(self) -> dict[str, Any]:
        data = self.signing_key.as_dict(private=False)
        data["kid"] = self.kid
        data["use"] = self.use
        return data


class TokenFactory:
    """按租户材料签发 JWT，并构造典型错误令牌。"""

    def __init__(self, clock: Clock) -> None:
        self._clock = clock

    # ----- 真实材料 -----

    @staticmethod
    def new_rsa_material(tenant_id: str, kid: str, alg: str = "RS256", use: str = "sig") -> TenantKeyMaterial:
        key = RSAKey.generate_key(2048, parameters={"kid": kid, "use": use})
        return TenantKeyMaterial(tenant_id, key, alg, kid, use)

    @staticmethod
    def new_ec_material(tenant_id: str, kid: str, alg: str = "ES256", use: str = "sig") -> TenantKeyMaterial:
        key = ECKey.generate_key("P-256", parameters={"kid": kid, "use": use})
        return TenantKeyMaterial(tenant_id, key, alg, kid, use)

    # ----- 正常签发 -----

    def issue(
        self,
        material: TenantKeyMaterial,
        claims: dict[str, Any],
        *,
        alg: str | None = None,
        kid: str | None = None,
        extra_headers: dict[str, Any] | None = None,
    ) -> str:
        header: dict[str, Any] = {"alg": alg or material.alg, "kid": kid or material.kid}
        if extra_headers:
            header.update(extra_headers)
        return jwt.encode(header, claims, material.signing_key, algorithms=[header["alg"]])

    def standard_claims(
        self,
        issuer: str,
        audience: str | list[str],
        *,
        ttl: int = 300,
        nbf: int | None = None,
        iat: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        now = self._clock.now()
        claims: dict[str, Any] = {
            "iss": issuer,
            "aud": audience,
            "iat": iat if iat is not None else now,
            "nbf": nbf if nbf is not None else now,
            "exp": now + ttl,
            "sub": "diagnostic-subject",
        }
        if extra:
            claims.update(extra)
        return claims

    # ----- 伪造/错误变体 -----

    @staticmethod
    def tamper_signature(token: str) -> str:
        """保留头部与载荷，破坏签名（真实令牌被改动后的样子）。"""
        header_b64, payload_b64, signature_b64 = token.split(".")
        raw = bytearray(base64.urlsafe_b64decode(signature_b64 + "=" * (-len(signature_b64) % 4)))
        raw[0] ^= 0x01
        new_sig = base64.urlsafe_b64encode(bytes(raw)).rstrip(b"=").decode("ascii")
        return f"{header_b64}.{payload_b64}.{new_sig}"

    @staticmethod
    def tamper_payload(token: str) -> str:
        """篡改载荷但不重签 —— 签名必然失效，证明库不会放行内容被改的令牌。"""
        header_b64, payload_b64, signature_b64 = token.split(".")
        padding = "=" * (-len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64 + padding))
        payload["sub"] = "forged-subject"
        new_payload = base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        return f"{header_b64}.{new_payload}.{signature_b64}"

    @staticmethod
    def unsigned_none_token(claims: dict[str, Any], kid: str | None = "k1") -> str:
        """构造 alg=none 的无签名令牌。

        需要显式构造允许 none 的注册表才能产出，模拟历史 CVE-2015-9235 类攻击面；
        正确接入的白名单永远不包含 none。带上合法形态的 kid，确保拦截它的是
        算法白名单而不是别的检查。
        """
        header: dict[str, Any] = {"alg": "none", "typ": "JWT"}
        if kid is not None:
            header["kid"] = kid
        header_b64 = base64.urlsafe_b64encode(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        payload_b64 = base64.urlsafe_b64encode(
            json.dumps(claims, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        return f"{header_b64}.{payload_b64}."

    @staticmethod
    def can_library_accept_none() -> bool:
        """验证 joserfc 在显式启用 none 的注册表里确实能解析该结构。

        这是库的中性能力（RFC 7515 允许 none），是否信任它完全是接入方策略。
        """
        registry = JWSRegistry(algorithms=["none"])
        from joserfc import jws

        obj = jws.extract_compact(TokenFactory.unsigned_none_token({"iss": "x"}).encode("utf-8"), None, registry)
        return jws.validate_compact(obj, None, registry=registry)
