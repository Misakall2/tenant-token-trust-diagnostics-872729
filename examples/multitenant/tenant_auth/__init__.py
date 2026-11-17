"""多租户 JWT 接入诊断包（基于 joserfc 公开接口的离线样例）。

本包不修改 joserfc 任何代码，只演示接入方应承担的职责：
可信租户选择、租户隔离的密钥缓存与轮换、固定信任配置下的验签，
以及验签之后不可跳过的声明检查。
"""

from .clock import Clock, ControlledClock, SystemClock
from .errors import (
    ClaimsValidationError,
    DiagnosticError,
    KeyRefreshError,
    KeySelectionError,
    SignatureVerificationError,
    Stage,
    TenantSelectionError,
)
from .keystore import BlockingKeySource, TenantKeyStore
from .model import Diagnosis, TenantPolicy, VerifiedClaims, redact_fingerprint
from .tokens import TenantKeyMaterial, TokenFactory
from .verifier import MultiTenantVerifier

__all__ = [
    "Clock",
    "ControlledClock",
    "SystemClock",
    "Stage",
    "DiagnosticError",
    "TenantSelectionError",
    "KeyRefreshError",
    "KeySelectionError",
    "SignatureVerificationError",
    "ClaimsValidationError",
    "TenantPolicy",
    "VerifiedClaims",
    "Diagnosis",
    "TenantKeyStore",
    "BlockingKeySource",
    "MultiTenantVerifier",
    "TokenFactory",
    "TenantKeyMaterial",
    "redact_fingerprint",
]
