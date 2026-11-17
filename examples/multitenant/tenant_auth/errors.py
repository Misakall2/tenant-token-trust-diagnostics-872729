"""诊断阶段与错误类型。

错误对象只携带稳定的机器可读原因码（``reason``）和非敏感细节，
绝不携带完整令牌、私钥或声明正文。
"""

from enum import Enum


class Stage(str, Enum):
    """一次验证请求按顺序经过的阶段。"""

    #: 租户选择：租户 ID 只能来自可信调用上下文
    TENANT_SELECTION = "tenant_selection"
    #: 密钥刷新：向租户绑定的（假）密钥源拉取 JWKS
    KEY_REFRESH = "key_refresh"
    #: 密钥选择：按令牌 kid 在该租户快照内定位唯一验证钥匙
    KEY_SELECTION = "key_selection"
    #: 签名验证：joserfc 在固定算法白名单下验签
    SIGNATURE = "signature"
    #: 声明检查：iss/aud/exp/nbf/iat 与必填声明
    CLAIMS = "claims"


class DiagnosticError(Exception):
    """所有接入侧诊断错误的基类。

    :param stage: 失败阶段
    :param reason: 稳定原因码，供断言与日志聚合使用
    :param tenant_id: 可信上下文传入的租户 ID
    :param detail: 非敏感补充信息（kid、算法名、声明名等标识符可以，正文不可以）
    """

    def __init__(
        self,
        stage: Stage,
        reason: str,
        tenant_id: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.stage = stage
        self.reason = reason
        self.tenant_id = tenant_id
        self.detail = detail
        message = f"stage={stage.value} reason={reason}"
        if tenant_id is not None:
            message += f" tenant={tenant_id}"
        if detail is not None:
            message += f" detail={detail}"
        super().__init__(message)


class TenantSelectionError(DiagnosticError):
    """租户策略缺失或租户上下文不可信。"""

    def __init__(self, reason: str, tenant_id: str | None = None, detail: str | None = None) -> None:
        super().__init__(Stage.TENANT_SELECTION, reason, tenant_id, detail)


class KeyRefreshError(DiagnosticError):
    """密钥源不可用、快照非法（重复编号、缺编号、空集合）等刷新期失败。"""

    def __init__(self, reason: str, tenant_id: str | None = None, detail: str | None = None) -> None:
        super().__init__(Stage.KEY_REFRESH, reason, tenant_id, detail)


class KeySelectionError(DiagnosticError):
    """快照内找不到 kid、钥匙用途不符等选择期失败。"""

    def __init__(self, reason: str, tenant_id: str | None = None, detail: str | None = None) -> None:
        super().__init__(Stage.KEY_SELECTION, reason, tenant_id, detail)


class SignatureVerificationError(DiagnosticError):
    """令牌格式错误、算法不在白名单、签名不匹配等。"""

    def __init__(self, reason: str, tenant_id: str | None = None, detail: str | None = None) -> None:
        super().__init__(Stage.SIGNATURE, reason, tenant_id, detail)


class ClaimsValidationError(DiagnosticError):
    """声明检查失败。``claim`` 记录是哪一个声明触发的。"""

    def __init__(
        self,
        reason: str,
        tenant_id: str | None = None,
        claim: str | None = None,
        detail: str | None = None,
    ) -> None:
        super().__init__(Stage.CLAIMS, reason, tenant_id, detail)
        self.claim = claim


def shared_failure(exc: DiagnosticError) -> DiagnosticError:
    """复制一个同阶段同原因的错误给单飞等待者，证明等待者收到同一结果。"""
    if isinstance(exc, ClaimsValidationError):
        return ClaimsValidationError(exc.reason, exc.tenant_id, exc.claim, exc.detail)
    return type(exc)(exc.reason, exc.tenant_id, exc.detail)
