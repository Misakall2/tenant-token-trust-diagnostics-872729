"""租户隔离的密钥缓存、轮换与单飞刷新。

设计要点（全部是接入方职责，joserfc 只提供 JWK/KeySet 原语）：

1. 每个租户独立状态：不同租户允许使用相同 kid，但查找永远限定在
   该租户自己的快照内，不存在跨租户试钥匙的路径。
2. 未知 kid 只触发该租户一次刷新；并发请求合并为同一次刷新，
   等待者拿到与发起者完全相同的结果（成功共用快照，失败共用异常）。
3. 刷新失败不覆盖旧快照；但快照一旦按注入时钟到期，就不能再拿旧钥匙放行。
4. 重复 kid、缺失 kid、空快照、钥匙用途不符都直接拒绝，绝不逐个试钥匙。
5. 刷新源只通过协议接口注入，样例中全部使用内存假源，不连接任何外部服务。
"""

import threading
from dataclasses import dataclass
from typing import Any, Callable, Protocol

from joserfc.errors import JoseError
from joserfc.jwk import Key, KeySet, JWKRegistry

from .clock import Clock, SystemClock
from .errors import (
    DiagnosticError,
    KeyRefreshError,
    KeySelectionError,
    shared_failure,
)


class KeySource(Protocol):
    """租户绑定的密钥源协议。生产实现可以包 HTTPS JWKS 端点；样例只用假源。"""

    def fetch(self, tenant_id: str) -> dict[str, Any]:
        """返回原始 JWKS 字典（``{"keys": [...]}``）。失败时抛出任意异常。"""


@dataclass
class _Snapshot:
    """某次成功刷新得到的不可变密钥快照。"""

    key_set: KeySet
    fetched_at: int
    ttl: int

    def is_fresh(self, now: int) -> bool:
        return now - self.fetched_at < self.ttl


@dataclass
class _InFlight:
    """进行中的刷新：统一结果，等待者据此收到同一结论。"""

    snapshot: _Snapshot | None = None
    error: DiagnosticError | None = None


class _TenantState:
    def __init__(self, ttl: int) -> None:
        # Condition 自带锁；刷新结果通过 generation 单调递增广播给等待者，
        # 避免"发起者已完成、后到者看到 in_flight 被清空而重复刷新"的竞态
        self.cond = threading.Condition()
        self.ttl = ttl
        self.snapshot: _Snapshot | None = None
        self.in_flight: _InFlight | None = None
        #: 上一次刷新的结果对象；后到的等待者在 in_flight 已清空时从这里取同一结论
        self.last_completed: _InFlight | None = None
        #: 刷新世代号：每完成一次刷新（成功或失败）+1，等待者据此判断结果已就绪
        self.generation = 0
        #: 已针对当前快照世代触发过刷新的未知 kid（负缓存）；
        #: 新快照安装时清空，保证同一未知 kid 在一个快照世代内只刷新一次
        self.negative_kids: set[str] = set()
        #: 成功完成（快照被接受）的刷新次数
        self.refresh_completed = 0
        #: 实际调用密钥源的次数（单飞发起者才会计数）
        self.fetch_calls = 0
        #: 最近一次刷新失败原因，仅用于诊断，不影响旧快照有效性
        self.last_refresh_error: str | None = None


class TenantKeyStore:
    """按租户隔离的密钥快照缓存。

    :param key_source: 注入的密钥源（样例中为 :class:`FakeKeySource`）
    :param ttl_by_tenant: 每个租户的快照 TTL（秒）
    :param clock: 可注入时钟
    """

    def __init__(
        self,
        key_source: KeySource,
        ttl_by_tenant: dict[str, int],
        clock: Clock | None = None,
        on_wait: "Callable[[str], None] | None" = None,
    ) -> None:
        self._source = key_source
        self._clock = clock or SystemClock()
        #: 线程成为单飞等待者时的回调（仅用于可观测性与确定性测试，生产为 None）
        self._on_wait = on_wait
        self._states: dict[str, _TenantState] = {
            tenant_id: _TenantState(ttl) for tenant_id, ttl in ttl_by_tenant.items()
        }

    # ----- 供测试与诊断使用的只读观测指标 -----

    def fetch_calls(self, tenant_id: str) -> int:
        return self._state(tenant_id).fetch_calls

    def refresh_completed(self, tenant_id: str) -> int:
        return self._state(tenant_id).refresh_completed

    def has_snapshot(self, tenant_id: str) -> bool:
        return self._state(tenant_id).snapshot is not None

    def snapshot_age(self, tenant_id: str) -> int | None:
        state = self._state(tenant_id)
        if state.snapshot is None:
            return None
        return self._clock.now() - state.snapshot.fetched_at

    def last_refresh_error(self, tenant_id: str) -> str | None:
        return self._state(tenant_id).last_refresh_error

    def _state(self, tenant_id: str) -> _TenantState:
        try:
            return self._states[tenant_id]
        except KeyError:
            # 未注册租户属于租户选择阶段的问题，这里防御性兜底
            raise KeyRefreshError("unknown_tenant", tenant_id) from None

    # ----- 刷新 -----

    def force_refresh(self, tenant_id: str) -> None:
        """供轮换演示使用：显式刷新并在失败时抛出。"""
        state = self._state(tenant_id)
        snapshot, error = self._call_source(tenant_id, state)
        with state.cond:
            if error is not None:
                raise error
            assert snapshot is not None
            state.snapshot = snapshot
            state.negative_kids.clear()
            state.last_refresh_error = None
            state.refresh_completed += 1
            state.generation += 1
            state.cond.notify_all()

    def _call_source(
        self, tenant_id: str, state: _TenantState
    ) -> tuple[_Snapshot | None, DiagnosticError | None]:
        """实际访问一次密钥源并校验快照。调用即计费，成功失败都只调一次。"""
        state.fetch_calls += 1
        try:
            raw = self._source.fetch(tenant_id)
            key_set = self._build_key_set(tenant_id, raw)
        except KeyRefreshError as exc:
            state.last_refresh_error = exc.reason
            return None, exc
        except Exception as exc:  # 密钥源抛出的任何异常都归一化，不向外泄露细节
            wrapped = KeyRefreshError("source_unavailable", tenant_id, type(exc).__name__)
            state.last_refresh_error = wrapped.reason
            return None, wrapped
        return _Snapshot(key_set, self._clock.now(), state.ttl), None

    @staticmethod
    def _build_key_set(tenant_id: str, raw: Any) -> KeySet:
        if not isinstance(raw, dict) or not isinstance(raw.get("keys"), list):
            raise KeyRefreshError("malformed_key_set", tenant_id)
        if not raw["keys"]:
            raise KeyRefreshError("empty_key_set", tenant_id)

        keys: list[Key] = []
        seen_kids: set[str] = set()
        for item in raw["keys"]:
            if not isinstance(item, dict) or not item.get("kid") or not isinstance(item["kid"], str):
                raise KeyRefreshError("missing_key_id", tenant_id)
            kid = item["kid"]
            if kid in seen_kids:
                # 同一租户内 kid 必须唯一，否则 get_by_kid 会静默选第一把，拒绝
                raise KeyRefreshError("duplicate_key_id", tenant_id, f"kid={kid}")
            seen_kids.add(kid)
            try:
                keys.append(JWKRegistry.import_key(item))
            except JoseError as exc:
                raise KeyRefreshError("invalid_key_material", tenant_id, exc.error) from exc
        return KeySet(keys)

    # ----- 对外主入口 -----

    def get_verification_key(
        self, tenant_id: str, kid: str | None, alg: str
    ) -> tuple[Key, bool]:
        """按 (租户, kid) 定位唯一验证钥匙。

        :returns: (验证钥匙, 是否使用了缓存快照, 本次请求是否实际参与了刷新)
        :raises DiagnosticError: 刷新失败、未知 kid、用途不符等

        刷新触发规则：

        * 快照缺失/过期，或 kid 在当前快照中未知 -> 触发刷新；
        * 同一 kid 在同一快照世代内只触发一次刷新（负缓存），之后直接拒绝；
        * 刷新失败不把 kid 记入负缓存（下次请求可重试），也不覆盖旧快照；
        * 并发请求由单飞合并，等待者拿到与发起者完全相同的结果。
        """
        state = self._state(tenant_id)

        with state.cond:
            now = self._clock.now()
            snapshot = state.snapshot
            fresh = snapshot is not None and snapshot.is_fresh(now)

            if fresh:
                assert snapshot is not None
                key = self._try_select(snapshot, kid, alg)
                if key is not None:
                    return key, True, False
                if self._kid_present(snapshot, kid):
                    # kid 存在但 use/alg 用途不符：刷新无意义，直接拒绝
                    raise KeySelectionError("key_use_mismatch", tenant_id, f"kid={kid} alg={alg}")
                # 未知 kid：本世代已经刷新过一次就不再请求密钥源
                if kid in state.negative_kids:
                    raise KeySelectionError("unknown_key_id", tenant_id, f"kid={kid}")

            if state.in_flight is None:
                # 本线程成为刷新发起者
                state.in_flight = _InFlight()
                leader = True
                wait_generation = state.generation
            else:
                # 等待者：记下当前世代，阻塞到发起者广播新世代
                leader = False
                wait_generation = state.generation
                if self._on_wait is not None:
                    self._on_wait(tenant_id)

        if leader:
            snapshot_out, error = self._call_source(tenant_id, state)
            with state.cond:
                in_flight = state.in_flight
                assert in_flight is not None
                in_flight.snapshot = snapshot_out
                in_flight.error = error
                state.in_flight = None
                state.last_completed = in_flight  # 供后到等待者读取同一结论
                if error is None:
                    assert snapshot_out is not None
                    state.snapshot = snapshot_out
                    state.negative_kids.clear()  # 新快照世代，负缓存作废
                    state.last_refresh_error = None
                    state.refresh_completed += 1
                state.generation += 1
                state.cond.notify_all()
        else:
            with state.cond:
                # 按世代等待：即使发起者在本线程拿到锁前就已完成，
                # 世代号也已推进，wait 的谓词立即为真，不会重复发起刷新
                if not state.cond.wait_for(
                    lambda: state.generation > wait_generation, timeout=10
                ):
                    raise KeyRefreshError("refresh_wait_timeout", tenant_id)
                completed = state.last_completed
                assert completed is not None
                snapshot_out, error = completed.snapshot, completed.error

        # 等待者与发起者共用同一份刷新结论；二者都算参与了本次刷新。
        if error is not None:
            # 刷新失败绝不覆盖旧快照：仍有未过期旧快照且 kid 在其中可继续服务
            with state.cond:
                fallback = state.snapshot
            if fallback is not None and fallback.is_fresh(self._clock.now()):
                key = self._try_select(fallback, kid, alg)
                if key is not None:
                    return key, True, True
            raise shared_failure(error)

        assert snapshot_out is not None
        with state.cond:
            key = self._try_select(snapshot_out, kid, alg)
            if key is not None:
                return key, False, True
            if self._kid_present(snapshot_out, kid):
                raise KeySelectionError("key_use_mismatch", tenant_id, f"kid={kid} alg={alg}")
            # 新快照里仍然没有该 kid：登记负缓存，本世代不再为它刷新
            state.negative_kids.add(kid)
        raise KeySelectionError("unknown_key_id", tenant_id, f"kid={kid}")

    @staticmethod
    def _kid_present(snapshot: _Snapshot, kid: str | None) -> bool:
        return any(key.kid == kid for key in snapshot.key_set.keys)

    @staticmethod
    def _try_select(snapshot: _Snapshot, kid: str | None, alg: str) -> Key | None:
        """只按精确 kid 选一把钥匙并校验用途；不存在返回 None，绝不遍历试签。"""
        for key in snapshot.key_set.keys:
            if key.kid != kid:
                continue
            # RFC 7517 use 必须是 sig；joserfc 在 alg.check_key 内也会再查一次，
            # 这里提前拦截以产生明确的 key_use_mismatch 诊断。
            designed_use = key.get("use")
            if designed_use is not None and designed_use != "sig":
                return None
            designed_alg = key.get("alg")
            if designed_alg is not None and designed_alg != alg:
                return None
            return key
        return None


class FakeKeySource:
    """离线假密钥源：按脚本返回快照，可模拟故障与轮换，不做任何网络访问。"""

    def __init__(self) -> None:
        self._scripts: dict[str, list[Any]] = {}
        self._lock = threading.Lock()
        self._call_counts: dict[str, int] = {}

    def set_script(self, tenant_id: str, responses: list[Any]) -> None:
        """``responses`` 为 JWKS 字典或 Exception 的序列，按调用顺序消费。"""
        self._scripts[tenant_id] = list(responses)
        self._call_counts.setdefault(tenant_id, 0)

    def fetch(self, tenant_id: str) -> dict[str, Any]:
        with self._lock:
            idx = self._call_counts.get(tenant_id, 0)
            self._call_counts[tenant_id] = idx + 1
            script = self._scripts.get(tenant_id)
            if not script:
                raise RuntimeError(f"no scripted response for tenant {tenant_id}")
            response = script[min(idx, len(script) - 1)]
        if isinstance(response, BaseException):
            # 抛给调用方，由 TenantKeyStore 归一化为 source_unavailable
            raise response
        return response

    def call_count(self, tenant_id: str) -> int:
        return self._call_counts.get(tenant_id, 0)


class BlockingKeySource:
    """确定性并发测试源：首个调用进入后阻塞，直到测试显式放行。

    与 :class:`threading.Barrier` 配合可保证 N 个线程全部在刷新进行中排队，
    从而稳定复现"并发请求合并刷新、等待者收到同一结果"，不依赖时序巧合。
    """

    def __init__(self, response: Any, entered: threading.Event | None = None) -> None:
        self._response = response
        self._entered = entered or threading.Event()
        self._release = threading.Event()
        self._lock = threading.Lock()
        self.calls = 0

    @property
    def entered(self) -> threading.Event:
        return self._entered

    def release(self) -> None:
        self._release.set()

    def fetch(self, tenant_id: str) -> dict[str, Any]:
        with self._lock:
            self.calls += 1
            first = self.calls == 1
        if first:
            self._entered.set()
            self._release.wait(timeout=10)
        if isinstance(self._response, BaseException):
            raise self._response
        return self._response
