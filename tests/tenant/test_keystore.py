"""密钥缓存、单飞刷新、负缓存、TTL 与快照校验测试。"""

import threading

import pytest

from tests.tenant.constants import TENANT_A
from tenant_auth.clock import ControlledClock
from tenant_auth.errors import KeyRefreshError, KeySelectionError, Stage
from tenant_auth.keystore import BlockingKeySource, FakeKeySource, TenantKeyStore
from tenant_auth.tokens import TokenFactory


def _store(source: FakeKeySource, clock: ControlledClock, ttl: int = 300) -> TenantKeyStore:
    return TenantKeyStore(source, {TENANT_A: ttl}, clock)


def test_first_call_refreshes_second_uses_cache(factory: TokenFactory, source: FakeKeySource,
                                                clock: ControlledClock) -> None:
    mat = factory.new_rsa_material(TENANT_A, "k1")
    source.set_script(TENANT_A, [{"keys": [mat.public_jwk()]}])
    store = _store(source, clock)
    key, cached, refreshed = store.get_verification_key(TENANT_A, "k1", "RS256")
    assert key.kid == "k1" and cached is False and refreshed is True
    key2, cached2, refreshed2 = store.get_verification_key(TENANT_A, "k1", "RS256")
    assert cached2 is True and refreshed2 is False
    assert source.call_count(TENANT_A) == 1


def test_unknown_kid_triggers_single_refresh_then_negative_cache(
    factory: TokenFactory, source: FakeKeySource, clock: ControlledClock
) -> None:
    old = factory.new_rsa_material(TENANT_A, "k1")
    new = factory.new_rsa_material(TENANT_A, "k2")
    # 两次都给含 k2 的新快照：第一次为未知 k2 刷新，之后同世代不再刷新
    source.set_script(
        TENANT_A,
        [{"keys": [old.public_jwk()]}, {"keys": [new.public_jwk()]}],
    )
    store = _store(source, clock)
    store.get_verification_key(TENANT_A, "k1", "RS256")  # 初始加载
    assert source.call_count(TENANT_A) == 1
    key, cached, refreshed = store.get_verification_key(TENANT_A, "k2", "RS256")
    assert key.kid == "k2" and refreshed is True
    assert source.call_count(TENANT_A) == 2
    # 已轮换掉的 k1：刷新确认缺失 -> 未知 kid 拒绝
    with pytest.raises(KeySelectionError) as exc:
        store.get_verification_key(TENANT_A, "k1", "RS256")
    assert exc.value.reason == "unknown_key_id"
    assert source.call_count(TENANT_A) == 3
    # 同一未知 kid 再请求：负缓存命中，不刷新、不试钥匙
    with pytest.raises(KeySelectionError):
        store.get_verification_key(TENANT_A, "k1", "RS256")
    assert source.call_count(TENANT_A) == 3


def test_refresh_failure_keeps_old_snapshot_and_is_retryable(
    factory: TokenFactory, source: FakeKeySource, clock: ControlledClock
) -> None:
    old = factory.new_rsa_material(TENANT_A, "k1")
    source.set_script(
        TENANT_A,
        [{"keys": [old.public_jwk()]}, RuntimeError("outage"), RuntimeError("outage")],
    )
    store = _store(source, clock)
    store.get_verification_key(TENANT_A, "k1", "RS256")
    for _ in range(2):
        with pytest.raises(KeyRefreshError) as exc:
            store.get_verification_key(TENANT_A, "k9", "RS256")
        assert exc.value.stage is Stage.KEY_REFRESH
        assert exc.value.reason == "source_unavailable"
    # 失败不记负缓存：两次都实际尝试了刷新
    assert source.call_count(TENANT_A) == 3
    # 旧快照未被覆盖，已知 kid 照常服务
    key, cached, refreshed = store.get_verification_key(TENANT_A, "k1", "RS256")
    assert key.kid == "k1" and cached is True
    assert store.last_refresh_error(TENANT_A) == "source_unavailable"


def test_expired_snapshot_cannot_serve_old_key_on_failure(
    factory: TokenFactory, source: FakeKeySource, clock: ControlledClock
) -> None:
    old = factory.new_rsa_material(TENANT_A, "k1")
    source.set_script(TENANT_A, [{"keys": [old.public_jwk()]}, RuntimeError("outage")])
    store = _store(source, clock, ttl=300)
    store.get_verification_key(TENANT_A, "k1", "RS256")
    clock.advance(301)  # 快照到期
    with pytest.raises(KeyRefreshError):
        store.get_verification_key(TENANT_A, "k1", "RS256")
    assert source.call_count(TENANT_A) == 2  # 到期强制刷新，故障则拒绝而非放行


def test_negative_cache_resets_on_successful_new_snapshot_and_ttl(
    factory: TokenFactory, source: FakeKeySource, clock: ControlledClock
) -> None:
    """负缓存不是永久黑名单：新快照世代与 TTL 到期后都允许重新解析。"""
    k1 = factory.new_rsa_material(TENANT_A, "k1")
    k2 = factory.new_rsa_material(TENANT_A, "k2")
    source.set_script(
        TENANT_A,
        [
            {"keys": [k1.public_jwk()]},
            {"keys": [k1.public_jwk(), k2.public_jwk()]},
            {"keys": [k1.public_jwk(), k2.public_jwk()]},
        ],
    )
    store = _store(source, clock, ttl=300)
    store.get_verification_key(TENANT_A, "k1", "RS256")
    # 未知 k2 触发刷新，新快照含 k2，负缓存随新快照世代清空
    key, _, refreshed = store.get_verification_key(TENANT_A, "k2", "RS256")
    assert key.kid == "k2" and refreshed is True
    assert source.call_count(TENANT_A) == 2
    # TTL 到期后再次请求：强制重新刷新而非沿用任何过期判断
    clock.advance(301)
    key2, cached, refreshed2 = store.get_verification_key(TENANT_A, "k2", "RS256")
    assert key2.kid == "k2" and cached is False and refreshed2 is True
    assert source.call_count(TENANT_A) == 3


def test_duplicate_kid_rejected(factory: TokenFactory, source: FakeKeySource,
                                clock: ControlledClock) -> None:
    k1 = factory.new_rsa_material(TENANT_A, "k1")
    other = factory.new_rsa_material(TENANT_A, "k1")  # 同号
    source.set_script(TENANT_A, [{"keys": [k1.public_jwk(), other.public_jwk()]}])
    store = _store(source, clock)
    with pytest.raises(KeyRefreshError) as exc:
        store.get_verification_key(TENANT_A, "k1", "RS256")
    assert exc.value.reason == "duplicate_key_id"


def test_malformed_and_empty_sets_rejected(source: FakeKeySource, clock: ControlledClock) -> None:
    store = _store(source, clock)
    for bad in ({"keys": []}, {"keys": [{"kty": "RSA"}]}, {"nope": []}, "not-a-dict"):
        source.set_script(TENANT_A, [bad])
        with pytest.raises(KeyRefreshError):
            store.get_verification_key(TENANT_A, "k1", "RS256")


def test_key_use_mismatch_rejected_without_refresh(
    factory: TokenFactory, source: FakeKeySource, clock: ControlledClock
) -> None:
    enc_key = factory.new_rsa_material(TENANT_A, "k1", use="enc")
    source.set_script(TENANT_A, [{"keys": [enc_key.public_jwk()]}])
    store = _store(source, clock)
    with pytest.raises(KeySelectionError) as exc:
        store.get_verification_key(TENANT_A, "k1", "RS256")
    assert exc.value.reason == "key_use_mismatch"
    # 用途不符是确定性拒绝，不应触发第二次密钥源调用
    assert source.call_count(TENANT_A) == 1


def test_concurrent_requests_coalesce_into_one_refresh(
    factory: TokenFactory, clock: ControlledClock
) -> None:
    mat = factory.new_rsa_material(TENANT_A, "k1")
    n_threads = 8
    blocking = BlockingKeySource({"keys": [mat.public_jwk()]})
    all_waiters_ready = threading.Event()
    waiter_count = {"n": 0}
    count_lock = threading.Lock()

    def on_wait(_tenant: str) -> None:
        with count_lock:
            waiter_count["n"] += 1
            if waiter_count["n"] == n_threads - 1:
                all_waiters_ready.set()

    store = TenantKeyStore(blocking, {TENANT_A: 300}, clock, on_wait=on_wait)
    results: list[object] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(n_threads)

    def worker() -> None:
        barrier.wait()
        try:
            results.append(store.get_verification_key(TENANT_A, "k1", "RS256"))
        except BaseException as exc:  # noqa: BLE001 - 测试收集线程内异常
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    assert blocking.entered.wait(timeout=5)        # 发起者已在密钥源内阻塞
    assert all_waiters_ready.wait(timeout=5)       # 其余 7 个确定已成为单飞等待者
    blocking.release()
    for t in threads:
        t.join()

    assert not errors
    assert blocking.calls == 1  # 单飞：只有一个线程真正访问密钥源
    assert len(results) == n_threads
    # 所有线程拿到同一把钥匙、且都标记为参与了本次刷新（无缓存旁路）
    assert all(item[0].kid == "k1" for item in results)  # type: ignore[index]
    assert all(item[2] is True for item in results)  # type: ignore[index]


def test_concurrent_failure_shared_by_all_waiters(
    factory: TokenFactory, clock: ControlledClock
) -> None:
    n_threads = 6
    blocking = BlockingKeySource(RuntimeError("boom"))
    all_waiters_ready = threading.Event()
    waiter_count = {"n": 0}
    count_lock = threading.Lock()

    def on_wait(_tenant: str) -> None:
        with count_lock:
            waiter_count["n"] += 1
            if waiter_count["n"] == n_threads - 1:
                all_waiters_ready.set()

    store = TenantKeyStore(blocking, {TENANT_A: 300}, clock, on_wait=on_wait)
    errors: list[BaseException] = []
    barrier = threading.Barrier(n_threads)

    def worker() -> None:
        barrier.wait()
        try:
            store.get_verification_key(TENANT_A, "k1", "RS256")
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    assert blocking.entered.wait(timeout=5)
    assert all_waiters_ready.wait(timeout=5)
    blocking.release()
    for t in threads:
        t.join()

    assert blocking.calls == 1
    assert len(errors) == n_threads
    assert all(getattr(e, "reason", None) == "source_unavailable" for e in errors)
