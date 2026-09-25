"""The adaptive L3 limiter: FIFO queue, priority, AIMD (#216)."""

from __future__ import annotations

import asyncio
import threading
import time

import httpx
import pytest

from mcp_trentina_crunchtools.errors import QuarantineAgentError
from mcp_trentina_crunchtools.quarantine import classifier
from mcp_trentina_crunchtools.quarantine.limiter import (
    AdaptiveLimiter,
    Outcome,
    Priority,
    l3_priority,
    limited_generate,
    limiter_for,
)
from mcp_trentina_crunchtools.quarantine.providers.base import (
    Provider,
    ProviderResult,
    parse_retry_after,
    status_error,
)

JUDGE = ("gemini", "test-model")


async def _settle() -> None:
    for _ in range(5):
        await asyncio.sleep(0)


class TestGrowth:
    async def test_slow_start_doubles_per_window(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=2, ceiling=64)
        for _ in range(2):
            lim.release(await lim.acquire(), Outcome.OK)
        assert lim.limit == 4
        for _ in range(4):
            lim.release(await lim.acquire(), Outcome.OK)
        assert lim.limit == 8

    async def test_additive_after_first_throttle(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=8, ceiling=64)
        lim.release(await lim.acquire(), Outcome.THROTTLED, retry_after=0.0)
        assert lim.limit == 4
        await asyncio.sleep(0.3)  # the minimum pause
        for _ in range(4):
            lim.release(await lim.acquire(), Outcome.OK)
        assert lim.limit == 5

    async def test_ceiling(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=4, ceiling=6)
        for _ in range(20):
            lim.release(await lim.acquire(), Outcome.OK)
        assert lim.limit == 6

    async def test_other_failures_do_not_move_the_limit(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=4, ceiling=64)
        for _ in range(10):
            lim.release(await lim.acquire(), Outcome.FAILED)
        assert lim.limit == 4
        assert lim.in_flight == 0


class TestThrottle:
    async def test_one_halving_per_epoch(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=16, ceiling=64)
        epochs = [await lim.acquire() for _ in range(16)]
        # Sixteen requests in flight together all come back 429: one signal.
        for epoch in epochs:
            lim.release(epoch, Outcome.THROTTLED, retry_after=0.0)
        assert lim.limit == 8
        assert lim.throttles == 16

    async def test_floor_is_one(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=64)
        for _ in range(3):
            lim.release(lim.epoch, Outcome.THROTTLED, retry_after=0.0)
            lim.in_flight += 1  # release() assumes a held slot
        assert lim.limit == 1

    async def test_retry_after_pauses_new_requests(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=4, ceiling=64)
        lim.release(await lim.acquire(), Outcome.THROTTLED, retry_after=0.3)
        assert lim.resume_in() > 0.2
        waiter = asyncio.ensure_future(lim.acquire())
        await asyncio.sleep(0.1)
        assert not waiter.done()
        await asyncio.wait_for(waiter, timeout=1.0)

    async def test_no_retry_after_still_pauses(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=4, ceiling=64)
        lim.release(await lim.acquire(), Outcome.THROTTLED)
        assert lim.resume_in() >= 0.9


class TestQueue:
    async def test_fifo_within_priority(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        order: list[int] = []

        async def take(n: int) -> None:
            epoch = await lim.acquire()
            order.append(n)
            lim.release(epoch, Outcome.FAILED)

        tasks = [asyncio.ensure_future(take(n)) for n in range(5)]
        await _settle()
        lim.release(held, Outcome.FAILED)
        await asyncio.gather(*tasks)
        assert order == [0, 1, 2, 3, 4]

    async def test_foreground_before_background(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        order: list[str] = []

        async def take(label: str, priority: Priority) -> None:
            l3_priority.set(priority)
            epoch = await lim.acquire()
            order.append(label)
            lim.release(epoch, Outcome.FAILED)

        background = [asyncio.ensure_future(take(f"bg{n}", Priority.BACKGROUND)) for n in range(3)]
        await _settle()
        foreground = asyncio.ensure_future(take("fg", Priority.FOREGROUND))
        await _settle()
        lim.release(held, Outcome.FAILED)
        await asyncio.gather(*background, foreground)
        assert order[0] == "fg"

    async def test_cancelled_waiter_leaves_no_slot_behind(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=1, ceiling=1)
        held = await lim.acquire()
        waiter = asyncio.ensure_future(lim.acquire())
        await _settle()
        waiter.cancel()
        await _settle()
        lim.release(held, Outcome.FAILED)
        assert lim.in_flight == 0
        lim.release(await lim.acquire(), Outcome.OK)

    async def test_concurrency_never_exceeds_limit(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=3, ceiling=3)
        peak = 0

        async def work() -> None:
            nonlocal peak
            epoch = await lim.acquire()
            peak = max(peak, lim.in_flight)
            await asyncio.sleep(0.001)
            lim.release(epoch, Outcome.OK)

        await asyncio.gather(*(work() for _ in range(30)))
        assert peak == 3


class _FakeProvider(Provider):
    def __init__(self, error: QuarantineAgentError | None = None) -> None:
        self._model = JUDGE[1]
        self.judge = JUDGE
        self.error = error

    async def generate(self, *_args: object, **_kwargs: object) -> ProviderResult:
        if self.error is not None:
            raise self.error
        return ProviderResult(text="{}")


class TestLimitedGenerate:
    async def test_success_releases_the_slot(self) -> None:
        await limited_generate(_FakeProvider(), system_prompt="s", user_content="u")
        assert limiter_for(JUDGE).in_flight == 0

    async def test_429_restamps_retry_after_with_the_real_pause(self) -> None:
        err = QuarantineAgentError("HTTP 429", status_code=429, retry_after=2.0)
        with pytest.raises(QuarantineAgentError) as info:
            await limited_generate(_FakeProvider(err), system_prompt="s", user_content="u")
        assert info.value.retry_after is not None
        assert 1.5 < info.value.retry_after <= 2.0
        assert limiter_for(JUDGE).in_flight == 0
        assert limiter_for(JUDGE).throttles == 1


class TestRetryAfter:
    def test_delta_seconds(self) -> None:
        assert parse_retry_after("7") == 7.0

    def test_http_date(self) -> None:
        # 2015-10-21 07:28:00 GMT, ten seconds after "now".
        assert parse_retry_after("Wed, 21 Oct 2015 07:28:10 GMT", now=1445412480.0) == 10.0

    def test_garbage_and_missing(self) -> None:
        assert parse_retry_after("soon") is None
        assert parse_retry_after(None) is None

    def test_status_error_keeps_the_header(self) -> None:
        request = httpx.Request("POST", "https://example.invalid")
        response = httpx.Response(429, headers={"Retry-After": "3"}, request=request)
        exc = httpx.HTTPStatusError("throttled", request=request, response=response)
        err = status_error(exc)
        assert err.status_code == 429
        assert err.retry_after == 3.0


class TestLimitedGenerateFailures:
    async def test_other_error_releases_and_leaves_the_limit(self) -> None:
        err = QuarantineAgentError("HTTP 500", status_code=500)
        with pytest.raises(QuarantineAgentError):
            await limited_generate(_FakeProvider(err), system_prompt="s", user_content="u")
        lim = limiter_for(JUDGE)
        assert lim.in_flight == 0
        assert lim.throttles == 0
        assert lim.resume_in() == 0

    async def test_cancellation_releases_the_slot(self) -> None:
        gate = asyncio.Event()

        class _Hanging(_FakeProvider):
            async def generate(self, *_a: object, **_kw: object) -> ProviderResult:
                await gate.wait()
                return ProviderResult(text="{}")

        call = asyncio.ensure_future(
            limited_generate(_Hanging(), system_prompt="s", user_content="u")
        )
        await _settle()
        assert limiter_for(JUDGE).in_flight == 1
        call.cancel()
        with pytest.raises(asyncio.CancelledError):
            await call
        assert limiter_for(JUDGE).in_flight == 0


class TestL2Gate:
    async def test_concurrent_scans_respect_the_bound(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_L2_CONCURRENCY", "2")
        monkeypatch.setattr(classifier, "_gate", None)
        lock = threading.Lock()
        running = peak = 0

        def fake_classify(*_a: object, **_kw: object) -> None:
            nonlocal running, peak
            with lock:
                running += 1
                peak = max(peak, running)
            time.sleep(0.02)
            with lock:
                running -= 1

        monkeypatch.setattr(classifier, "classify", fake_classify)
        await asyncio.gather(*(classifier.classify_async("x") for _ in range(8)))
        assert peak == 2


class TestStaleSuccess:
    async def test_successes_from_before_a_halving_do_not_regrow_it(self) -> None:
        lim = AdaptiveLimiter(JUDGE, start=8, ceiling=64)
        epochs = [await lim.acquire() for _ in range(8)]
        lim.release(epochs[0], Outcome.THROTTLED, retry_after=0.0)
        assert lim.limit == 4
        for epoch in epochs[1:]:
            lim.release(epoch, Outcome.OK)
        assert lim.limit == 4


class TestPausedBeyondBudget:
    async def test_a_call_during_a_long_pause_is_refused_unsent(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_L3_THROTTLE_BUDGET", "5")
        lim = limiter_for(JUDGE)
        lim.release(await lim.acquire(), Outcome.THROTTLED, retry_after=60.0)
        provider = _FakeProvider()
        with pytest.raises(QuarantineAgentError) as info:
            await limited_generate(provider, system_prompt="s", user_content="u")
        assert info.value.status_code == 429
        assert info.value.retry_after is not None
        assert info.value.retry_after > 5
        assert lim.in_flight == 0


class TestL2GateUnderCancellation:
    async def test_a_cancelled_scan_keeps_its_permit_until_the_thread_ends(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("TRENTINA_L2_CONCURRENCY", "1")
        monkeypatch.setattr(classifier, "_gate", None)
        release = threading.Event()
        monkeypatch.setattr(classifier, "classify", lambda *_a, **_kw: release.wait(2))

        first = asyncio.ensure_future(classifier.classify_async("x"))
        await asyncio.sleep(0.05)
        first.cancel()
        second = asyncio.ensure_future(classifier.classify_async("y"))
        await asyncio.sleep(0.05)
        # The first thread is still running, so the second may not start.
        assert classifier._gate is not None
        assert classifier._gate[1].locked()
        release.set()
        await asyncio.wait_for(second, timeout=2)
