#!/usr/bin/env python3
"""Cross-provider injection-detection benchmark (issue #43).

Runs the Layer 3 adversarial corpus (``tests/adversarial_corpus.py``) through
``quarantine_detect()`` once per configured LLM provider and produces a
comparative report: detection rate by attack category, false-positive rate on
benign content, risk-level calibration, latency, and estimated token cost.

The thesis this measures: does it matter which LLM you put behind the Q-Agent?
The corpus is deliberately semantic — every attack already bypasses Layer 1 and
Layer 2 — so what remains is purely the model's reasoning about intent.

Usage (see docs/benchmark.md for the full option list)

    uv run python benchmarks/provider_benchmark.py
        Benchmark every provider that has credentials configured.

    uv run python benchmarks/provider_benchmark.py --providers gemini,anthropic
        Benchmark a specific subset.

    uv run python benchmarks/provider_benchmark.py --dry-run
        List what would run without spending any tokens.

Credentials are read from the same environment variables the server uses:
GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY. Ollama is auto-detected by
probing OLLAMA_BASE_URL (default http://localhost:11434).

Cost figures use the editable PRICING table below and are estimates only.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import statistics
import sys
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import httpx

_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from mcp_trentina_crunchtools.config import get_config
from mcp_trentina_crunchtools.quarantine.agent import quarantine_detect
from tests.adversarial_corpus import CORPUS, RISK_ORDER, Case

TOKENS_PER_MILLION = 1_000_000
HTTP_OK = 200

PRICING: dict[str, tuple[float, float]] = {
    "gemini": (0.10, 0.40),
    "openai": (0.15, 0.60),
    "anthropic": (1.00, 5.00),
    "ollama": (0.0, 0.0),
}

PROVIDER_ENV_KEY: dict[str, str | None] = {
    "gemini": "GEMINI_API_KEY",
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "ollama": None,
}

_DETECTION_FAILED_PREFIX = "Q-Agent detection failed"


def resolved_model(provider: str) -> str:
    """The model name each provider driver actually uses, for reporting.

    Mirrors the resolution logic in ``quarantine/providers/__init__.py`` so the
    report names the real model, not the placeholder default.
    """
    config = get_config()
    default_gemini = "gemini-2.5-flash-lite"
    if provider == "gemini":
        return config.model
    if provider == "openai":
        return config.model if config.model != default_gemini else "gpt-4o-mini"
    if provider == "anthropic":
        return (
            config.model
            if config.model != default_gemini
            else "claude-haiku-4-5-20251001"
        )
    if provider == "ollama":
        return config.ollama_model
    return "unknown"


@dataclass
class CaseResult:
    """Outcome of running one corpus case against one provider."""

    id: str
    category: str
    expect_injection: bool
    min_risk: str
    detected: bool
    risk_level: str
    latency_ms: float
    input_tokens: int
    output_tokens: int
    cost_usd: float
    error: bool
    summary: str = ""

    @property
    def correct(self) -> bool:
        """Did the detector reach the right injection/benign verdict?"""
        return self.detected == self.expect_injection

    @property
    def risk_ok(self) -> bool:
        """For a correctly-detected attack, did it meet the minimum severity?"""
        if not self.expect_injection or not self.detected:
            return False
        return RISK_ORDER.get(self.risk_level, 0) >= RISK_ORDER[self.min_risk]


@dataclass
class ProviderReport:
    """Aggregated metrics for one provider across the whole corpus."""

    provider: str
    model: str
    results: list[CaseResult] = field(default_factory=list)

    def _scored_attacks(self) -> list[CaseResult]:
        """Attack cases that produced a verdict (provider errors excluded)."""
        return [r for r in self.results if r.expect_injection and not r.error]

    def _scored_benign(self) -> list[CaseResult]:
        return [r for r in self.results if not r.expect_injection and not r.error]

    @property
    def errors(self) -> int:
        return sum(1 for r in self.results if r.error)

    @property
    def detection_rate(self) -> float:
        attacks = self._scored_attacks()
        if not attacks:
            return 0.0
        return sum(1 for r in attacks if r.detected) / len(attacks)

    @property
    def fp_rate(self) -> float:
        benign = self._scored_benign()
        if not benign:
            return 0.0
        return sum(1 for r in benign if r.detected) / len(benign)

    @property
    def risk_calibration(self) -> float:
        detected = [r for r in self._scored_attacks() if r.detected]
        if not detected:
            return 0.0
        return sum(1 for r in detected if r.risk_ok) / len(detected)

    def detection_by_category(self) -> dict[str, tuple[int, int]]:
        """category -> (detected, total_scored) over attack cases."""
        out: dict[str, list[int]] = {}
        for r in self._scored_attacks():
            slot = out.setdefault(r.category, [0, 0])
            slot[1] += 1
            if r.detected:
                slot[0] += 1
        return {k: (v[0], v[1]) for k, v in out.items()}

    def fp_by_category(self) -> dict[str, tuple[int, int]]:
        """category -> (false_positives, total_scored) over benign cases."""
        out: dict[str, list[int]] = {}
        for r in self._scored_benign():
            slot = out.setdefault(r.category, [0, 0])
            slot[1] += 1
            if r.detected:
                slot[0] += 1
        return {k: (v[0], v[1]) for k, v in out.items()}

    def _latencies(self) -> list[float]:
        return [r.latency_ms for r in self.results if not r.error]

    @property
    def median_latency_ms(self) -> float:
        lat = self._latencies()
        return statistics.median(lat) if lat else 0.0

    @property
    def p95_latency_ms(self) -> float:
        lat = sorted(self._latencies())
        if not lat:
            return 0.0
        idx = min(len(lat) - 1, round(0.95 * (len(lat) - 1)))
        return lat[idx]

    @property
    def total_cost_usd(self) -> float:
        return sum(r.cost_usd for r in self.results)

    @property
    def cost_per_1k_calls_usd(self) -> float:
        scored = [r for r in self.results if not r.error]
        if not scored:
            return 0.0
        return (sum(r.cost_usd for r in scored) / len(scored)) * 1000


def _cost(provider: str, input_tokens: int, output_tokens: int) -> float:
    in_price, out_price = PRICING.get(provider, (0.0, 0.0))
    return (
        (input_tokens / TOKENS_PER_MILLION) * in_price
        + (output_tokens / TOKENS_PER_MILLION) * out_price
    )


RETRY_BASE_DELAY = 1.0
RETRY_MAX_DELAY = 15.0
RETRYABLE_MARKERS = (
    "503", "429", "500", "502", "504", "overload",
    "timed out", "timeout", "unavailable", "connect",
)


async def _run_case(
    provider: str, case: Case, delay: float, retries: int
) -> CaseResult:
    """Run a single case through one provider, timing and pricing the call.

    Transient failures (503/429/timeouts/connection errors) are retried up to
    ``retries`` times with exponential backoff — the same retryable/terminal
    split issue #42 defines for provider fallback. Terminal failures (bad
    schema, auth) are not retried. Any failure is captured as an errored
    ``CaseResult`` rather than raised, so one bad call never aborts the run.
    """
    loop = asyncio.get_event_loop()
    result: dict | None = None
    summary = ""
    latency_ms = 0.0
    for attempt in range(retries + 1):
        start = loop.time()
        try:
            result = await quarantine_detect(
                case.payload, provider_name=provider, include_usage=True
            )
            summary = str(result.get("summary", ""))
        except Exception as exc:
            result = None
            summary = f"{type(exc).__name__}: {exc}"
        latency_ms = (loop.time() - start) * 1000
        errored = result is None or summary.startswith(_DETECTION_FAILED_PREFIX)
        retryable = any(m in summary.lower() for m in RETRYABLE_MARKERS)
        if not errored or attempt >= retries or not retryable:
            break
        await asyncio.sleep(min(RETRY_MAX_DELAY, RETRY_BASE_DELAY * 2**attempt))

    if delay:
        await asyncio.sleep(delay)

    error = result is None or summary.startswith(_DETECTION_FAILED_PREFIX)
    payload = result or {}
    usage = payload.get("usage", {}) or {}
    in_tok = int(usage.get("input_tokens", 0))
    out_tok = int(usage.get("output_tokens", 0))
    return CaseResult(
        id=case.id,
        category=case.category,
        expect_injection=case.expect_injection,
        min_risk=case.min_risk,
        detected=bool(payload.get("injection_detected", False)),
        risk_level=str(payload.get("risk_level", "low")),
        latency_ms=round(latency_ms, 1),
        input_tokens=in_tok,
        output_tokens=out_tok,
        cost_usd=_cost(provider, in_tok, out_tok),
        error=error,
        summary=summary[:300],
    )


async def run_provider(
    provider: str, cases: list[Case], concurrency: int, delay: float, retries: int
) -> ProviderReport:
    """Run the full corpus against one provider with bounded concurrency.

    Results are sorted back into corpus order before returning so the JSON and
    markdown output is stable and diffable across runs.
    """
    report = ProviderReport(provider=provider, model=resolved_model(provider))
    sem = asyncio.Semaphore(concurrency)

    async def _guarded(case: Case) -> CaseResult:
        async with sem:
            return await _run_case(provider, case, delay, retries)

    tasks = [asyncio.create_task(_guarded(c)) for c in cases]
    for done, coro in enumerate(asyncio.as_completed(tasks), 1):
        res = await coro
        mark = "ERR" if res.error else ("HIT" if res.detected else "   ")
        print(
            f"  [{provider}] {done}/{len(cases)} {mark} {res.id} "
            f"({res.latency_ms:.0f}ms)",
            file=sys.stderr,
        )
        report.results.append(res)

    order = {c.id: i for i, c in enumerate(cases)}
    report.results.sort(key=lambda r: order[r.id])
    return report


def available_providers(requested: list[str] | None) -> list[str]:
    """Providers with usable credentials, intersected with any --providers list.

    Ollama is probed over HTTP; hosted providers are gated on their API-key
    environment variable. Warnings are emitted only when the caller explicitly
    asked for a provider that turns out to be unavailable.
    """
    candidates = requested or list(PROVIDER_ENV_KEY)
    usable: list[str] = []
    for name in candidates:
        if name not in PROVIDER_ENV_KEY:
            print(f"warning: unknown provider {name!r}, skipping", file=sys.stderr)
            continue
        if name == "ollama":
            base = get_config().ollama_base_url.rstrip("/")
            try:
                reachable = httpx.get(f"{base}/api/tags", timeout=1.5).status_code == HTTP_OK
            except httpx.HTTPError:
                reachable = False
            if reachable:
                usable.append(name)
                continue
            if requested and "ollama" in requested:
                print(f"warning: ollama not reachable at {base}", file=sys.stderr)
            continue
        env = PROVIDER_ENV_KEY[name]
        if env and os.environ.get(env):
            usable.append(name)
            continue
        if requested:
            print(f"warning: {name} requested but {env} not set", file=sys.stderr)
    return usable


def _pct(n: int, d: int) -> str:
    return f"{100 * n / d:.0f}%" if d else "—"


def _category_table(
    title: str,
    reports: list[ProviderReport],
    categories: list[str],
    counts: dict[str, dict[str, tuple[int, int]]],
) -> str:
    """Render a category-by-provider table (used for both detection and FP)."""
    header = "| Category | " + " | ".join(r.provider for r in reports) + " |"
    sep = "|----------|" + "|".join(["------"] * len(reports)) + "|"
    lines = [f"## {title}", "", header, sep]
    for cat in categories:
        cells = [
            f"{_pct(*counts[r.provider].get(cat, (0, 0)))} "
            f"({counts[r.provider].get(cat, (0, 0))[0]}/"
            f"{counts[r.provider].get(cat, (0, 0))[1]})"
            for r in reports
        ]
        lines.append(f"| {cat} | " + " | ".join(cells) + " |")
    lines.append("")
    return "\n".join(lines)


def render_markdown(reports: list[ProviderReport], meta: dict) -> str:
    attack_cats = sorted({c.category for c in CORPUS if c.expect_injection})
    benign_cats = sorted({c.category for c in CORPUS if not c.expect_injection})

    out = [
        "# Q-Agent provider benchmark",
        "",
        "Detection = share of attacks flagged. FP = share of benign content "
        "wrongly flagged. Risk-cal = share of caught attacks that met the "
        "expected minimum severity. Cost is an estimate from the harness "
        "PRICING table.",
        "",
        f"- Generated: {meta['timestamp']}",
        f"- Corpus: {meta['n_attacks']} attacks + {meta['n_benign']} benign "
        f"= {meta['n_total']} cases across {meta['n_categories']} categories",
        f"- Providers: {', '.join(r.provider for r in reports)}",
        "",
        "## Summary",
        "",
        "| Provider | Model | Detection | FP rate | Risk-cal | "
        "Median latency | $/1k calls | Errors |",
        "|----------|-------|-----------|---------|----------|"
        "----------------|------------|--------|",
    ]
    for r in reports:
        out.append(
            f"| {r.provider} | `{r.model}` | {r.detection_rate:.0%} | "
            f"{r.fp_rate:.0%} | {r.risk_calibration:.0%} | "
            f"{r.median_latency_ms:.0f}ms | ${r.cost_per_1k_calls_usd:.2f} | "
            f"{r.errors} |"
        )
    out.append("")

    out.append(_category_table(
        "Detection by attack category",
        reports,
        attack_cats,
        {r.provider: r.detection_by_category() for r in reports},
    ))
    out.append(_category_table(
        "False positives by benign category",
        reports,
        benign_cats,
        {r.provider: r.fp_by_category() for r in reports},
    ))

    by_id: dict[str, list[CaseResult]] = {}
    for r in reports:
        for res in r.results:
            by_id.setdefault(res.id, []).append(res)
    universal_miss, universal_fp = [], []
    for cid, results in by_id.items():
        scored = [x for x in results if not x.error]
        if not scored:
            continue
        if scored[0].expect_injection:
            if all(not x.detected for x in scored):
                universal_miss.append(cid)
            continue
        if all(x.detected for x in scored):
            universal_fp.append(cid)
    out += [
        "## Notable results",
        "",
        f"- Attacks missed by **every** provider ({len(universal_miss)}): "
        + (", ".join(f"`{i}`" for i in sorted(universal_miss)) or "none 🎉"),
        f"- Benign content flagged by **every** provider ({len(universal_fp)}): "
        + (", ".join(f"`{i}`" for i in sorted(universal_fp)) or "none 🎉"),
        "",
    ]
    return "\n".join(out)


def build_meta(providers: list[str]) -> dict:
    attacks = [c for c in CORPUS if c.expect_injection]
    benign = [c for c in CORPUS if not c.expect_injection]
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "n_total": len(CORPUS),
        "n_attacks": len(attacks),
        "n_benign": len(benign),
        "n_categories": len({c.category for c in CORPUS}),
        "providers": providers,
        "pricing": PRICING,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--providers",
        help="Comma-separated subset (gemini,openai,anthropic,ollama). "
        "Default: all with credentials.",
    )
    p.add_argument(
        "--categories",
        help="Comma-separated category filter (e.g. detector_meta,exfil_action).",
    )
    p.add_argument("--limit", type=int, help="Run only the first N cases (smoke test).")
    p.add_argument(
        "--concurrency", type=int, default=4, help="Max concurrent calls per provider."
    )
    p.add_argument(
        "--delay", type=float, default=0.0, help="Seconds to sleep after each call."
    )
    p.add_argument(
        "--retries",
        type=int,
        default=0,
        help="Retry transient failures (503/429/timeout) up to N times with "
        "exponential backoff. Terminal errors (auth/schema) are not retried.",
    )
    p.add_argument(
        "--out",
        default=str(_REPO_ROOT / "benchmarks" / "results"),
        help="Output directory for JSON + markdown.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="List providers and cases that would run, without calling any API.",
    )
    return p.parse_args(argv)


def select_cases(args: argparse.Namespace) -> list[Case]:
    cases = list(CORPUS)
    if args.categories:
        wanted = {c.strip() for c in args.categories.split(",")}
        cases = [c for c in cases if c.category in wanted]
    if args.limit:
        cases = cases[: args.limit]
    return cases


async def main_async(args: argparse.Namespace) -> int:
    requested = (
        [p.strip() for p in args.providers.split(",")] if args.providers else None
    )
    providers = available_providers(requested)
    cases = select_cases(args)

    if not cases:
        print("No cases selected.", file=sys.stderr)
        return 2

    if args.dry_run:
        print(f"Would run {len(cases)} cases against: {providers or '(none available)'}")
        for c in cases:
            kind = "ATTACK" if c.expect_injection else "benign"
            print(f"  {kind:6} {c.category:26} {c.id}")
        return 0

    if not providers:
        print(
            "No providers available. Set GEMINI_API_KEY / OPENAI_API_KEY / "
            "ANTHROPIC_API_KEY, or start Ollama.",
            file=sys.stderr,
        )
        return 2

    reports: list[ProviderReport] = []
    for provider in providers:
        print(f"Running {len(cases)} cases against {provider}…", file=sys.stderr)
        reports.append(
            await run_provider(
                provider, cases, args.concurrency, args.delay, args.retries
            )
        )

    meta = build_meta(providers)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = meta["timestamp"].replace(":", "").replace("-", "")

    json_path = out_dir / f"benchmark-{stamp}.json"
    md_path = out_dir / f"benchmark-{stamp}.md"

    payload = {
        "meta": meta,
        "providers": [
            {
                "provider": r.provider,
                "model": r.model,
                "detection_rate": r.detection_rate,
                "fp_rate": r.fp_rate,
                "risk_calibration": r.risk_calibration,
                "median_latency_ms": r.median_latency_ms,
                "p95_latency_ms": r.p95_latency_ms,
                "cost_per_1k_calls_usd": r.cost_per_1k_calls_usd,
                "total_cost_usd": r.total_cost_usd,
                "errors": r.errors,
                "detection_by_category": r.detection_by_category(),
                "fp_by_category": r.fp_by_category(),
                "cases": [asdict(c) for c in r.results],
            }
            for r in reports
        ],
    }
    json_path.write_text(json.dumps(payload, indent=2))
    md = render_markdown(reports, meta)
    md_path.write_text(md)

    print("\n" + md)
    print(f"\nWrote {json_path}", file=sys.stderr)
    print(f"Wrote {md_path}", file=sys.stderr)
    return 0


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(main_async(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
