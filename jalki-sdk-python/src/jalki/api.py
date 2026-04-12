"""
jälki public API.

ask, find, deploy, stream — nothing else is public.
"""

from __future__ import annotations

import asyncio
import logging
from typing import AsyncIterator, Optional

import jalki as _module
from jalki.client import SOCKET_PATH, JalkiClient
from jalki.knowledge import explain, find_probes, get_probe
from jalki.protocol import (
    POS_CMD,
    POS_ID,
    POS_INTERP,
    POS_LABELS,
    POS_NET_DST,
    POS_NET_SRC,
    POS_OUTCOME,
    POS_PID,
    POS_PROBE_IDX,
    POS_PROTO,
    POS_SEVERITY,
    POS_TS,
    Method,
)
from jalki.types import (
    AskResult,
    Event,
    Interpretation,
    NetData,
    Outcome,
    ProcData,
    ProbeHandle,
    ProbeMatch,
    Proto,
    Severity,
)

logger = logging.getLogger("jalki.api")


async def connect(socket_path: str = SOCKET_PATH) -> JalkiClient:
    """Connect to daemon and return client. Sets as default client."""
    client = JalkiClient(socket_path)
    await client.connect()
    _module._default_client = client
    return client


def find(question: str) -> list[ProbeMatch]:
    """
    Search the knowledge base. No daemon required.
    Always works, even offline. Synchronous — no event loop needed.
    """
    return find_probes(question)


async def deploy(
    function: str,
    *,
    sample_rate: float = 1.0,
    filter: Optional[dict[str, object]] = None,
    client: Optional[JalkiClient] = None,
) -> ProbeHandle:
    """Attach a kernel probe. Returns handle for streaming."""
    c = client or _module._default_client
    if c is None:
        raise ConnectionError(
            "not connected to daemon. call await jalki.connect() first, "
            "or start daemon: sudo jalki --emit stdout"
        )

    params = {"function": function, "sample_rate": sample_rate}
    if filter is not None:
        params["filter"] = filter

    try:
        result = await c.call(Method.DEPLOY, params)
    except RuntimeError as e:
        if "already attached" in str(e):
            return ProbeHandle(probe_id=function, function=function)
        raise
    probe_id = result.get("probe_id", function) if isinstance(result, dict) else function
    return ProbeHandle(probe_id=probe_id, function=function)


async def stream(
    handle: ProbeHandle,
    *,
    filter: Optional[dict[str, object]] = None,
    interpreted: bool = False,
    client: Optional[JalkiClient] = None,
) -> AsyncIterator[Event]:
    """
    Live event stream from a deployed probe.
    Stateless — no cursor, no resumption.
    Filter applied server-side.
    """
    c = client or _module._default_client
    if c is None:
        raise ConnectionError("not connected to daemon")

    params: dict[str, object] = {"probe_id": handle.probe_id}
    if filter is not None:
        params["filter"] = filter
    if interpreted:
        params["interpreted"] = True

    probe_names = [handle.function]

    async for raw in c.subscribe(params):
        if isinstance(raw, list):
            yield _decode_stream_event(raw, probe_names, c)


async def ask(
    question: str,
    *,
    collect_seconds: int = 5,
    max_events: int = 100,
    filter: Optional[dict[str, object]] = None,
    client: Optional[JalkiClient] = None,
) -> AskResult:
    """
    Magic method. find → deploy → collect → interpret.
    Falls back to KB-only if no daemon running.
    Never raises — always returns something useful.
    """
    # 1. Find relevant probes (local, always works).
    matches = find_probes(question)
    if not matches:
        return AskResult(
            interpretation="No probes found for this question.",
            severity=Severity.INFO,
            action="Try keywords like 'connect', 'retransmit', 'packet loss'.",
            events=[],
            probes_used=[],
            kb_only=True,
        )

    # 2. Try to connect to daemon.
    c = client or _module._default_client
    if c is None:
        try:
            c = await connect()
        except Exception:
            return _kb_only_result(question, matches)

    # 3. Deploy top probes (up to 3), deduplicated by function name.
    seen: set[str] = set()
    selected = [p for p in matches if p.function not in seen and not seen.add(p.function)][:3]
    handles: list[tuple[ProbeMatch, ProbeHandle]] = []
    for probe in selected:
        try:
            h = await deploy(probe.function, client=c)
            handles.append((probe, h))
        except Exception as e:
            logger.debug("deploy %s failed: %s", probe.function, e)

    if not handles:
        return _kb_only_result(question, matches)

    # 4. Collect events.
    events: list[Event] = []
    try:
        async def _collect() -> None:
            for _, handle in handles:
                async for event in stream(handle, interpreted=True, client=c):
                    events.append(event)
                    if len(events) >= max_events:
                        return

        await asyncio.wait_for(_collect(), timeout=collect_seconds)
    except (asyncio.TimeoutError, Exception) as e:
        if not isinstance(e, asyncio.TimeoutError):
            logger.debug("collect failed: %s", e)

    # 5. Interpret.
    probes_used = [p.function for p, _ in handles]
    return _interpret(question, events, probes_used)


def _kb_only_result(question: str, matches: list[ProbeMatch]) -> AskResult:
    """Return a KB-only analysis when no daemon is available."""
    selected = matches[:3]
    parts = []
    for probe in selected:
        parts.append(f"**{probe.function}** ({probe.attachment})")
        parts.append(f"  {probe.why}")
        for f in probe.fields:
            parts.append(f"  {f.name} — {f.meaning}")
        interps = explain(probe.function)
        for interp in interps:
            parts.append(
                f"  [{interp.get('severity', 'info')}] {interp.get('pattern', '')} → "
                f"{interp.get('conclusion', '')}"
            )
        parts.append("")

    interpretation = "\n".join(parts) if parts else "No interpretation available."

    return AskResult(
        interpretation=interpretation,
        severity=Severity.INFO,
        action="Start the daemon for live events: sudo jalki --emit stdout",
        events=[],
        probes_used=[p.function for p in selected],
        kb_only=True,
    )


def _interpret(
    question: str, events: list[Event], probes: list[str]
) -> AskResult:
    """Build AskResult from collected events."""
    if not events:
        return AskResult(
            interpretation="No events observed. The kernel functions did not fire.",
            severity=Severity.INFO,
            action="Try collecting for longer, or check if the relevant activity is happening.",
            events=events,
            probes_used=probes,
            kb_only=False,
        )

    # Use the first event's interpretation if available.
    for event in events:
        if event.interp is not None:
            return AskResult(
                interpretation=event.interp.conclusion,
                severity=event.severity,
                action=event.interp.action,
                events=events,
                probes_used=probes,
                kb_only=False,
            )

    # Fall back to KB interpretation.
    for probe in probes:
        interps = explain(probe)
        if interps:
            best = interps[0]
            return AskResult(
                interpretation=best.get("conclusion", ""),
                severity=Severity(
                    {"info": 0, "warning": 1, "error": 2, "critical": 3}.get(
                        best.get("severity", "info"), 0
                    )
                ),
                action=best.get("action", ""),
                events=events,
                probes_used=probes,
                kb_only=False,
            )

    return AskResult(
        interpretation=f"Collected {len(events)} events but no specific interpretation matched.",
        severity=Severity.INFO,
        action="Review the events manually.",
        events=events,
        probes_used=probes,
        kb_only=False,
    )


def _decode_stream_event(
    raw: list[object], probe_names: list[str], client: JalkiClient
) -> Event:
    """Decode a positional STREAM_EVENT MessagePack array into an Event."""

    def _get(idx: int) -> object:
        return raw[idx] if idx < len(raw) else None

    probe_idx = _get(POS_PROBE_IDX)
    probe = (
        probe_names[int(probe_idx)]
        if probe_idx is not None and int(probe_idx) < len(probe_names)
        else "unknown"
    )

    net_src = _get(POS_NET_SRC)
    net_dst = _get(POS_NET_DST)
    proto_val = _get(POS_PROTO)
    net = None
    if net_src is not None or net_dst is not None:
        net = NetData(
            src=str(net_src) if net_src else "",
            dst=str(net_dst) if net_dst else "",
            proto=Proto(int(proto_val)) if proto_val is not None else Proto.TCP,
        )

    pid_val = _get(POS_PID)
    cmd_val = _get(POS_CMD)
    proc = None
    if pid_val is not None:
        proc = ProcData(pid=int(pid_val), cmd=str(cmd_val) if cmd_val else "")

    labels_val = _get(POS_LABELS)
    labels = dict(labels_val) if isinstance(labels_val, dict) else None

    interp_val = _get(POS_INTERP)
    interp = None
    if isinstance(interp_val, (list, tuple)) and len(interp_val) >= 2:
        interp = Interpretation(
            conclusion=str(interp_val[0]), action=str(interp_val[1])
        )

    sev_val = _get(POS_SEVERITY)
    out_val = _get(POS_OUTCOME)

    return Event(
        id=str(_get(POS_ID) or ""),
        ts=int(_get(POS_TS) or 0),
        probe=probe,
        severity=Severity(int(sev_val)) if sev_val is not None else Severity.INFO,
        outcome=Outcome(int(out_val)) if out_val is not None else Outcome.UNKNOWN,
        net=net,
        proc=proc,
        labels=labels,
        interp=interp,
        _client=client,
    )
