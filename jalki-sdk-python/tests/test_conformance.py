"""
jälki Python SDK conformance tests.

Run without daemon: pytest tests/test_conformance.py -m "not daemon"
Run with daemon:    sudo jalki --emit stdout & pytest tests/test_conformance.py
"""

import asyncio

import pytest

import jalki
import jalki.api
import jalki.client
from jalki.types import Outcome, Severity


class TestNoDaemon:
    """Tests that work without a running daemon."""

    def test_find_tcp_connect(self) -> None:
        """find_tcp_connect: find returns tcp_connect for connection question."""
        matches = jalki.find("why are connections failing")
        assert len(matches) >= 1
        assert matches[0].function == "tcp_connect"

    def test_find_retransmit(self) -> None:
        """find_retransmit: find returns tcp_retransmit_skb for packet loss."""
        matches = jalki.find("packet loss")
        assert len(matches) >= 1
        assert matches[0].function == "tcp_retransmit_skb"

    def test_find_no_daemon(self) -> None:
        """find_no_daemon: find works without daemon."""
        matches = jalki.find("connection refused")
        assert len(matches) >= 1
        assert matches[0].function == "tcp_connect"

    @pytest.mark.asyncio
    async def test_ask_fallback_no_daemon(self, monkeypatch) -> None:
        """ask_fallback_no_daemon: ask falls back to KB when no daemon.

        Force connection failure via monkeypatch so the test is deterministic
        even if a real daemon is running on the machine.
        """

        async def _no_daemon(*_args, **_kwargs):
            raise ConnectionError("simulated: no daemon")

        monkeypatch.setattr(jalki.api, "connect", _no_daemon)
        previous_default = jalki._default_client
        jalki._default_client = None
        try:
            result = await jalki.ask("why are connections failing")
        finally:
            jalki._default_client = previous_default
        assert result.interpretation
        assert result.action
        assert result.kb_only is True


@pytest.mark.daemon
class TestWithDaemon:
    """Tests that require a running jälki daemon."""

    @pytest.fixture(autouse=True)
    async def client(self) -> None:
        try:
            await jalki.connect()
        except Exception:
            pytest.skip("jälki daemon not running")

    @pytest.mark.asyncio
    async def test_deploy_returns_handle(self) -> None:
        """deploy_returns_handle."""
        handle = await jalki.deploy("tcp_connect")
        assert handle.probe_id
        assert handle.function == "tcp_connect"

    @pytest.mark.asyncio
    async def test_stream_required_fields(self) -> None:
        """stream_required_fields: events have id, ts, probe, severity, outcome."""
        handle = await jalki.deploy("tcp_connect")
        events: list[jalki.Event] = []

        async def collect() -> None:
            async for event in jalki.stream(handle):
                events.append(event)
                if len(events) >= 5:
                    break

        try:
            await asyncio.wait_for(collect(), timeout=3.0)
        except asyncio.TimeoutError:
            pass

        for event in events:
            assert event.id
            assert event.ts > 0
            assert event.probe == "tcp_connect"
            assert isinstance(event.severity, Severity)
            assert isinstance(event.outcome, Outcome)

    @pytest.mark.asyncio
    async def test_compact_no_false_protocol_fields(self) -> None:
        """compact_no_false_protocol_fields."""
        handle = await jalki.deploy("tcp_connect")
        events: list[jalki.Event] = []

        async def collect() -> None:
            async for event in jalki.stream(handle):
                events.append(event)
                if len(events) >= 3:
                    break

        try:
            await asyncio.wait_for(collect(), timeout=3.0)
        except asyncio.TimeoutError:
            pass

        # Canonical no_field list — matches jalki-sdk-meta/src/conformance.rs
        # case `compact_no_false_protocol_fields`.
        forbidden = (
            "source",
            "enrichment_state",
            "entity_ids",
            "correlation_keys",
            "occurrence_type",
        )
        for event in events:
            for field_name in forbidden:
                assert not hasattr(event, field_name), (
                    f"event has forbidden FALSE Protocol field: {field_name}"
                )

    @pytest.mark.asyncio
    async def test_filter_server_side(self) -> None:
        """filter_server_side: server-side filter means non-matching events never arrive."""
        handle = await jalki.deploy("tcp_connect")
        events: list[jalki.Event] = []

        async def collect() -> None:
            async for event in jalki.stream(handle, filter={"dst_port": 9999}):
                events.append(event)
                if len(events) >= 5:
                    break

        try:
            await asyncio.wait_for(collect(), timeout=2.0)
        except asyncio.TimeoutError:
            pass

        # Every event we got back must match the filter.
        for event in events:
            assert event.net is not None
            # dst is "ip:port" — split and check port.
            assert event.net.dst.endswith(":9999"), (
                f"filter violation: {event.net.dst} not filtered to port 9999"
            )

    @pytest.mark.asyncio
    async def test_ask_with_daemon(self) -> None:
        """ask_with_daemon."""
        result = await jalki.ask("why are connections failing")
        assert result.interpretation
        assert result.action
