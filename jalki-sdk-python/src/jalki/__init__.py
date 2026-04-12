"""
jälki SDK — ask the kernel questions.

Four methods:
    ask(question)  → AskResult     # magic: find → deploy → collect → interpret
    find(question) → ProbeMatch[]  # local KB search, no daemon needed
    deploy(fn)     → ProbeHandle   # attach a kernel probe
    stream(handle) → EventStream   # live event iterator

Usage:
    import jalki

    # magic mode
    result = await jalki.ask("why is postgres slow")
    print(result.interpretation)

    # control mode
    matches = jalki.find("connection refused")
    handle = await jalki.deploy("tcp_connect", filter={"dst_port": 5432})
    async for event in jalki.stream(handle):
        print(event.net.dst, event.severity)
"""

from jalki.api import ask, find, deploy, stream, connect
from jalki.types import (
    Event, NetData, ProcData, Interpretation,
    EventFilter, ProbeMatch, ProbeHandle, AskResult,
    AskOptions, DeployOptions, StreamOptions,
    Severity, Outcome, Proto, Attachment,
)

__all__ = [
    "ask", "find", "deploy", "stream", "connect",
    "Event", "NetData", "ProcData", "Interpretation",
    "EventFilter", "ProbeMatch", "ProbeHandle", "AskResult",
    "AskOptions", "DeployOptions", "StreamOptions",
    "Severity", "Outcome", "Proto", "Attachment",
]

__version__ = "0.1.0"
__meta_version__ = "0.1.0"

# Module-level default client, set by connect()
_default_client = None
