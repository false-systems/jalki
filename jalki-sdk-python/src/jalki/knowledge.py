"""
jälki knowledge base — embedded, local, zero-latency.

find() runs here. No daemon needed. Same JSON as the daemon.
"""

from __future__ import annotations

import json
import os
from importlib import resources
from pathlib import Path
from typing import Optional

from jalki.types import FieldInfo, ProbeMatch


def _load_layers() -> list[dict]:
    """Load all knowledge base layers from embedded JSON.

    Order of preference:
      1. $JALKI_KNOWLEDGE_PATH (explicit override)
      2. Packaged resource (jalki/knowledge/*.json — included in the wheel)
      3. Repo-root knowledge/ (development checkout)
    """
    # 1. Explicit override.
    env_path = os.environ.get("JALKI_KNOWLEDGE_PATH")
    if env_path:
        layers = _load_from_dir(Path(env_path))
        if layers:
            return layers

    # 2. Packaged resource — works for `pip install`-ed wheels.
    try:
        packaged = resources.files("jalki").joinpath("knowledge")
        if packaged.is_dir():
            layers = []
            for entry in sorted(packaged.iterdir(), key=lambda e: e.name):
                if entry.name.endswith(".json"):
                    with entry.open("r", encoding="utf-8") as f:
                        layers.append(json.load(f))
            if layers:
                return layers
    except (AttributeError, FileNotFoundError, ModuleNotFoundError):
        pass

    # 3. Repo-root fallback (development checkout).
    repo_root_knowledge = (
        Path(__file__).resolve().parent.parent.parent.parent / "knowledge"
    )
    return _load_from_dir(repo_root_knowledge)


def _load_from_dir(knowledge_dir: Path) -> list[dict]:
    if not knowledge_dir.is_dir():
        return []
    layers = []
    for json_file in sorted(knowledge_dir.glob("*.json")):
        with open(json_file, encoding="utf-8") as f:
            layers.append(json.load(f))
    return layers


# Load at import time — same as daemon.
_LAYERS = _load_layers()


def find_probes(question: str) -> list[ProbeMatch]:
    """
    Search KB for probes matching the question.
    Scores by: function name match (20pts), answer match (10pts), keyword match (5pts).
    Returns sorted by score descending.
    """
    q = question.lower()
    scored: list[tuple[dict, int]] = []

    for layer in _LAYERS:
        for probe in layer.get("probes", []):
            score = 0

            # Function name match.
            if probe["function"] in q:
                score += 20

            # Answer match.
            for answer in probe.get("answers", []):
                if q in answer.lower() or answer.lower() in q:
                    score += 10

            # Keyword match.
            for keyword in probe.get("keywords", []):
                if keyword.lower() in q:
                    score += 5

            if score > 0:
                scored.append((probe, score))

    scored.sort(key=lambda x: x[1], reverse=True)

    return [
        ProbeMatch(
            function=p["function"],
            attachment=p["attachment"],
            event_type=p["event_type"],
            why=p.get("use_when", ""),
            fields=[
                FieldInfo(
                    name=f["name"],
                    meaning=f["meaning"],
                    important=f.get("important", False),
                )
                for f in p.get("fields", [])
                if f.get("important", False)
            ],
            combine_with=p.get("combine_with", []),
        )
        for p, _ in scored
    ]


def get_probe(function: str) -> Optional[ProbeMatch]:
    """Look up a specific function by name."""
    for layer in _LAYERS:
        for probe in layer.get("probes", []):
            if probe["function"] == function:
                return ProbeMatch(
                    function=probe["function"],
                    attachment=probe["attachment"],
                    event_type=probe["event_type"],
                    why=probe.get("use_when", ""),
                    fields=[
                        FieldInfo(
                            name=f["name"],
                            meaning=f["meaning"],
                            important=f.get("important", False),
                        )
                        for f in probe.get("fields", [])
                        if f.get("important", False)
                    ],
                    combine_with=probe.get("combine_with", []),
                )
    return None


def explain(
    function: str,
    ret: Optional[int] = None,
    tcp_state: Optional[int] = None,
) -> list[dict]:
    """
    Return matching interpretations for an event.
    Matches against interpretation patterns in the KB.
    """
    for layer in _LAYERS:
        for probe in layer.get("probes", []):
            if probe["function"] != function:
                continue

            matches = []
            for interp in probe.get("interpretations", []):
                pattern = interp.get("pattern", "")

                if ret is not None:
                    if f"ret == {ret}" in pattern:
                        matches.append(interp)
                        continue
                    if "ret == 0" in pattern and ret == 0:
                        matches.append(interp)
                        continue
                    if "ret != 0" in pattern and ret != 0:
                        matches.append(interp)
                        continue

                if tcp_state is not None:
                    if "SYN_SENT (2)" in pattern and tcp_state == 2:
                        matches.append(interp)
                        continue
                    if "ESTABLISHED (1)" in pattern and tcp_state == 1:
                        matches.append(interp)
                        continue
                    if "CLOSE_WAIT (7)" in pattern and tcp_state == 7:
                        matches.append(interp)
                        continue

            return matches

    return []
